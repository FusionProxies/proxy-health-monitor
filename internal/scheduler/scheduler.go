// Package scheduler runs the checks on their intervals, records results,
// updates health state and incidents, and hands events to the alert manager.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/alerts"
	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
	"github.com/FusionProxies/proxy-health-monitor/internal/metrics"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
)

// Checker runs one check. *checks.Checker satisfies it.
type Checker interface {
	Check(ctx context.Context, p *config.Proxy) checks.Result
}

// Scheduler owns the monitoring loop.
type Scheduler struct {
	cfg     *config.Config
	store   *storage.Store
	checker Checker
	alerts  *alerts.Manager
	metrics *metrics.Registry
	log     *slog.Logger
	limits  *Limits

	mu        sync.Mutex
	trackers  map[string]*health.Tracker
	manual    map[string]chan struct{}
	lastCheck map[string]time.Time
	running   map[string]bool
	states    map[string]storage.ProxyState

	// ShutdownGrace is how long in-flight checks may finish after Run's
	// context ends.
	ShutdownGrace time.Duration
	// PruneEvery is how often retention runs.
	PruneEvery time.Duration
	rnd        *rand.Rand
}

// New builds a scheduler and restores state from the database.
func New(cfg *config.Config, store *storage.Store, checker Checker, am *alerts.Manager, reg *metrics.Registry, log *slog.Logger) (*Scheduler, error) {
	s := &Scheduler{
		cfg: cfg, store: store, checker: checker, alerts: am, metrics: reg, log: log,
		limits:   NewLimits(cfg.Monitor.Concurrency, cfg.Targets),
		trackers: map[string]*health.Tracker{}, manual: map[string]chan struct{}{},
		lastCheck: map[string]time.Time{}, running: map[string]bool{}, states: map[string]storage.ProxyState{},
		ShutdownGrace: 5 * time.Second, PruneEvery: time.Hour,
		rnd: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	if err := s.restore(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Scheduler) restore() error {
	now := time.Now()
	var names []string
	for _, p := range s.cfg.Proxies {
		names = append(names, p.Name)
	}
	if err := s.store.ForgetProxiesExcept(names, now); err != nil {
		return fmt.Errorf("cleaning removed proxies: %w", err)
	}
	states, err := s.store.States()
	if err != nil {
		return err
	}
	openInc, err := s.store.Incidents(storage.IncidentFilter{OnlyOpen: true})
	if err != nil {
		return err
	}
	for _, p := range s.cfg.EnabledProxies() {
		tr := health.NewTracker(p.Name, p.Effective, s.cfg.Alerts.RepeatInterval.D())
		r := health.Restored{Open: map[string]health.OpenIncident{}}
		if st, ok := states[p.Name]; ok {
			r.ConsecutiveFailures, r.ConsecutiveSuccesses = st.ConsecutiveFailures, st.ConsecutiveSuccesses
			r.LastError, r.LastClass = st.LastError, st.LastErrorClass
			s.lastCheck[p.Name] = st.LastCheck
			s.states[p.Name] = st
		}
		samples, err := s.store.Samples(p.Name, now.Add(-p.Effective.AvailabilityWindow.D()), now.Add(time.Minute))
		if err != nil {
			return err
		}
		for _, x := range samples {
			r.History = append(r.History, health.Observation{Time: x.Time, OK: x.OK, TotalMS: x.TotalMS})
		}
		for _, in := range openInc {
			if in.Proxy == p.Name {
				r.Open[in.Kind] = health.OpenIncident{ID: in.ID, Started: in.StartedAt}
			}
		}
		if last, err := s.store.Incidents(storage.IncidentFilter{Proxy: p.Name, Limit: 5}); err == nil {
			for _, in := range last {
				if in.Kind == health.IncDown && in.EndedAt != nil {
					r.LastDownEnded = *in.EndedAt
					break
				}
			}
		}
		tr.Restore(r)
		s.trackers[p.Name] = tr
		s.manual[p.Name] = make(chan struct{}, 1)
		if s.metrics != nil {
			s.metrics.Register(p.Name, p.Protocol(), p.Target)
			s.metrics.SetState(p.Name, tr.State(), tr.ConsecutiveFailures(), len(r.Open))
		}
	}
	if s.alerts != nil {
		if last, err := s.store.LastSentAlerts(now.Add(-s.cfg.Alerts.Cooldown.D())); err == nil {
			s.alerts.Restore(last)
		}
	}
	return nil
}

// Run checks every enabled proxy on its interval until ctx ends, then lets
// in-flight checks finish for up to ShutdownGrace.
func (s *Scheduler) Run(ctx context.Context) error {
	checkCtx, cancelChecks := context.WithCancel(context.Background())
	defer cancelChecks()
	go func() {
		<-ctx.Done()
		t := time.NewTimer(s.ShutdownGrace)
		defer t.Stop()
		select {
		case <-t.C:
			cancelChecks()
		case <-checkCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	proxies := s.cfg.EnabledProxies()
	for i, p := range proxies {
		wg.Add(1)
		go func(i int, p *config.Proxy) {
			defer wg.Done()
			s.loop(ctx, checkCtx, p, s.initialDelay(i, len(proxies), p))
		}(i, p)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.pruneLoop(ctx)
	}()
	s.log.Info("monitoring started", "proxies", len(proxies), "concurrency", s.cfg.Monitor.Concurrency)
	wg.Wait()
	s.log.Info("monitoring stopped")
	return nil
}

// initialDelay spreads the first checks over the first interval (at most
// 30s), so a restart does not fire every check at once.
func (s *Scheduler) initialDelay(i, n int, p *config.Proxy) time.Duration {
	span := min(p.Interval.D(), 30*time.Second)
	if n <= 1 {
		return 0
	}
	return span * time.Duration(i) / time.Duration(n)
}

func (s *Scheduler) nextDelay(p *config.Proxy) time.Duration {
	iv := p.Interval.D()
	j := s.cfg.Monitor.Jitter
	if j <= 0 {
		return iv
	}
	s.mu.Lock()
	r := s.rnd.Float64()*2 - 1 // -1..1
	s.mu.Unlock()
	return iv + time.Duration(float64(iv)*j*r)
}

func (s *Scheduler) loop(ctx, checkCtx context.Context, p *config.Proxy, first time.Duration) {
	timer := time.NewTimer(first)
	defer timer.Stop()
	manual := s.manual[p.Name]
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-manual:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		s.RunCheck(ctx, checkCtx, p)
		timer.Reset(s.nextDelay(p))
	}
}

// RunCheck runs one check of p now (respecting the limits) and records it.
// waitCtx bounds the wait for a slot; checkCtx bounds the check itself.
func (s *Scheduler) RunCheck(waitCtx, checkCtx context.Context, p *config.Proxy) (checks.Result, bool) {
	release, err := s.limits.Acquire(waitCtx, p.TargetRef)
	if err != nil {
		return checks.Result{}, false
	}
	s.mu.Lock()
	s.running[p.Name] = true
	s.mu.Unlock()
	res := s.checker.Check(checkCtx, p)
	release()
	s.mu.Lock()
	s.running[p.Name] = false
	s.mu.Unlock()
	if res.Class == checks.ClassCanceled {
		return res, false
	}
	s.Record(p, res)
	return res, true
}

// Record stores a result, updates state and incidents, and raises alerts.
func (s *Scheduler) Record(p *config.Proxy, res checks.Result) {
	if err := s.store.InsertCheck(res); err != nil {
		s.log.Error("storing check", "proxy", p.Name, "err", redact.Error(err))
	}
	s.mu.Lock()
	tr := s.trackers[p.Name]
	if tr == nil {
		s.mu.Unlock()
		return
	}
	before := tr.State()
	evs := tr.Observe(res)
	for i := range evs {
		ev := &evs[i]
		group := ev.Kind.Group()
		switch {
		case ev.Kind.Opens():
			id, err := s.store.OpenIncident(p.Name, group, ev.Message, ev.Error, tr.ConsecutiveFailures(), ev.Time)
			if err != nil {
				s.log.Error("opening incident", "proxy", p.Name, "err", redact.Error(err))
			}
			tr.SetIncidentID(group, id)
			ev.IncidentID = id
		case ev.Kind.Closes():
			if ev.IncidentID != 0 {
				if err := s.store.CloseIncident(ev.IncidentID, ev.Time); err != nil {
					s.log.Error("closing incident", "proxy", p.Name, "err", redact.Error(err))
				}
			}
		}
	}
	if id := tr.IncidentID(health.IncDown); id != 0 && !res.OK {
		_ = s.store.UpdateIncident(id, res.Error, tr.ConsecutiveFailures())
	}
	after := tr.State()
	openCount := 0
	for _, k := range []string{health.IncDown, health.IncLatency, health.IncAvailability} {
		if tr.IncidentID(k) != 0 {
			openCount++
		}
	}
	consecFail, consecOK := tr.ConsecutiveFailures(), tr.ConsecutiveSuccesses()
	s.lastCheck[p.Name] = res.Time
	st := s.states[p.Name]
	st.Proxy, st.State = p.Name, string(after)
	st.ConsecutiveFailures, st.ConsecutiveSuccesses = consecFail, consecOK
	st.LastCheck, st.UpdatedAt = res.Time, time.Now()
	if res.OK {
		st.LastOK = res.Time
		st.LastTotalMS = float64(res.Total) / float64(time.Millisecond)
	} else {
		st.LastFailure, st.LastError, st.LastErrorClass = res.Time, res.Error, string(res.Class)
	}
	s.states[p.Name] = st
	s.mu.Unlock()
	if err := s.store.SaveState(st); err != nil {
		s.log.Error("saving state", "proxy", p.Name, "err", redact.Error(err))
	}
	if s.metrics != nil {
		s.metrics.Observe(res, after, consecFail, openCount)
	}
	if res.OK {
		s.log.Debug("check ok", "proxy", p.Name, "total_ms", res.Total.Milliseconds())
	} else {
		s.log.Debug("check failed", "proxy", p.Name, "class", string(res.Class), "err", res.Error)
	}
	if before != after {
		s.log.Info("state changed", "proxy", p.Name, "from", string(before), "to", string(after))
	}
	if s.alerts != nil {
		for _, ev := range evs {
			s.alerts.Handle(ev)
		}
	}
}

// ErrTooSoon is returned by Trigger when the proxy was checked very recently.
var ErrTooSoon = errors.New("checked too recently")

// ErrUnknownProxy is returned by Trigger for a name that is not monitored.
var ErrUnknownProxy = errors.New("unknown proxy")

// Trigger asks for an immediate check of one proxy. The usual floor interval
// still applies, so the dashboard cannot be used to hammer a proxy.
func (s *Scheduler) Trigger(name string) error {
	p := s.cfg.ProxyByName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.manual[name]
	if p == nil || ch == nil {
		return ErrUnknownProxy
	}
	floor := config.FloorInterval
	if config.IsLoopbackHost(p.Host) {
		floor = config.LoopbackFloorInterval
	}
	if s.running[name] || time.Since(s.lastCheck[name]) < floor {
		return fmt.Errorf("%w: wait %s between checks", ErrTooSoon, config.FormatDuration(floor))
	}
	select {
	case ch <- struct{}{}:
	default:
	}
	return nil
}

func (s *Scheduler) pruneLoop(ctx context.Context) {
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	s.Prune()
	t := time.NewTicker(s.PruneEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Prune()
		}
	}
}

// Prune applies the retention settings once.
func (s *Scheduler) Prune() {
	now := time.Now()
	c, i, err := s.store.Prune(now.Add(-s.cfg.Storage.Retention.D()), now.Add(-s.cfg.Storage.IncidentRetention.D()))
	if err != nil {
		s.log.Error("retention", "err", redact.Error(err))
		return
	}
	if c > 0 || i > 0 {
		s.log.Info("retention applied", "checks_deleted", c, "incidents_deleted", i)
	}
}

// Running reports whether a check of the proxy is in flight.
func (s *Scheduler) Running(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[name]
}
