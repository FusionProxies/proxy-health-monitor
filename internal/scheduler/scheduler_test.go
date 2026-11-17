package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/alerts"
	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/metrics"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// scripted returns results from a queue (true = success); when empty it succeeds.
type scripted struct {
	mu    sync.Mutex
	queue []bool
	calls atomic.Int64
	delay time.Duration
}

func (s *scripted) Check(ctx context.Context, p *config.Proxy) checks.Result {
	s.calls.Add(1)
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return checks.Result{Proxy: p.Name, Time: time.Now(), Class: checks.ClassCanceled}
		}
	}
	s.mu.Lock()
	ok := true
	if len(s.queue) > 0 {
		ok, s.queue = s.queue[0], s.queue[1:]
	}
	s.mu.Unlock()
	r := checks.Result{Proxy: p.Name, Time: time.Now(), OK: ok, Total: 50 * time.Millisecond}
	if !ok {
		r.Class, r.Error = checks.ClassTimeout, "no answer"
	}
	return r
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Storage: config.Storage{Path: filepath.Join(t.TempDir(), "s.db")},
		Monitor: config.Monitor{Concurrency: 2},
		Targets: []*config.Target{{Name: "t", URL: "http://127.0.0.1:9/healthz", MinSpacing: config.Duration(time.Millisecond)}},
		Proxies: []*config.Proxy{{Name: "p", URL: "http://127.0.0.1:3128", Interval: config.Duration(time.Second), Timeout: config.Duration(500 * time.Millisecond)}},
	}
	if err := cfg.Validate(""); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLimitsPerTarget(t *testing.T) {
	tg := &config.Target{Name: "t", MaxConcurrent: 1, MinSpacing: config.Duration(80 * time.Millisecond)}
	l := NewLimits(8, []*config.Target{tg})
	var mu sync.Mutex
	var starts []time.Time
	var inFlight, maxInFlight int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := l.Acquire(context.Background(), tg)
			if err != nil {
				t.Error(err)
				return
			}
			n := atomic.AddInt32(&inFlight, 1)
			mu.Lock()
			starts = append(starts, time.Now())
			if n > maxInFlight {
				maxInFlight = n
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
			rel()
		}()
	}
	wg.Wait()
	if maxInFlight != 1 {
		t.Fatalf("max_concurrent 1 violated: %d", maxInFlight)
	}
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < 70*time.Millisecond {
			t.Fatalf("min_spacing violated: %s between checks", gap)
		}
	}
}

func TestLimitsGlobalAndCancel(t *testing.T) {
	a := &config.Target{Name: "a", MaxConcurrent: 4}
	b := &config.Target{Name: "b", MaxConcurrent: 4}
	l := NewLimits(1, []*config.Target{a, b})
	rel, err := l.Acquire(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("global concurrency 1 must block a second check: %v", err)
	}
	rel()
	rel2, err := l.Acquire(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	rel2()
}

func newScheduler(t *testing.T, cfg *config.Config, c Checker, store *storage.Store) (*Scheduler, *alerts.Manager) {
	t.Helper()
	am := alerts.NewManager(cfg.Alerts, cfg.Proxies, alerts.Build(cfg.Alerts, quiet, "test"), store, quiet)
	s, err := New(cfg, store, c, am, metrics.New("test"), quiet)
	if err != nil {
		t.Fatal(err)
	}
	return s, am
}

func TestIncidentLifecycleAndRestart(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c := &scripted{queue: []bool{true, false, false, false, false}}
	s, am := newScheduler(t, cfg, c, store)
	p := cfg.Proxies[0]
	for i := 0; i < 5; i++ {
		s.RunCheck(context.Background(), context.Background(), p)
	}
	open, _ := store.Incidents(storage.IncidentFilter{OnlyOpen: true})
	if len(open) != 1 || open[0].Kind != "down" || open[0].Failures != 4 {
		t.Fatalf("open incidents %+v", open)
	}
	states, _ := store.States()
	if states["p"].State != "down" || states["p"].ConsecutiveFailures != 4 {
		t.Fatalf("state %+v", states["p"])
	}
	am.DeliverPending(context.Background())

	// Restart: a new scheduler on the same database continues the incident.
	c2 := &scripted{queue: []bool{true, true}}
	s2, am2 := newScheduler(t, cfg, c2, store)
	s2.RunCheck(context.Background(), context.Background(), p)
	s2.RunCheck(context.Background(), context.Background(), p)
	all, _ := store.Incidents(storage.IncidentFilter{})
	if len(all) != 1 || all[0].Open || all[0].ID != open[0].ID {
		t.Fatalf("the same incident must close after the restart: %+v", all)
	}
	am2.DeliverPending(context.Background())
	recs, _ := store.Alerts(10)
	if len(recs) != 2 || recs[0].Kind != "recovered" || recs[1].Kind != "down" || recs[0].Status != "sent" {
		t.Fatalf("alert history %+v", recs)
	}
	if n, _ := store.TotalChecks(); n != 7 {
		t.Fatalf("stored checks %d", n)
	}
}

func TestRunChecksOnScheduleAndStopsGracefully(t *testing.T) {
	cfg := testConfig(t)
	cfg.Monitor.Jitter = 0
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c := &scripted{delay: 50 * time.Millisecond}
	s, _ := newScheduler(t, cfg, c, store)
	ctx, cancel := context.WithTimeout(context.Background(), 2300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop after its context ended")
	}
	if n := c.calls.Load(); n < 2 || n > 4 {
		t.Fatalf("expected about 3 checks in 2.3s at a 1s interval, got %d", n)
	}
}

func TestTrigger(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, _ := newScheduler(t, cfg, &scripted{}, store)
	if err := s.Trigger("nope"); !errors.Is(err, ErrUnknownProxy) {
		t.Fatalf("unknown: %v", err)
	}
	if err := s.Trigger("p"); err != nil {
		t.Fatalf("first trigger: %v", err)
	}
	s.RunCheck(context.Background(), context.Background(), cfg.Proxies[0])
	if err := s.Trigger("p"); !errors.Is(err, ErrTooSoon) {
		t.Fatalf("right after a check: %v", err)
	}
}
