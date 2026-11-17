// Package alerts decides which health events become notifications and
// delivers them.
//
// Flood control, in order:
//
//  1. Deduplication: one notification per incident and event kind.
//  2. Cooldown: after an incident of a kind opened an alert for a proxy, a
//     new incident of the same kind for that proxy within `cooldown` is
//     recorded but not sent, and neither is its resolution. A flapping proxy
//     therefore produces one down/recovered pair per cooldown, not dozens.
//  3. Rate limit: at most `max_per_minute` notifications per minute across
//     all proxies. The rest are counted and summarized in one message when
//     the minute is over.
//
// Every decision, sent or suppressed, is stored in the alert history.
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
)

// Severity of an alert.
const (
	SevCritical = "critical"
	SevWarning  = "warning"
	SevInfo     = "info"
)

// Alert is a notification ready to send.
type Alert struct {
	health.Event
	Severity string            `json:"severity"`
	Title    string            `json:"title"`
	Text     string            `json:"text"`
	Protocol string            `json:"protocol,omitempty"`
	ProxyURL string            `json:"proxy_url,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Summary  bool              `json:"summary,omitempty"` // a rate-limit summary, not about one proxy
}

// Notifier delivers alerts to one channel.
type Notifier interface {
	Name() string
	Accepts(kind health.Kind) bool
	Send(ctx context.Context, a Alert) error
}

// Recorder stores alert decisions. *storage.Store satisfies it.
type Recorder interface {
	RecordAlert(storage.AlertRecord) error
}

// Manager applies flood control and delivers alerts in the background.
type Manager struct {
	cfg       config.Alerts
	notifiers []Notifier
	rec       Recorder
	log       *slog.Logger
	proxies   map[string]*config.Proxy
	now       func() time.Time

	mu             sync.Mutex
	lastSent       map[[2]string]time.Time // (proxy, group) -> last opening alert sent
	suppressedOpen map[[2]string]bool      // the open incident's alert was suppressed
	sentIncident   map[string]bool         // "incidentID/kind" already sent
	windowStart    time.Time
	windowCount    int
	flooded        int
	floodedProxies map[string]bool

	queue chan Alert
}

// NewManager builds a manager. rec may be nil.
func NewManager(cfg config.Alerts, proxies []*config.Proxy, notifiers []Notifier, rec Recorder, log *slog.Logger) *Manager {
	pm := map[string]*config.Proxy{}
	for _, p := range proxies {
		pm[p.Name] = p
	}
	return &Manager{
		cfg: cfg, notifiers: notifiers, rec: rec, log: log, proxies: pm, now: time.Now,
		lastSent: map[[2]string]time.Time{}, suppressedOpen: map[[2]string]bool{}, sentIncident: map[string]bool{},
		floodedProxies: map[string]bool{}, queue: make(chan Alert, 256),
	}
}

// SetClock replaces the clock (tests).
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// Restore loads when alerts were last sent, so cooldowns survive a restart.
// Keys are (proxy, event kind).
func (m *Manager) Restore(last map[[2]string]time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, t := range last {
		kind := health.Kind(k[1])
		if !kind.Opens() {
			continue
		}
		g := [2]string{k[0], kind.Group()}
		if t.After(m.lastSent[g]) {
			m.lastSent[g] = t
		}
	}
}

// Channels lists the configured notifier names.
func (m *Manager) Channels() []string {
	out := make([]string, 0, len(m.notifiers))
	for _, n := range m.notifiers {
		out = append(out, n.Name())
	}
	return out
}

// Handle decides what to do with one event. It never blocks on delivery.
func (m *Manager) Handle(ev health.Event) {
	a := m.build(ev)
	now := m.now()
	key := [2]string{ev.Proxy, ev.Kind.Group()}

	m.mu.Lock()
	reason := ""
	dedupKey := fmt.Sprintf("%d/%s", ev.IncidentID, ev.Kind)
	switch {
	case ev.IncidentID != 0 && m.sentIncident[dedupKey]:
		reason = "duplicate"
	case ev.Kind.Opens():
		if last, ok := m.lastSent[key]; ok && now.Sub(last) < m.cfg.Cooldown.D() {
			reason = fmt.Sprintf("cooldown (a %s alert for this proxy was sent %s ago)", key[1], now.Sub(last).Round(time.Second))
			m.suppressedOpen[key] = true
		} else {
			m.suppressedOpen[key] = false
		}
	case ev.Kind.Closes():
		if m.suppressedOpen[key] {
			reason = "its opening alert was suppressed by the cooldown"
			m.suppressedOpen[key] = false
		}
	case ev.Kind == health.EvStillDown:
		if m.suppressedOpen[key] {
			reason = "its opening alert was suppressed by the cooldown"
		}
	}
	if reason == "" {
		if now.Sub(m.windowStart) >= time.Minute {
			m.windowStart, m.windowCount = now, 0
		}
		if m.windowCount >= m.cfg.MaxPerMinute {
			reason = fmt.Sprintf("rate limit (%d per minute)", m.cfg.MaxPerMinute)
			m.flooded++
			m.floodedProxies[ev.Proxy] = true
		} else {
			m.windowCount++
		}
	}
	if reason == "" {
		if ev.Kind.Opens() {
			m.lastSent[key] = now
		}
		if ev.IncidentID != 0 {
			m.sentIncident[dedupKey] = true
		}
	}
	m.mu.Unlock()

	if reason != "" {
		m.log.Info("alert suppressed", "proxy", ev.Proxy, "event", string(ev.Kind), "reason", reason)
		m.record(a, "suppressed", "", reason)
		return
	}
	select {
	case m.queue <- a:
	default:
		m.log.Error("alert queue full, alert dropped", "proxy", ev.Proxy, "event", string(ev.Kind))
		m.record(a, "failed", "", "alert queue full")
	}
}

func (m *Manager) build(ev health.Event) Alert {
	a := Alert{Event: ev}
	a.Message = redact.String(ev.Message)
	a.Error = redact.String(ev.Error)
	p := m.proxies[ev.Proxy]
	if p != nil {
		a.Protocol = p.Protocol()
		a.ProxyURL = p.DisplayURL()
		a.Labels = p.Labels
	}
	label := map[health.Kind]string{
		health.EvDown: "DOWN", health.EvStillDown: "STILL DOWN", health.EvRecovered: "RECOVERED",
		health.EvLatency: "SLOW", health.EvLatencyResolved: "LATENCY OK",
		health.EvAvailability: "AVAILABILITY LOW", health.EvAvailabilityResolved: "AVAILABILITY OK",
	}[ev.Kind]
	switch ev.Kind {
	case health.EvDown:
		a.Severity = SevCritical
	case health.EvStillDown, health.EvLatency, health.EvAvailability:
		a.Severity = SevWarning
	default:
		a.Severity = SevInfo
	}
	a.Title = fmt.Sprintf("[%s] %s", label, ev.Proxy)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", ev.Proxy, a.Message)
	if p != nil {
		fmt.Fprintf(&b, "\nProxy: %s (%s)", a.ProxyURL, a.Protocol)
	}
	if ev.IncidentID != 0 {
		fmt.Fprintf(&b, "\nIncident: #%d", ev.IncidentID)
	}
	fmt.Fprintf(&b, "\nTime: %s", ev.Time.UTC().Format("2006-01-02 15:04:05 UTC"))
	a.Text = b.String()
	return a
}

func (m *Manager) record(a Alert, status, channels, note string) {
	if m.rec == nil {
		return
	}
	msg := a.Title + ": " + a.Message
	if note != "" {
		msg += " [" + note + "]"
	}
	if err := m.rec.RecordAlert(storage.AlertRecord{
		Time: m.now(), Proxy: a.Proxy, Kind: string(a.Kind), IncidentID: a.IncidentID,
		Status: status, Channels: channels, Message: redact.String(msg),
	}); err != nil {
		m.log.Error("recording alert", "err", redact.Error(err))
	}
}

// Run delivers queued alerts until ctx ends, then keeps delivering what is
// already queued for up to drain.
func (m *Manager) Run(ctx context.Context, drain time.Duration) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case a := <-m.queue:
			m.deliver(context.Background(), a)
		case <-tick.C:
			m.flushSummary()
		case <-ctx.Done():
			m.flushSummary()
			deadline := time.After(drain)
			for {
				select {
				case a := <-m.queue:
					dctx, cancel := context.WithTimeout(context.Background(), drain)
					m.deliver(dctx, a)
					cancel()
				case <-deadline:
					return
				default:
					return
				}
			}
		}
	}
}

// flushSummary queues one message about alerts dropped by the rate limit,
// once the minute that dropped them is over.
func (m *Manager) flushSummary() {
	m.mu.Lock()
	if m.flooded == 0 || m.now().Sub(m.windowStart) < time.Minute {
		m.mu.Unlock()
		return
	}
	n := m.flooded
	names := make([]string, 0, len(m.floodedProxies))
	for p := range m.floodedProxies {
		names = append(names, p)
	}
	m.flooded, m.floodedProxies = 0, map[string]bool{}
	m.mu.Unlock()
	sort.Strings(names)
	if len(names) > 20 {
		names = append(names[:20], fmt.Sprintf("and %d more", len(names)-20))
	}
	a := Alert{Summary: true, Severity: SevWarning}
	a.Kind = "summary"
	a.Time = m.now()
	a.Title = "[SUMMARY] alerts not sent"
	a.Message = fmt.Sprintf("%d alerts were not sent because of max_per_minute (%d). Proxies: %s. Check the dashboard or `proxy-monitor status`.", n, m.cfg.MaxPerMinute, strings.Join(names, ", "))
	a.Text = a.Message
	select {
	case m.queue <- a:
	default:
	}
}

func (m *Manager) deliver(ctx context.Context, a Alert) {
	var sent, failed []string
	for _, n := range m.notifiers {
		if !a.Summary && !n.Accepts(a.Kind) {
			continue
		}
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				select {
				case <-time.After(time.Duration(attempt*attempt) * 2 * time.Second):
				case <-ctx.Done():
				}
			}
			sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err = n.Send(sctx, a)
			cancel()
			if err == nil || ctx.Err() != nil {
				break
			}
		}
		if err != nil {
			failed = append(failed, n.Name())
			m.log.Error("alert delivery failed", "channel", n.Name(), "proxy", a.Proxy, "err", redact.Error(err))
			continue
		}
		sent = append(sent, n.Name())
	}
	status := "sent"
	note := ""
	if len(sent) == 0 && len(failed) > 0 {
		status = "failed"
	} else if len(failed) > 0 {
		note = "failed: " + strings.Join(failed, ", ")
	}
	if len(sent) == 0 && len(failed) == 0 {
		status, note = "suppressed", "no channel accepts this event"
	}
	m.record(a, status, strings.Join(sent, ", "), note)
}

// Pending returns the number of queued alerts (tests).
func (m *Manager) Pending() int { return len(m.queue) }

// DeliverPending delivers everything queued now, synchronously (tests and
// the one-shot CLI).
func (m *Manager) DeliverPending(ctx context.Context) {
	for {
		select {
		case a := <-m.queue:
			m.deliver(ctx, a)
		default:
			return
		}
	}
}
