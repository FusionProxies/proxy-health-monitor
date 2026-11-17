// Package health turns a stream of check results for one proxy into a state
// (healthy, degraded, down) and into events that open and close incidents.
//
// Rules, per proxy:
//
//   - down: failure_threshold consecutive failures. It stays down until
//     recovery_threshold consecutive successes, then a "recovered" event fires.
//   - latency: the median total time of the last latency_samples successful
//     checks is above the latency threshold. Resolves when it is back at or
//     below the threshold.
//   - availability: at least availability_min_checks checks in the
//     availability_window and the success rate is below the availability
//     threshold. Resolves when it is back at or above. It does not open while
//     the proxy is down or within one window after a down incident ended,
//     because that outage was already reported.
//   - degraded: not down, but the last check failed or a latency or
//     availability incident is open.
package health

import (
	"fmt"
	"sort"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
)

// State is the health of a proxy.
type State string

// States.
const (
	Unknown  State = "unknown"
	Healthy  State = "healthy"
	Degraded State = "degraded"
	Down     State = "down"
)

// Kind names an event. The names match the `events:` filter in alerts.
type Kind string

// Event kinds.
const (
	EvDown                 Kind = "down"
	EvStillDown            Kind = "still_down"
	EvRecovered            Kind = "recovered"
	EvLatency              Kind = "latency"
	EvLatencyResolved      Kind = "latency_resolved"
	EvAvailability         Kind = "availability"
	EvAvailabilityResolved Kind = "availability_resolved"
)

// Incident kinds.
const (
	IncDown         = "down"
	IncLatency      = "latency"
	IncAvailability = "availability"
)

// Group is the incident kind an event belongs to.
func (k Kind) Group() string {
	switch k {
	case EvLatency, EvLatencyResolved:
		return IncLatency
	case EvAvailability, EvAvailabilityResolved:
		return IncAvailability
	}
	return IncDown
}

// Opens reports whether the event starts an incident.
func (k Kind) Opens() bool { return k == EvDown || k == EvLatency || k == EvAvailability }

// Closes reports whether the event ends an incident.
func (k Kind) Closes() bool {
	return k == EvRecovered || k == EvLatencyResolved || k == EvAvailabilityResolved
}

// Event is something worth recording and possibly alerting about.
type Event struct {
	Kind                Kind          `json:"event"`
	Proxy               string        `json:"proxy"`
	Time                time.Time     `json:"time"`
	IncidentID          int64         `json:"incident_id,omitempty"`
	Message             string        `json:"message"`
	ErrorClass          string        `json:"error_class,omitempty"`
	Error               string        `json:"error,omitempty"`
	ConsecutiveFailures int           `json:"consecutive_failures,omitempty"`
	Duration            time.Duration `json:"-"`
	LatencyMS           float64       `json:"latency_ms,omitempty"`
	Availability        float64       `json:"availability,omitempty"`
}

type obs struct {
	t  time.Time
	ok bool
}

type open struct {
	id      int64
	started time.Time
}

// Tracker follows one proxy. It is not safe for concurrent use; the
// scheduler calls it from one goroutine per proxy.
type Tracker struct {
	name   string
	th     config.Thresholds
	repeat time.Duration

	consecFail, consecOK int
	window               []obs
	latencies            []float64 // most recent successful totals, oldest first
	open                 map[string]*open
	lastDownEnded        time.Time
	lastReminder         time.Time
	lastErr, lastClass   string
	seen                 bool
}

// NewTracker returns a tracker with no history.
func NewTracker(name string, th config.Thresholds, repeat time.Duration) *Tracker {
	return &Tracker{name: name, th: th, repeat: repeat, open: map[string]*open{}}
}

// Restored is what the scheduler loads from the database at startup.
type Restored struct {
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	History              []Observation // oldest first
	Open                 map[string]OpenIncident
	LastDownEnded        time.Time
	LastError, LastClass string
}

// Observation is a past check.
type Observation struct {
	Time    time.Time
	OK      bool
	TotalMS float64
}

// OpenIncident is an incident that was open when the monitor stopped.
type OpenIncident struct {
	ID      int64
	Started time.Time
}

// Restore loads saved state so a restart does not reopen incidents or forget
// the availability window.
func (t *Tracker) Restore(r Restored) {
	t.consecFail, t.consecOK = r.ConsecutiveFailures, r.ConsecutiveSuccesses
	for _, h := range r.History {
		t.window = append(t.window, obs{t: h.Time, ok: h.OK})
		if h.OK {
			t.pushLatency(h.TotalMS)
		}
		t.seen = true
	}
	for k, o := range r.Open {
		t.open[k] = &open{id: o.ID, started: o.Started}
		if k == IncDown {
			t.lastReminder = o.Started
		}
	}
	t.lastDownEnded = r.LastDownEnded
	t.lastErr, t.lastClass = r.LastError, r.LastClass
	if t.consecFail > 0 || t.consecOK > 0 {
		t.seen = true
	}
}

func (t *Tracker) pushLatency(ms float64) {
	t.latencies = append(t.latencies, ms)
	if over := len(t.latencies) - t.th.LatencySamples; over > 0 {
		t.latencies = append(t.latencies[:0], t.latencies[over:]...)
	}
}

// SetIncidentID stores the database id of an incident opened by an event.
func (t *Tracker) SetIncidentID(kind string, id int64) {
	if o := t.open[kind]; o != nil {
		o.id = id
	}
}

// IncidentID returns the id of an open incident, or 0.
func (t *Tracker) IncidentID(kind string) int64 {
	if o := t.open[kind]; o != nil {
		return o.id
	}
	return 0
}

// ConsecutiveFailures is the current run of failed checks.
func (t *Tracker) ConsecutiveFailures() int { return t.consecFail }

// ConsecutiveSuccesses is the current run of successful checks.
func (t *Tracker) ConsecutiveSuccesses() int { return t.consecOK }

// State returns the current state.
func (t *Tracker) State() State {
	switch {
	case !t.seen:
		return Unknown
	case t.open[IncDown] != nil:
		return Down
	case t.consecFail > 0 || t.open[IncLatency] != nil || t.open[IncAvailability] != nil:
		return Degraded
	}
	return Healthy
}

// Availability returns the success percentage and number of checks in the
// current window.
func (t *Tracker) Availability() (float64, int) {
	if len(t.window) == 0 {
		return 0, 0
	}
	ok := 0
	for _, o := range t.window {
		if o.ok {
			ok++
		}
	}
	return 100 * float64(ok) / float64(len(t.window)), len(t.window)
}

// MedianLatency returns the median of the recent successful totals, and
// whether there are enough samples for the latency rule.
func (t *Tracker) MedianLatency() (float64, bool) {
	if len(t.latencies) == 0 {
		return 0, false
	}
	s := append([]float64(nil), t.latencies...)
	sort.Float64s(s)
	n := len(s)
	med := s[n/2]
	if n%2 == 0 {
		med = (s[n/2-1] + s[n/2]) / 2
	}
	return med, n >= t.th.LatencySamples
}

// Observe feeds one result and returns the events it caused.
func (t *Tracker) Observe(r checks.Result) []Event {
	now := r.Time
	t.seen = true
	t.window = append(t.window, obs{t: now, ok: r.OK})
	cut := now.Add(-t.th.AvailabilityWindow.D())
	i := 0
	for i < len(t.window) && t.window[i].t.Before(cut) {
		i++
	}
	if i > 0 {
		t.window = append(t.window[:0], t.window[i:]...)
	}

	if r.OK {
		t.consecOK++
		t.consecFail = 0
		t.pushLatency(float64(r.Total) / float64(time.Millisecond))
	} else {
		t.consecFail++
		t.consecOK = 0
		t.lastErr, t.lastClass = r.Error, string(r.Class)
	}

	var evs []Event
	ev := func(k Kind, msg string) Event {
		return Event{Kind: k, Proxy: t.name, Time: now, Message: msg, ErrorClass: t.lastClass, Error: t.lastErr, ConsecutiveFailures: t.consecFail}
	}

	down := t.open[IncDown]
	switch {
	case down == nil && t.consecFail >= t.th.FailureThreshold:
		t.open[IncDown] = &open{started: now}
		t.lastReminder = now
		evs = append(evs, ev(EvDown, fmt.Sprintf("%d consecutive failed checks; last error: %s", t.consecFail, t.lastErr)))
	case down != nil && !r.OK:
		if t.repeat > 0 && now.Sub(t.lastReminder) >= t.repeat {
			t.lastReminder = now
			e := ev(EvStillDown, fmt.Sprintf("still down after %s (%d consecutive failed checks); last error: %s", human(now.Sub(down.started)), t.consecFail, t.lastErr))
			e.IncidentID = down.id
			e.Duration = now.Sub(down.started)
			evs = append(evs, e)
		}
	case down != nil && t.consecOK >= t.th.RecoveryThreshold:
		delete(t.open, IncDown)
		t.lastDownEnded = now
		e := ev(EvRecovered, fmt.Sprintf("recovered after %s; %d consecutive successful checks", human(now.Sub(down.started)), t.consecOK))
		e.IncidentID = down.id
		e.Duration = now.Sub(down.started)
		e.Error, e.ErrorClass = "", ""
		evs = append(evs, e)
	}

	if t.open[IncDown] == nil {
		thr := float64(t.th.Latency.D()) / float64(time.Millisecond)
		if med, enough := t.MedianLatency(); enough {
			lat := t.open[IncLatency]
			switch {
			case lat == nil && med > thr:
				t.open[IncLatency] = &open{started: now}
				e := ev(EvLatency, fmt.Sprintf("median response time of the last %d successful checks is %.0f ms, above the %s threshold", len(t.latencies), med, t.th.Latency))
				e.LatencyMS = med
				e.Error, e.ErrorClass = "", ""
				evs = append(evs, e)
			case lat != nil && med <= thr:
				delete(t.open, IncLatency)
				e := ev(EvLatencyResolved, fmt.Sprintf("response time is back to normal (median %.0f ms) after %s", med, human(now.Sub(lat.started))))
				e.IncidentID, e.LatencyMS, e.Duration = lat.id, med, now.Sub(lat.started)
				e.Error, e.ErrorClass = "", ""
				evs = append(evs, e)
			}
		}

		pct, n := t.Availability()
		av := t.open[IncAvailability]
		afterOutage := !t.lastDownEnded.IsZero() && now.Sub(t.lastDownEnded) < t.th.AvailabilityWindow.D()
		switch {
		case av == nil && n >= t.th.AvailabilityMinChecks && pct < t.th.Availability && !afterOutage:
			t.open[IncAvailability] = &open{started: now}
			e := ev(EvAvailability, fmt.Sprintf("%.1f%% of %d checks succeeded in the last %s, below the %.1f%% threshold", pct, n, t.th.AvailabilityWindow, t.th.Availability))
			e.Availability = pct
			evs = append(evs, e)
		case av != nil && pct >= t.th.Availability:
			delete(t.open, IncAvailability)
			e := ev(EvAvailabilityResolved, fmt.Sprintf("availability is back to %.1f%% after %s", pct, human(now.Sub(av.started))))
			e.IncidentID, e.Availability, e.Duration = av.id, pct, now.Sub(av.started)
			e.Error, e.ErrorClass = "", ""
			evs = append(evs, e)
		}
	}
	return evs
}

// human prints a duration rounded to seconds ("12m30s", "2h5m").
func human(d time.Duration) string {
	if d < time.Second {
		return "less than a second"
	}
	d = d.Round(time.Second)
	if d >= time.Hour {
		d = d.Round(time.Minute)
	}
	return config.FormatDuration(d)
}
