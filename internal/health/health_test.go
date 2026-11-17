package health

import (
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
)

var th = config.Thresholds{
	FailureThreshold: 3, RecoveryThreshold: 2, Latency: config.Duration(time.Second), LatencySamples: 3,
	Availability: 90, AvailabilityWindow: config.Duration(time.Hour), AvailabilityMinChecks: 10,
}

type feeder struct {
	t   *testing.T
	tr  *Tracker
	now time.Time
}

func newFeeder(t *testing.T, repeat time.Duration) *feeder {
	return &feeder{t: t, tr: NewTracker("p", th, repeat), now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (f *feeder) feed(ok bool, ms int) []Event {
	f.now = f.now.Add(time.Minute)
	r := checks.Result{Proxy: "p", Time: f.now, OK: ok, Total: time.Duration(ms) * time.Millisecond}
	if !ok {
		r.Class, r.Error = checks.ClassTimeout, "no answer"
	}
	return f.tr.Observe(r)
}

func kinds(evs []Event) []Kind {
	var k []Kind
	for _, e := range evs {
		k = append(k, e.Kind)
	}
	return k
}

func TestDownAndRecovery(t *testing.T) {
	f := newFeeder(t, 0)
	if f.tr.State() != Unknown {
		t.Fatal("new tracker must be unknown")
	}
	f.feed(true, 100)
	if f.tr.State() != Healthy {
		t.Fatalf("state %s", f.tr.State())
	}
	if evs := f.feed(false, 0); len(evs) != 0 || f.tr.State() != Degraded {
		t.Fatalf("one failure is degraded, not down: %v %s", kinds(evs), f.tr.State())
	}
	f.feed(false, 0)
	evs := f.feed(false, 0)
	if len(evs) != 1 || evs[0].Kind != EvDown || f.tr.State() != Down || evs[0].ConsecutiveFailures != 3 {
		t.Fatalf("third failure must open a down incident: %+v", evs)
	}
	f.tr.SetIncidentID(IncDown, 42)
	if evs := f.feed(false, 0); len(evs) != 0 {
		t.Fatalf("no repeat without repeat_interval: %v", kinds(evs))
	}
	if evs := f.feed(true, 100); len(evs) != 0 || f.tr.State() != Down {
		t.Fatalf("one success is not a recovery (threshold 2): %v %s", kinds(evs), f.tr.State())
	}
	evs = f.feed(true, 100)
	if len(evs) != 1 || evs[0].Kind != EvRecovered || evs[0].IncidentID != 42 || evs[0].Duration != 3*time.Minute {
		t.Fatalf("recovery: %+v", evs)
	}
	if f.tr.State() != Healthy {
		t.Fatalf("state after recovery %s", f.tr.State())
	}
}

func TestStillDownReminder(t *testing.T) {
	f := newFeeder(t, 5*time.Minute)
	for i := 0; i < 3; i++ {
		f.feed(false, 0)
	}
	var reminders int
	for i := 0; i < 10; i++ {
		for _, e := range f.feed(false, 0) {
			if e.Kind == EvStillDown {
				reminders++
			}
		}
	}
	if reminders != 2 { // 10 more minutes at one reminder per 5 minutes
		t.Fatalf("reminders %d", reminders)
	}
}

func TestLatencyIncident(t *testing.T) {
	f := newFeeder(t, 0)
	f.feed(true, 1500)
	if evs := f.feed(true, 1500); len(evs) != 0 {
		t.Fatalf("needs latency_samples successes first: %v", kinds(evs))
	}
	evs := f.feed(true, 1500)
	if len(evs) != 1 || evs[0].Kind != EvLatency || evs[0].LatencyMS != 1500 || f.tr.State() != Degraded {
		t.Fatalf("latency incident: %+v %s", evs, f.tr.State())
	}
	f.feed(true, 200)
	evs = f.feed(true, 200) // median of 1500,200,200 = 200
	if len(evs) != 1 || evs[0].Kind != EvLatencyResolved || f.tr.State() != Healthy {
		t.Fatalf("latency resolution: %+v %s", evs, f.tr.State())
	}
}

func TestAvailabilityIncident(t *testing.T) {
	f := newFeeder(t, 0)
	var opened, resolved bool
	// 1 failure in every 4 checks, never 3 in a row: 75% < 90%.
	for i := 0; i < 16; i++ {
		for _, e := range f.feed(i%4 != 0, 100) {
			if e.Kind == EvAvailability {
				opened = true
				if e.Availability >= 90 {
					t.Fatalf("availability %v", e.Availability)
				}
			}
		}
	}
	if !opened || f.tr.State() != Degraded {
		t.Fatalf("availability incident not opened, state %s", f.tr.State())
	}
	for i := 0; i < 60 && !resolved; i++ {
		for _, e := range f.feed(true, 100) {
			if e.Kind == EvAvailabilityResolved {
				resolved = true
			}
		}
	}
	if !resolved {
		t.Fatal("availability incident never resolved")
	}
}

func TestNoAvailabilityAlertRightAfterOutage(t *testing.T) {
	f := newFeeder(t, 0)
	for i := 0; i < 10; i++ {
		f.feed(true, 100)
	}
	for i := 0; i < 4; i++ {
		f.feed(false, 0)
	}
	var got []Kind
	for i := 0; i < 5; i++ {
		got = append(got, kinds(f.feed(true, 100))...)
	}
	for _, k := range got {
		if k == EvAvailability {
			t.Fatalf("outage already reported; availability alert must wait a window: %v", got)
		}
	}
	if len(got) != 1 || got[0] != EvRecovered {
		t.Fatalf("expected only the recovery, got %v", got)
	}
}

func TestRestore(t *testing.T) {
	tr := NewTracker("p", th, 0)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr.Restore(Restored{
		ConsecutiveFailures: 5,
		Open:                map[string]OpenIncident{IncDown: {ID: 7, Started: start}},
		History:             []Observation{{Time: start, OK: false}},
	})
	if tr.State() != Down || tr.IncidentID(IncDown) != 7 {
		t.Fatalf("restored state %s id %d", tr.State(), tr.IncidentID(IncDown))
	}
	r := checks.Result{Proxy: "p", Time: start.Add(time.Minute), OK: true, Total: time.Millisecond}
	tr.Observe(r)
	r.Time = r.Time.Add(time.Minute)
	evs := tr.Observe(r)
	if len(evs) != 1 || evs[0].Kind != EvRecovered || evs[0].IncidentID != 7 {
		t.Fatalf("a restored incident must close with its own id: %+v", evs)
	}
}

func TestKinds(t *testing.T) {
	if !EvDown.Opens() || EvDown.Closes() || !EvRecovered.Closes() || EvStillDown.Opens() || EvStillDown.Closes() {
		t.Fatal("open/close flags")
	}
	if EvLatencyResolved.Group() != IncLatency || EvAvailability.Group() != IncAvailability || EvStillDown.Group() != IncDown {
		t.Fatal("groups")
	}
}
