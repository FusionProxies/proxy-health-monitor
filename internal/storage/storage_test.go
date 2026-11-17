package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestChecksRoundTrip(t *testing.T) {
	s := open(t)
	now := time.Now().Truncate(time.Millisecond)
	ok := checks.Result{Proxy: "a", Time: now.Add(-2 * time.Minute), OK: true, StatusCode: 200, DNS: 2 * time.Millisecond, Connect: 10 * time.Millisecond, Handshake: 30 * time.Millisecond, TLS: 40 * time.Millisecond, TTFB: 50 * time.Millisecond, Total: 150 * time.Millisecond, BytesIn: 900, BytesOut: 300}
	bad := checks.Result{Proxy: "a", Time: now.Add(-time.Minute), Class: checks.ClassTimeout, Error: "no answer"}
	other := checks.Result{Proxy: "b", Time: now, OK: true, Total: time.Second}
	for _, r := range []checks.Result{ok, bad, other} {
		if err := s.InsertCheck(r); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.Checks("a", now.Add(-time.Hour), now.Add(time.Second), false, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %d", err, len(rows))
	}
	if rows[0].OK || rows[0].Class != "timeout" || !rows[1].OK || rows[1].TotalMS != 150 || rows[1].HandshakeMS != 30 || rows[1].BytesIn != 900 {
		t.Fatalf("rows (newest first) %+v", rows)
	}
	failed, _ := s.Checks("a", now.Add(-time.Hour), now.Add(time.Second), true, 10)
	if len(failed) != 1 {
		t.Fatalf("failed only: %d", len(failed))
	}
	samples, _ := s.Samples("a", now.Add(-time.Hour), now.Add(time.Second))
	if len(samples) != 2 || !samples[0].OK || samples[1].Class != "timeout" {
		t.Fatalf("samples (oldest first) %+v", samples)
	}
	c, o, _ := s.Counts("a", now.Add(-time.Hour), now.Add(time.Second))
	if c != 2 || o != 1 {
		t.Fatalf("counts %d %d", c, o)
	}
}

func TestStateAndForget(t *testing.T) {
	s := open(t)
	now := time.Now().Truncate(time.Millisecond)
	for _, n := range []string{"a", "b"} {
		if err := s.SaveState(ProxyState{Proxy: n, State: "down", ConsecutiveFailures: 4, LastCheck: now, LastError: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.SaveState(ProxyState{Proxy: "a", State: "healthy", LastCheck: now, LastOK: now})
	id, _ := s.OpenIncident("b", "down", "gone", "x", 3, now)
	if err := s.ForgetProxiesExcept([]string{"a"}, now); err != nil {
		t.Fatal(err)
	}
	st, _ := s.States()
	if len(st) != 1 || st["a"].State != "healthy" || !st["a"].LastOK.Equal(now) {
		t.Fatalf("states %+v", st)
	}
	in, _ := s.Incidents(IncidentFilter{Proxy: "b"})
	if len(in) != 1 || in[0].ID != id || in[0].Open {
		t.Fatalf("incident of a removed proxy must be closed: %+v", in)
	}
}

func TestIncidents(t *testing.T) {
	s := open(t)
	t0 := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	id, err := s.OpenIncident("a", "down", "3 failures", "timeout", 3, t0)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.UpdateIncident(id, "refused", 7)
	open, _ := s.Incidents(IncidentFilter{OnlyOpen: true})
	if len(open) != 1 || !open[0].Open || open[0].LastError != "refused" || open[0].Failures != 7 {
		t.Fatalf("open %+v", open)
	}
	_ = s.CloseIncident(id, t0.Add(10*time.Minute))
	all, _ := s.Incidents(IncidentFilter{})
	if all[0].Open || all[0].DurationS != 600 || all[0].EndedAt == nil {
		t.Fatalf("closed %+v", all[0])
	}
	if open, _ := s.Incidents(IncidentFilter{OnlyOpen: true}); len(open) != 0 {
		t.Fatal("still open")
	}
	if recent, _ := s.Incidents(IncidentFilter{Since: time.Now().Add(-time.Minute)}); len(recent) != 0 {
		t.Fatal("an incident that ended 50 minutes ago is not within the last minute")
	}
}

func TestRetention(t *testing.T) {
	s := open(t)
	now := time.Now()
	for i := 0; i < 12000; i += 1000 {
		_ = s.InsertCheck(checks.Result{Proxy: "a", Time: now.Add(-time.Duration(i) * time.Minute / 100), OK: true})
	}
	// 6000+ rows old enough to delete exercise the batching.
	tx := now.Add(-48 * time.Hour)
	for i := 0; i < 6100; i++ {
		_ = s.InsertCheck(checks.Result{Proxy: "a", Time: tx, OK: true})
	}
	oldID, _ := s.OpenIncident("a", "down", "", "", 3, now.Add(-100*24*time.Hour))
	_ = s.CloseIncident(oldID, now.Add(-99*24*time.Hour))
	openOld, _ := s.OpenIncident("a", "down", "", "", 3, now.Add(-100*24*time.Hour)) // open: kept
	_ = s.RecordAlert(AlertRecord{Time: now.Add(-100 * 24 * time.Hour), Proxy: "a", Kind: "down", Status: "sent"})
	_ = s.RecordAlert(AlertRecord{Time: now, Proxy: "a", Kind: "down", Status: "sent"})

	before, _ := s.TotalChecks()
	c, i, err := s.Prune(now.Add(-24*time.Hour), now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.TotalChecks()
	if c != 6100 || after != before-6100 || i != 1 {
		t.Fatalf("deleted checks %d incidents %d (before %d after %d)", c, i, before, after)
	}
	in, _ := s.Incidents(IncidentFilter{})
	if len(in) != 1 || in[0].ID != openOld {
		t.Fatalf("open incidents must survive retention: %+v", in)
	}
	al, _ := s.Alerts(10)
	if len(al) != 1 {
		t.Fatalf("old alert records must be pruned: %d", len(al))
	}
}

func TestLastSentAlerts(t *testing.T) {
	s := open(t)
	now := time.Now().Truncate(time.Millisecond)
	_ = s.RecordAlert(AlertRecord{Time: now.Add(-time.Hour), Proxy: "a", Kind: "down", Status: "sent"})
	_ = s.RecordAlert(AlertRecord{Time: now, Proxy: "a", Kind: "down", Status: "sent"})
	_ = s.RecordAlert(AlertRecord{Time: now, Proxy: "b", Kind: "down", Status: "suppressed"})
	m, err := s.LastSentAlerts(now.Add(-2 * time.Hour))
	if err != nil || len(m) != 1 || !m[[2]string{"a", "down"}].Equal(now) {
		t.Fatalf("%v %v", m, err)
	}
}

func TestReopenKeepsData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.InsertCheck(checks.Result{Proxy: "a", Time: time.Now(), OK: true})
	s.Close()
	s, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n, _ := s.TotalChecks(); n != 1 {
		t.Fatalf("rows after reopen: %d", n)
	}
}
