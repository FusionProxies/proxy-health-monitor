package stats

import (
	"math"
	"testing"
	"time"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestPercentile(t *testing.T) {
	s := []float64{10, 20, 30, 40}
	cases := map[float64]float64{0: 10, 50: 25, 100: 40, 95: 38.5, 25: 17.5}
	for p, want := range cases {
		if got := Percentile(s, p); !near(got, want) {
			t.Errorf("P%.0f = %v, want %v", p, got, want)
		}
	}
	if Percentile(nil, 50) != 0 || Percentile([]float64{7}, 95) != 7 {
		t.Fatal("edge cases")
	}
	// 1..100: p95 by linear interpolation is 95.05.
	var h []float64
	for i := 1; i <= 100; i++ {
		h = append(h, float64(i))
	}
	if got := Percentile(h, 95); !near(got, 95.05) {
		t.Fatalf("p95 of 1..100 = %v", got)
	}
}

func TestSummarize(t *testing.T) {
	now := time.Now()
	samples := []Sample{
		{Time: now, OK: true, TotalMS: 100, TTFBMS: 40},
		{Time: now, OK: true, TotalMS: 300, TTFBMS: 60},
		{Time: now, OK: false, Class: "timeout"},
		{Time: now, OK: true, TotalMS: 200, TTFBMS: 50},
		{Time: now, OK: false, Class: "timeout"},
		{Time: now, OK: false, Class: "auth_failed"},
	}
	s := Summarize(samples)
	if s.Checks != 6 || s.Successes != 3 || s.Failures != 3 {
		t.Fatalf("counts %+v", s)
	}
	if !near(s.Uptime, 50) {
		t.Fatalf("uptime %v", s.Uptime)
	}
	// Latency comes from successful checks only.
	if !near(s.AvgMS, 200) || !near(s.P50MS, 200) || !near(s.MinMS, 100) || !near(s.MaxMS, 300) || !near(s.P95MS, 290) {
		t.Fatalf("latency %+v", s)
	}
	if !near(s.TTFBP50MS, 50) {
		t.Fatalf("ttfb p50 %v", s.TTFBP50MS)
	}
	if s.Errors["timeout"] != 2 || s.Errors["auth_failed"] != 1 {
		t.Fatalf("errors %v", s.Errors)
	}
	if z := Summarize(nil); z.Checks != 0 || z.Uptime != 0 {
		t.Fatalf("empty %+v", z)
	}
}

func TestSeries(t *testing.T) {
	from := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	to := from.Add(4 * time.Hour)
	samples := []Sample{
		{Time: from.Add(10 * time.Minute), OK: true, TotalMS: 100},
		{Time: from.Add(20 * time.Minute), OK: false},
		{Time: from.Add(2*time.Hour + time.Minute), OK: true, TotalMS: 300},
		{Time: from.Add(-time.Minute), OK: true, TotalMS: 1}, // outside
		{Time: to, OK: true, TotalMS: 1},                     // outside (end is exclusive)
	}
	b := Series(samples, from, to, time.Hour)
	if len(b) != 4 {
		t.Fatalf("want 4 buckets, got %d", len(b))
	}
	if b[0].Checks != 2 || b[0].Successes != 1 || !near(b[0].Uptime, 50) || !near(b[0].P50MS, 100) {
		t.Fatalf("bucket 0 %+v", b[0])
	}
	if b[1].Checks != 0 {
		t.Fatalf("empty bucket must stay empty (a gap), got %+v", b[1])
	}
	if b[2].Checks != 1 || !near(b[2].P95MS, 300) {
		t.Fatalf("bucket 2 %+v", b[2])
	}
}

func TestBucketWidth(t *testing.T) {
	for w, want := range map[time.Duration]time.Duration{time.Hour: time.Minute, 24 * time.Hour: 15 * time.Minute, 7 * 24 * time.Hour: 2 * time.Hour, 30 * 24 * time.Hour: 6 * time.Hour} {
		if got := BucketWidth(w); got != want {
			t.Errorf("BucketWidth(%s) = %s", w, got)
		}
	}
}
