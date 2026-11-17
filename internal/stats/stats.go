// Package stats computes uptime and latency statistics from check samples.
//
// Definitions (also in docs/metrics.md):
//
//   - Uptime is successful checks divided by all checks in the period, as a
//     percentage. A period without checks has no uptime.
//   - Latency statistics use the total time of successful checks only; a
//     failed check has no meaningful latency.
//   - Percentiles use linear interpolation between the two closest ranks
//     (the same method as numpy's default and Excel's PERCENTILE.INC).
package stats

import (
	"math"
	"sort"
	"time"
)

// Sample is the part of a check result the statistics need.
type Sample struct {
	Time    time.Time
	OK      bool
	TotalMS float64
	TTFBMS  float64
	Class   string
}

// Summary describes a set of samples.
type Summary struct {
	Checks    int     `json:"checks"`
	Successes int     `json:"successes"`
	Failures  int     `json:"failures"`
	Uptime    float64 `json:"uptime"` // percent; meaningless when Checks == 0
	AvgMS     float64 `json:"avg_ms"`
	MinMS     float64 `json:"min_ms"`
	P50MS     float64 `json:"p50_ms"`
	P95MS     float64 `json:"p95_ms"`
	MaxMS     float64 `json:"max_ms"`
	TTFBP50MS float64 `json:"ttfb_p50_ms"`
	// Errors counts failures by class.
	Errors map[string]int `json:"errors,omitempty"`
}

// Percentile returns the p-th percentile (0..100) of sorted values, or 0 for
// an empty slice. The input must be sorted ascending.
func Percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := p / 100 * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo] + (sorted[hi]-sorted[lo])*frac
}

// Summarize computes a Summary.
func Summarize(samples []Sample) Summary {
	s := Summary{Checks: len(samples)}
	lat := make([]float64, 0, len(samples))
	ttfb := make([]float64, 0, len(samples))
	var sum float64
	for _, x := range samples {
		if x.OK {
			s.Successes++
			lat = append(lat, x.TotalMS)
			sum += x.TotalMS
			if x.TTFBMS > 0 {
				ttfb = append(ttfb, x.TTFBMS)
			}
			continue
		}
		s.Failures++
		if x.Class != "" {
			if s.Errors == nil {
				s.Errors = map[string]int{}
			}
			s.Errors[x.Class]++
		}
	}
	if s.Checks > 0 {
		s.Uptime = 100 * float64(s.Successes) / float64(s.Checks)
	}
	if len(lat) > 0 {
		sort.Float64s(lat)
		sort.Float64s(ttfb)
		s.AvgMS = sum / float64(len(lat))
		s.MinMS = lat[0]
		s.MaxMS = lat[len(lat)-1]
		s.P50MS = Percentile(lat, 50)
		s.P95MS = Percentile(lat, 95)
		s.TTFBP50MS = Percentile(ttfb, 50)
	}
	return s
}

// Bucket is one time slice of a series.
type Bucket struct {
	Start     time.Time `json:"start"`
	Checks    int       `json:"checks"`
	Successes int       `json:"successes"`
	Uptime    float64   `json:"uptime"`
	P50MS     float64   `json:"p50_ms"`
	P95MS     float64   `json:"p95_ms"`
}

// Series splits samples in [from, to) into buckets of the given width.
// Buckets without checks are included with Checks == 0, so a chart shows
// gaps honestly instead of joining the neighbours.
func Series(samples []Sample, from, to time.Time, width time.Duration) []Bucket {
	if width <= 0 || !to.After(from) {
		return nil
	}
	from = from.Truncate(width)
	n := int(to.Sub(from)/width) + 1
	if n > 10000 {
		n = 10000
	}
	groups := make([][]Sample, n)
	for _, s := range samples {
		if s.Time.Before(from) || !s.Time.Before(to) {
			continue
		}
		i := int(s.Time.Sub(from) / width)
		if i >= 0 && i < n {
			groups[i] = append(groups[i], s)
		}
	}
	out := make([]Bucket, 0, n)
	for i, g := range groups {
		start := from.Add(time.Duration(i) * width)
		if !start.Before(to) {
			break
		}
		sum := Summarize(g)
		out = append(out, Bucket{Start: start, Checks: sum.Checks, Successes: sum.Successes, Uptime: sum.Uptime, P50MS: sum.P50MS, P95MS: sum.P95MS})
	}
	return out
}

// BucketWidth picks a bucket width that gives a readable chart (about 60 to
// 150 points) for a window.
func BucketWidth(window time.Duration) time.Duration {
	switch {
	case window <= time.Hour:
		return time.Minute
	case window <= 6*time.Hour:
		return 5 * time.Minute
	case window <= 24*time.Hour:
		return 15 * time.Minute
	case window <= 7*24*time.Hour:
		return 2 * time.Hour
	default:
		return 6 * time.Hour
	}
}
