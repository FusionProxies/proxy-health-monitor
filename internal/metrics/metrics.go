// Package metrics keeps in-memory counters and gauges and writes them in the
// Prometheus text exposition format (version 0.0.4). It has no dependency on
// the Prometheus client library.
//
// Label values never contain credentials: proxies are identified by their
// configured name.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
)

// Buckets for the check duration histogram, in seconds.
var Buckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 30}

type proxyMetrics struct {
	protocol, target  string
	state             health.State
	up                int
	consecFail        int
	success, failure  uint64
	errors            map[string]uint64
	lastCheck         time.Time
	lastSuccess       time.Time
	phases            [6]float64 // dns, connect, handshake, tls, ttfb, total (seconds, last successful check)
	bucketCounts      []uint64
	sum               float64
	count             uint64
	bytesIn, bytesOut uint64
	openIncidents     int
}

// Registry holds the metrics of every proxy.
type Registry struct {
	mu      sync.Mutex
	proxies map[string]*proxyMetrics
	version string
	started time.Time
}

// New returns an empty registry.
func New(version string) *Registry {
	return &Registry{proxies: map[string]*proxyMetrics{}, version: version, started: time.Now()}
}

// Register declares a proxy so it is exported before its first check.
func (r *Registry) Register(name, protocol, target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.proxies[name]; !ok {
		r.proxies[name] = &proxyMetrics{protocol: protocol, target: target, state: health.Unknown, errors: map[string]uint64{}, bucketCounts: make([]uint64, len(Buckets))}
	}
}

// Observe records one check and the resulting state.
func (r *Registry) Observe(res checks.Result, state health.State, consecFail, openIncidents int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.proxies[res.Proxy]
	if m == nil {
		return
	}
	m.state = state
	m.consecFail = consecFail
	m.openIncidents = openIncidents
	m.lastCheck = res.Time.Add(res.Total)
	m.bytesIn += uint64(res.BytesIn)
	m.bytesOut += uint64(res.BytesOut)
	if !res.OK {
		m.up = 0
		m.failure++
		m.errors[string(res.Class)]++
		return
	}
	m.up = 1
	m.success++
	m.lastSuccess = m.lastCheck
	sec := func(d time.Duration) float64 { return d.Seconds() }
	m.phases = [6]float64{sec(res.DNS), sec(res.Connect), sec(res.Handshake), sec(res.TLS), sec(res.TTFB), sec(res.Total)}
	t := res.Total.Seconds()
	for i, b := range Buckets {
		if t <= b {
			m.bucketCounts[i]++
		}
	}
	m.sum += t
	m.count++
}

// SetState updates the state without a check (restored at startup).
func (r *Registry) SetState(name string, state health.State, consecFail, openIncidents int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m := r.proxies[name]; m != nil {
		m.state, m.consecFail, m.openIncidents = state, consecFail, openIncidents
	}
}

var phaseNames = [6]string{"dns", "connect", "proxy_handshake", "tls", "ttfb", "total"}

var allStates = []health.State{health.Unknown, health.Healthy, health.Degraded, health.Down}

// Write renders every metric.
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.proxies))
	for n := range r.proxies {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	header := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}

	header("proxy_monitor_build_info", "gauge", "Build information.")
	fmt.Fprintf(&b, "proxy_monitor_build_info{version=%s} 1\n", q(r.version))
	header("proxy_monitor_start_time_seconds", "gauge", "Unix time the monitor started.")
	fmt.Fprintf(&b, "proxy_monitor_start_time_seconds %d\n", r.started.Unix())

	header("proxy_monitor_up", "gauge", "1 if the last check of the proxy succeeded, 0 if it failed or none ran yet.")
	for _, n := range names {
		m := r.proxies[n]
		fmt.Fprintf(&b, "proxy_monitor_up{proxy=%s,protocol=%s,target=%s} %d\n", q(n), q(m.protocol), q(m.target), m.up)
	}
	header("proxy_monitor_state", "gauge", "Current health state of the proxy (one series per state, the current one is 1).")
	for _, n := range names {
		for _, s := range allStates {
			v := 0
			if r.proxies[n].state == s {
				v = 1
			}
			fmt.Fprintf(&b, "proxy_monitor_state{proxy=%s,state=%s} %d\n", q(n), q(string(s)), v)
		}
	}
	header("proxy_monitor_consecutive_failures", "gauge", "Failed checks in a row.")
	for _, n := range names {
		fmt.Fprintf(&b, "proxy_monitor_consecutive_failures{proxy=%s} %d\n", q(n), r.proxies[n].consecFail)
	}
	header("proxy_monitor_open_incidents", "gauge", "Open incidents (down, latency, availability).")
	for _, n := range names {
		fmt.Fprintf(&b, "proxy_monitor_open_incidents{proxy=%s} %d\n", q(n), r.proxies[n].openIncidents)
	}
	header("proxy_monitor_checks_total", "counter", "Checks run since the monitor started, by result.")
	for _, n := range names {
		m := r.proxies[n]
		fmt.Fprintf(&b, "proxy_monitor_checks_total{proxy=%s,result=\"success\"} %d\n", q(n), m.success)
		fmt.Fprintf(&b, "proxy_monitor_checks_total{proxy=%s,result=\"failure\"} %d\n", q(n), m.failure)
	}
	header("proxy_monitor_check_errors_total", "counter", "Failed checks since the monitor started, by error class.")
	for _, n := range names {
		m := r.proxies[n]
		classes := make([]string, 0, len(m.errors))
		for c := range m.errors {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		for _, c := range classes {
			fmt.Fprintf(&b, "proxy_monitor_check_errors_total{proxy=%s,class=%s} %d\n", q(n), q(c), m.errors[c])
		}
	}
	header("proxy_monitor_last_check_timestamp_seconds", "gauge", "Unix time the last check finished.")
	for _, n := range names {
		fmt.Fprintf(&b, "proxy_monitor_last_check_timestamp_seconds{proxy=%s} %s\n", q(n), ts(r.proxies[n].lastCheck))
	}
	header("proxy_monitor_last_success_timestamp_seconds", "gauge", "Unix time the last successful check finished.")
	for _, n := range names {
		fmt.Fprintf(&b, "proxy_monitor_last_success_timestamp_seconds{proxy=%s} %s\n", q(n), ts(r.proxies[n].lastSuccess))
	}
	header("proxy_monitor_phase_seconds", "gauge", "Duration of each phase of the last successful check.")
	for _, n := range names {
		m := r.proxies[n]
		if m.success == 0 {
			continue
		}
		for i, p := range phaseNames {
			fmt.Fprintf(&b, "proxy_monitor_phase_seconds{proxy=%s,phase=%s} %s\n", q(n), q(p), f(m.phases[i]))
		}
	}
	header("proxy_monitor_check_duration_seconds", "histogram", "Total duration of successful checks.")
	for _, n := range names {
		m := r.proxies[n]
		for i, bound := range Buckets {
			fmt.Fprintf(&b, "proxy_monitor_check_duration_seconds_bucket{proxy=%s,le=%s} %d\n", q(n), q(f(bound)), m.bucketCounts[i])
		}
		fmt.Fprintf(&b, "proxy_monitor_check_duration_seconds_bucket{proxy=%s,le=\"+Inf\"} %d\n", q(n), m.count)
		fmt.Fprintf(&b, "proxy_monitor_check_duration_seconds_sum{proxy=%s} %s\n", q(n), f(m.sum))
		fmt.Fprintf(&b, "proxy_monitor_check_duration_seconds_count{proxy=%s} %d\n", q(n), m.count)
	}
	header("proxy_monitor_check_bytes_total", "counter", "Bytes exchanged with the proxy by checks, by direction.")
	for _, n := range names {
		m := r.proxies[n]
		fmt.Fprintf(&b, "proxy_monitor_check_bytes_total{proxy=%s,direction=\"in\"} %d\n", q(n), m.bytesIn)
		fmt.Fprintf(&b, "proxy_monitor_check_bytes_total{proxy=%s,direction=\"out\"} %d\n", q(n), m.bytesOut)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// q quotes a label value per the exposition format.
func q(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func f(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func ts(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return f(float64(t.UnixMilli()) / 1000)
}
