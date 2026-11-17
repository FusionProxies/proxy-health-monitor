package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
	"github.com/FusionProxies/proxy-health-monitor/internal/metrics"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/scheduler"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
)

const (
	token    = "test-token-0123456789abcdef"
	proxyPW  = "Pr0xyPassw0rd!"
	proxyUsr = "customer-4711-country-de"
)

type fakeTrigger struct {
	calls []string
	err   error
}

func (f *fakeTrigger) Trigger(name string) error {
	f.calls = append(f.calls, name)
	return f.err
}

type setup struct {
	srv   *Server
	store *storage.Store
	cfg   *config.Config
	trig  *fakeTrigger
	reg   *metrics.Registry
}

func newSetup(t *testing.T, tok, listen string, allowed []string) *setup {
	t.Helper()
	t.Cleanup(redact.Reset)
	cfg := &config.Config{
		Server:  config.Server{Listen: listen, AuthToken: tok, AllowedHosts: allowed},
		Targets: []*config.Target{{Name: "own", URL: "https://health.example.com/healthz?key=abc123"}},
		Proxies: []*config.Proxy{{Name: "p1", URL: "socks5h://proxy.example.com:1080", Username: proxyUsr, Password: proxyPW, Labels: map[string]string{"region": "de"}}},
	}
	if err := cfg.Validate(""); err != nil {
		t.Fatal(err)
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg := metrics.New("test")
	reg.Register("p1", cfg.Proxies[0].Protocol(), "own")
	trig := &fakeTrigger{}
	srv := New(Options{Config: cfg, Store: st, Metrics: reg, Trigger: trig, Version: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Channels: []string{"console"}})
	return &setup{srv: srv, store: st, cfg: cfg, trig: trig, reg: reg}
}

func (s *setup) do(method, path, host string, mod func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:50000"
	if mod != nil {
		mod(req)
	}
	rr := httptest.NewRecorder()
	s.srv.Handler().ServeHTTP(rr, req)
	return rr
}

func bearer(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }

func TestHealthIsPublicButTerse(t *testing.T) {
	s := newSetup(t, token, "127.0.0.1:8090", nil)
	rr := s.do("GET", "/api/health", "127.0.0.1:8090", nil)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "version") {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	rr = s.do("GET", "/api/health", "127.0.0.1:8090", bearer)
	if !strings.Contains(rr.Body.String(), `"version"`) {
		t.Fatalf("authorized health should include details: %s", rr.Body)
	}
}

func TestAuthentication(t *testing.T) {
	s := newSetup(t, token, "127.0.0.1:8090", nil)
	for _, path := range []string{"/api/proxies", "/api/metrics", "/api/incidents", "/api/settings", "/metrics", "/", "/static/app.js"} {
		rr := s.do("GET", path, "127.0.0.1:8090", nil)
		if rr.Code != 401 || !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("%s without auth: %d", path, rr.Code)
		}
	}
	if rr := s.do("GET", "/api/proxies", "127.0.0.1:8090", bearer); rr.Code != 200 {
		t.Fatalf("bearer: %d", rr.Code)
	}
	if rr := s.do("GET", "/api/proxies", "127.0.0.1:8090", func(r *http.Request) { r.SetBasicAuth("anyone", token) }); rr.Code != 200 {
		t.Fatalf("basic: %d", rr.Code)
	}
	if rr := s.do("GET", "/api/proxies", "127.0.0.1:8090", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }); rr.Code != 401 {
		t.Fatalf("wrong token: %d", rr.Code)
	}
}

func TestFailedAuthThrottle(t *testing.T) {
	s := newSetup(t, token, "127.0.0.1:8090", nil)
	for i := 0; i < throttleMax; i++ {
		s.do("GET", "/api/proxies", "127.0.0.1:8090", func(r *http.Request) { r.Header.Set("Authorization", "Bearer guess"+fmt.Sprint(i)) })
	}
	if rr := s.do("GET", "/api/proxies", "127.0.0.1:8090", bearer); rr.Code != 429 {
		t.Fatalf("after %d failures even the right token waits: %d", throttleMax, rr.Code)
	}
}

func TestNoTokenOnLoopback(t *testing.T) {
	s := newSetup(t, "", "127.0.0.1:8090", nil)
	if rr := s.do("GET", "/api/proxies", "localhost:8090", nil); rr.Code != 200 {
		t.Fatalf("%d", rr.Code)
	}
}

func TestHostCheckBlocksDNSRebinding(t *testing.T) {
	s := newSetup(t, "", "127.0.0.1:8090", []string{"monitor.example.com"})
	if rr := s.do("GET", "/api/proxies", "attacker.example:8090", nil); rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host on a loopback dashboard: %d", rr.Code)
	}
	for _, h := range []string{"127.0.0.1:8090", "localhost:8090", "[::1]:8090", "monitor.example.com"} {
		if rr := s.do("GET", "/api/proxies", h, nil); rr.Code != 200 {
			t.Fatalf("Host %s: %d", h, rr.Code)
		}
	}
	// Bound to all interfaces: any Host, unless allowed_hosts narrows it.
	r := newSetup(t, token, "0.0.0.0:8090", nil)
	if rr := r.do("GET", "/api/proxies", "10.1.2.3:8090", bearer); rr.Code != 200 {
		t.Fatalf("remote listen: %d", rr.Code)
	}
	n := newSetup(t, token, "0.0.0.0:8090", []string{"monitor.example.com"})
	if rr := n.do("GET", "/api/proxies", "10.1.2.3:8090", bearer); rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("allowed_hosts not enforced: %d", rr.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newSetup(t, "", "127.0.0.1:8090", nil)
	rr := s.do("GET", "/", "127.0.0.1:8090", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Proxy Health Monitor") {
		t.Fatalf("dashboard: %d", rr.Code)
	}
	h := rr.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") || h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", h)
	}
	if rr := s.do("GET", "/static/app.js", "127.0.0.1:8090", nil); rr.Code != 200 {
		t.Fatalf("app.js %d", rr.Code)
	}
	if rr := s.do("GET", "/nope", "127.0.0.1:8090", nil); rr.Code != 404 {
		t.Fatalf("unknown path %d", rr.Code)
	}
}

func TestManagementEndpoint(t *testing.T) {
	// Without a token the endpoint is off, even on localhost.
	s := newSetup(t, "", "127.0.0.1:8090", nil)
	if rr := s.do("POST", "/api/proxies/p1/check", "127.0.0.1:8090", func(r *http.Request) { r.Header.Set("X-Proxy-Monitor-Request", "1") }); rr.Code != 403 {
		t.Fatalf("no token: %d", rr.Code)
	}

	s = newSetup(t, token, "127.0.0.1:8090", nil)
	if rr := s.do("POST", "/api/proxies/p1/check", "127.0.0.1:8090", bearer); rr.Code != 403 {
		t.Fatalf("missing CSRF header: %d", rr.Code)
	}
	cross := func(r *http.Request) {
		bearer(r)
		r.Header.Set("X-Proxy-Monitor-Request", "1")
		r.Header.Set("Origin", "https://evil.example")
	}
	if rr := s.do("POST", "/api/proxies/p1/check", "127.0.0.1:8090", cross); rr.Code != 403 {
		t.Fatalf("cross-origin: %d", rr.Code)
	}
	ok := func(r *http.Request) {
		bearer(r)
		r.Header.Set("X-Proxy-Monitor-Request", "1")
		r.Header.Set("Origin", "http://127.0.0.1:8090")
	}
	if rr := s.do("POST", "/api/proxies/p1/check", "127.0.0.1:8090", ok); rr.Code != 202 || len(s.trig.calls) != 1 {
		t.Fatalf("valid request: %d %v", rr.Code, s.trig.calls)
	}
	if rr := s.do("POST", "/api/proxies/nope/check", "127.0.0.1:8090", ok); rr.Code != 404 {
		t.Fatalf("unknown proxy: %d", rr.Code)
	}
	s.trig.err = fmt.Errorf("%w: wait 10s", scheduler.ErrTooSoon)
	if rr := s.do("POST", "/api/proxies/p1/check", "127.0.0.1:8090", ok); rr.Code != 409 {
		t.Fatalf("too soon: %d", rr.Code)
	}
	if rr := s.do("GET", "/api/proxies/p1/check", "127.0.0.1:8090", bearer); rr.Code == 202 {
		t.Fatal("GET must not trigger a check")
	}
}

func TestNoCredentialsInAnyOutput(t *testing.T) {
	s := newSetup(t, "", "127.0.0.1:8090", nil)
	now := time.Now()
	// Simulate an error message that carries credentials.
	leaky := "proxy http://" + proxyUsr + ":" + proxyPW + "@proxy.example.com:1080 said 407"
	_ = s.store.InsertCheck(checks.Result{Proxy: "p1", Time: now.Add(-time.Minute), Class: checks.ClassAuth, Error: leaky})
	_ = s.store.InsertCheck(checks.Result{Proxy: "p1", Time: now, OK: true, Total: 120 * time.Millisecond})
	_ = s.store.SaveState(storage.ProxyState{Proxy: "p1", State: "degraded", LastCheck: now, LastError: leaky, LastErrorClass: "auth_failed"})
	_, _ = s.store.OpenIncident("p1", "down", leaky, leaky, 3, now)
	_ = s.store.RecordAlert(storage.AlertRecord{Time: now, Proxy: "p1", Kind: "down", Status: "sent", Message: leaky})
	s.reg.Observe(checks.Result{Proxy: "p1", Time: now, OK: true, Total: time.Second}, health.Healthy, 0, 1)

	for _, path := range []string{"/api/proxies", "/api/proxies/p1", "/api/proxies/p1/checks", "/api/incidents", "/api/alerts", "/api/settings", "/api/metrics", "/metrics"} {
		rr := s.do("GET", path, "127.0.0.1:8090", nil)
		if rr.Code != 200 {
			t.Fatalf("%s: %d", path, rr.Code)
		}
		body := rr.Body.String()
		for _, secret := range []string{proxyPW, proxyUsr, "abc123"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s leaks %q", path, secret)
			}
		}
	}
}

func TestProxyDetailAndSeries(t *testing.T) {
	s := newSetup(t, "", "127.0.0.1:8090", nil)
	now := time.Now()
	for i := 0; i < 20; i++ {
		_ = s.store.InsertCheck(checks.Result{Proxy: "p1", Time: now.Add(-time.Duration(i) * time.Minute), OK: i%5 != 0, Total: time.Duration(100+i) * time.Millisecond, Class: map[bool]checks.Class{true: "", false: checks.ClassTimeout}[i%5 != 0]})
	}
	rr := s.do("GET", "/api/proxies/p1", "127.0.0.1:8090", nil)
	var d struct {
		Proxy     ProxyView                  `json:"proxy"`
		Summaries map[string]json.RawMessage `json:"summaries"`
		Errors    []storage.CheckRow         `json:"recent_errors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Proxy.Day.Checks != 20 || d.Proxy.Day.Successes != 16 || len(d.Errors) != 4 || d.Proxy.Protocol != "SOCKS5 (remote DNS)" {
		t.Fatalf("detail %+v errors %d", d.Proxy.Day, len(d.Errors))
	}
	rr = s.do("GET", "/api/proxies/p1/series?window=1h", "127.0.0.1:8090", nil)
	var sr struct {
		BucketSeconds int `json:"bucket_seconds"`
		Buckets       []struct {
			Checks int `json:"checks"`
		} `json:"buckets"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &sr)
	total := 0
	for _, b := range sr.Buckets {
		total += b.Checks
	}
	if sr.BucketSeconds != 60 || total != 20 {
		t.Fatalf("series: bucket %ds, %d checks", sr.BucketSeconds, total)
	}
	if rr := s.do("GET", "/api/proxies/nope", "127.0.0.1:8090", nil); rr.Code != 404 {
		t.Fatalf("unknown proxy %d", rr.Code)
	}
}

func TestPrometheusOutput(t *testing.T) {
	s := newSetup(t, token, "127.0.0.1:8090", nil)
	now := time.Now()
	s.reg.Observe(checks.Result{Proxy: "p1", Time: now, OK: true, Total: 700 * time.Millisecond, Connect: 20 * time.Millisecond}, health.Healthy, 0, 0)
	s.reg.Observe(checks.Result{Proxy: "p1", Time: now, Class: checks.ClassTimeout}, health.Degraded, 1, 0)
	rr := s.do("GET", "/metrics", "127.0.0.1:8090", bearer)
	body := rr.Body.String()
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("content type %s", rr.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		`proxy_monitor_up{proxy="p1",protocol="SOCKS5 (remote DNS)",target="own"} 0`,
		`proxy_monitor_state{proxy="p1",state="degraded"} 1`,
		`proxy_monitor_checks_total{proxy="p1",result="success"} 1`,
		`proxy_monitor_check_errors_total{proxy="p1",class="timeout"} 1`,
		`proxy_monitor_check_duration_seconds_bucket{proxy="p1",le="0.5"} 0`,
		`proxy_monitor_check_duration_seconds_bucket{proxy="p1",le="1"} 1`,
		`proxy_monitor_check_duration_seconds_count{proxy="p1"} 1`,
		`proxy_monitor_phase_seconds{proxy="p1",phase="connect"} 0.02`,
		"# TYPE proxy_monitor_check_duration_seconds histogram",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}
