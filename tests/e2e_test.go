// Package tests runs the whole monitor (scheduler, storage, alerts, API and
// metrics) against local test proxies. Nothing here touches the network
// beyond 127.0.0.1.
package tests

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/alerts"
	"github.com/FusionProxies/proxy-health-monitor/internal/app"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/testproxy"
)

const (
	token  = "e2e-token-0123456789abcdef"
	secret = "e2e-webhook-secret"
	pass   = "E2e-Proxy-Pa55"
)

type hook struct {
	mu     sync.Mutex
	events []alerts.WebhookPayload
	badSig int
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Header.Get("X-Proxy-Monitor-Signature") != alerts.Sign(secret, r.Header.Get("X-Proxy-Monitor-Timestamp"), body) {
		h.badSig++
	}
	var p alerts.WebhookPayload
	_ = json.Unmarshal(body, &p)
	h.events = append(h.events, p)
}

func (h *hook) has(event, proxy string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.events {
		if e.Event == event && e.Proxy == proxy {
			return true
		}
	}
	return false
}

func get(t *testing.T, base, path string, v any) string {
	t.Helper()
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
	}
	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
	}
	return string(body)
}

type proxiesResp struct {
	Proxies []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"proxies"`
}

func states(t *testing.T, base string) map[string]string {
	var r proxiesResp
	get(t, base, "/api/proxies", &r)
	out := map[string]string{}
	for _, p := range r.Proxies {
		out[p.Name] = p.State
	}
	return out
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test takes about 15 seconds")
	}
	defer redact.Reset()
	tg, err := testproxy.StartTarget(false)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	httpPx, err := testproxy.StartHTTP("", "e2e-user", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer httpPx.Close()
	socksPx, err := testproxy.StartSOCKS5("", "e2e-user", pass)
	if err != nil {
		t.Fatal(err)
	}
	defer socksPx.Close()
	h := &hook{}
	hs := httptest.NewServer(h)
	defer hs.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pm.yaml")
	t.Setenv("E2E_PASS", pass)
	body := `
storage:
  path: ` + filepath.ToSlash(filepath.Join(dir, "e2e.db")) + `
server:
  listen: 127.0.0.1:0
  auth_token: ` + token + `
monitor:
  interval: 1s
  timeout: 800ms
  jitter: 0
thresholds:
  failure_threshold: 2
  recovery_threshold: 2
targets:
  - name: own
    url: ` + tg.URL + `
    expect_body: ok
    min_spacing: 10ms
proxies:
  - name: http-forward
    url: http://` + httpPx.Addr() + `
    username: e2e-user
    password: ${E2E_PASS}
    interval: 1s
    timeout: 800ms
  - name: socks
    url: socks5h://` + socksPx.Addr() + `
    username: e2e-user
    password: ${E2E_PASS}
    interval: 1s
    timeout: 800ms
  - name: rotated-password
    url: socks5h://` + socksPx.Addr() + `
    username: e2e-user
    password: not-the-password
    interval: 1s
    timeout: 800ms
alerts:
  cooldown: 1s
  console: false
  webhooks:
    - name: test
      url: ` + hs.URL + `
      secret: ` + secret + `
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), app.Options{Ready: ready})
	}()
	base := "http://" + <-ready

	waitFor(t, "first states", 8*time.Second, func() bool {
		s := states(t, base)
		return s["http-forward"] == "healthy" && s["socks"] == "healthy" && s["rotated-password"] == "down"
	})
	waitFor(t, "down alert for the wrong password", 5*time.Second, func() bool { return h.has("down", "rotated-password") })

	// Outage on the SOCKS5 proxy, then recovery.
	socksPx.SetDown(true)
	waitFor(t, "socks down", 8*time.Second, func() bool { return states(t, base)["socks"] == "down" })
	socksPx.SetDown(false)
	waitFor(t, "socks recovered", 8*time.Second, func() bool { return states(t, base)["socks"] == "healthy" })
	waitFor(t, "recovery alert", 5*time.Second, func() bool { return h.has("recovered", "socks") })

	var inc struct {
		Incidents []struct {
			Proxy string `json:"proxy"`
			Kind  string `json:"kind"`
			Open  bool   `json:"open"`
		} `json:"incidents"`
	}
	get(t, base, "/api/incidents", &inc)
	var closedSocks, openRotated bool
	for _, i := range inc.Incidents {
		if i.Proxy == "socks" && i.Kind == "down" && !i.Open {
			closedSocks = true
		}
		if i.Proxy == "rotated-password" && i.Open {
			openRotated = true
		}
	}
	if !closedSocks || !openRotated {
		t.Fatalf("incidents: %+v", inc.Incidents)
	}

	metrics := get(t, base, "/metrics", nil)
	for _, want := range []string{`proxy_monitor_up{proxy="http-forward"`, `proxy_monitor_check_errors_total{proxy="rotated-password",class="auth_failed"}`, `proxy_monitor_state{proxy="rotated-password",state="down"} 1`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	all := get(t, base, "/api/proxies", nil) + get(t, base, "/api/proxies/rotated-password", nil) + get(t, base, "/api/alerts", nil) + metrics
	if strings.Contains(all, pass) || strings.Contains(all, "not-the-password") || strings.Contains(all, "e2e-user") {
		t.Fatal("credentials in API output")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("monitor did not shut down")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.badSig != 0 {
		t.Fatalf("%d webhook deliveries had a bad signature", h.badSig)
	}
}
