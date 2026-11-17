package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
	"github.com/FusionProxies/proxy-health-monitor/internal/testproxy"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageAndUnknown(t *testing.T) {
	if code, out, _ := runCLI(); code != 0 || !strings.Contains(out, "Commands:") {
		t.Fatalf("usage: %d %s", code, out)
	}
	if code, _, errs := runCLI("frobnicate"); code != exitUsage || !strings.Contains(errs, "unknown command") {
		t.Fatalf("unknown: %d %s", code, errs)
	}
	if code, _, _ := runCLI("check", "-h"); code != 0 {
		t.Fatalf("-h: %d", code)
	}
}

func TestInitAndValidate(t *testing.T) {
	defer redact.Reset()
	p := filepath.Join(t.TempDir(), "pm.yaml")
	if code, out, errs := runCLI("init", "-config", p); code != 0 || !strings.Contains(out, "Wrote") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if code, _, errs := runCLI("init", "-config", p); code != exitUsage || !strings.Contains(errs, "already exists") {
		t.Fatalf("second init must not overwrite: %d", code)
	}
	t.Setenv("VENDOR_PROXY_USER", "u")
	t.Setenv("VENDOR_PROXY_PASS", "secret-pass")
	code, out, errs := runCLI("validate", "-config", p)
	if code != 0 || !strings.Contains(out, "is valid: 2 proxies") || strings.Contains(out, "secret-pass") {
		t.Fatalf("validate: %d %s %s", code, out, errs)
	}
	if code, _, errs := runCLI("validate", "-config", filepath.Join(t.TempDir(), "missing.yaml")); code != exitUsage || !strings.Contains(errs, "proxy-monitor init") {
		t.Fatalf("missing file hint: %d %s", code, errs)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pm.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckCommand(t *testing.T) {
	defer redact.Reset()
	tg, err := testproxy.StartTarget(false)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	px, err := testproxy.StartHTTP("", "cli-user", "cli-password-123")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()
	cfg := writeConfig(t, `
targets:
  - name: t
    url: `+tg.URL+`
    expect_body: ok
proxies:
  - name: good
    url: http://`+px.Addr()+`
    username: cli-user
    password: cli-password-123
    interval: 5s
    timeout: 3s
  - name: bad
    url: http://`+px.Addr()+`
    username: cli-user
    password: wrong-password-456
    interval: 5s
    timeout: 3s
`)
	code, out, errs := runCLI("check", "-config", cfg, "-proxy", "good")
	if code != 0 || !strings.Contains(out, "1 of 1 proxies passed") {
		t.Fatalf("good: %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = runCLI("check", "-config", cfg)
	if code != exitFailed || !strings.Contains(out, "auth_failed") || !strings.Contains(out, "1 of 2 proxies passed") {
		t.Fatalf("mixed: %d\n%s", code, out)
	}
	if strings.Contains(out, "cli-password-123") || strings.Contains(out, "wrong-password-456") {
		t.Fatalf("password printed:\n%s", out)
	}
	code, out, _ = runCLI("check", "-config", cfg, "-json")
	var res struct {
		Total, Failed int
		Results       []struct {
			Proxy string `json:"proxy"`
			OK    bool   `json:"ok"`
			URL   string `json:"url"`
		}
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Total != 2 || res.Failed != 1 || code != exitFailed {
		t.Fatalf("json: %v %+v", err, res)
	}
	if strings.Contains(res.Results[0].URL, "cli-user") {
		t.Fatalf("username in JSON url: %s", res.Results[0].URL)
	}
	if code, _, errs := runCLI("check", "-config", cfg, "-proxy", "nope"); code != exitUsage || !strings.Contains(errs, "no proxy named") {
		t.Fatalf("unknown proxy: %d", code)
	}
}

func TestStatusAndReport(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, `
storage:
  path: `+filepath.ToSlash(filepath.Join(dir, "m.db"))+`
targets:
  - name: t
    url: http://127.0.0.1:9/healthz
proxies:
  - name: alpha
    url: http://127.0.0.1:3128
  - name: beta
    url: socks5h://127.0.0.1:1080
`)
	if code, _, errs := runCLI("status", "-config", cfg); code != exitRuntime || !strings.Contains(errs, "no database") {
		t.Fatalf("status without a database: %d %s", code, errs)
	}
	st, err := storage.Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 10; i++ {
		_ = st.InsertCheck(checks.Result{Proxy: "alpha", Time: now.Add(-time.Duration(i) * time.Minute), OK: true, Total: time.Duration(100+i*10) * time.Millisecond})
		_ = st.InsertCheck(checks.Result{Proxy: "beta", Time: now.Add(-time.Duration(i) * time.Minute), OK: i > 3, Class: map[bool]checks.Class{true: "", false: checks.ClassTimeout}[i > 3], Total: 300 * time.Millisecond})
	}
	_ = st.SaveState(storage.ProxyState{Proxy: "alpha", State: "healthy", LastCheck: now})
	_ = st.SaveState(storage.ProxyState{Proxy: "beta", State: "down", LastCheck: now, ConsecutiveFailures: 4, LastError: "no answer"})
	id, _ := st.OpenIncident("beta", "down", "4 consecutive failed checks", "no answer", 4, now.Add(-4*time.Minute))
	_ = id
	st.Close()

	code, out, _ := runCLI("status", "-config", cfg)
	if code != exitFailed || !strings.Contains(out, "DOWN") || !strings.Contains(out, "Open incidents") {
		t.Fatalf("status: %d\n%s", code, out)
	}
	code, out, _ = runCLI("report", "-config", cfg, "-since", "1h", "-format", "markdown")
	if code != 0 || !strings.Contains(out, "| alpha | HTTP forward | 10 | 100.00%") || !strings.Contains(out, "| beta |") || !strings.Contains(out, "### beta incidents") {
		t.Fatalf("markdown:\n%s", out)
	}
	code, out, _ = runCLI("report", "-config", cfg, "-format", "csv", "-proxy", "beta")
	if code != 0 || !strings.HasPrefix(out, "proxy,protocol,checks") || !strings.Contains(out, "beta,SOCKS5 (remote DNS),10,6,60.00") {
		t.Fatalf("csv:\n%s", out)
	}
	code, out, _ = runCLI("report", "-config", cfg, "-format", "json", "-since", "7d")
	if code != 0 || !strings.Contains(out, `"period": "7d"`) {
		t.Fatalf("json:\n%s", out)
	}
	code, out, _ = runCLI("report", "-config", cfg)
	if code != 0 || !strings.Contains(out, "timeout (4)") {
		t.Fatalf("table:\n%s", out)
	}
	if code, _, _ := runCLI("report", "-config", cfg, "-format", "xml"); code != exitUsage {
		t.Fatalf("bad format: %d", code)
	}
}
