package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `
targets:
  - name: own
    url: https://health.example.com/healthz
proxies:
  - name: p1
    url: http://proxy.example.com:3128
`

func TestSampleConfigIsValid(t *testing.T) {
	defer redact.Reset()
	p := write(t, Sample)
	cfg, err := LoadWithEnv(p, env(map[string]string{"VENDOR_PROXY_USER": "vendor-user", "VENDOR_PROXY_PASS": "vendor-pass"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxies) != 2 || cfg.Proxies[1].Scheme != "socks5h" || cfg.Proxies[1].Interval.D() != 2*time.Minute {
		t.Fatalf("unexpected sample result: %+v", cfg.Proxies[1])
	}
	if cfg.Server.Listen != "127.0.0.1:8090" {
		t.Fatalf("dashboard must default to localhost, got %s", cfg.Server.Listen)
	}
	if cfg.Storage.Path != filepath.Join(filepath.Dir(p), "proxy-monitor.db") {
		t.Fatalf("relative storage path not resolved against the config dir: %s", cfg.Storage.Path)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := LoadWithEnv(write(t, minimal), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Proxies[0]
	if p.Interval.D() != time.Minute || p.Timeout.D() != 10*time.Second {
		t.Fatalf("interval %s timeout %s", p.Interval, p.Timeout)
	}
	if p.Target != "own" || p.Mode != ModeConnect {
		t.Fatalf("single target should be implied and https means CONNECT: %+v", p)
	}
	if cfg.Thresholds.FailureThreshold != 3 || cfg.Thresholds.Availability != 95 || cfg.Alerts.Cooldown.D() != 10*time.Minute {
		t.Fatalf("threshold defaults: %+v", cfg.Thresholds)
	}
	if cfg.Storage.Retention.D() != 30*24*time.Hour {
		t.Fatalf("retention default %s", cfg.Storage.Retention)
	}
}

func TestEnvExpansion(t *testing.T) {
	defer redact.Reset()
	body := minimal + `    username: ${U}-country-us
    password: ${P}
alerts:
  email:
    host: localhost
    port: ${SMTP_PORT}
    tls: none
    from: a@example.com
    to: [b@example.com]
    password: "$${literal}"
  telegram:
    bot_token: ${TG}
    chat_id: ${CHAT}
`
	cfg, err := LoadWithEnv(write(t, body), env(map[string]string{"U": "user1", "P": "null", "SMTP_PORT": "2525", "TG": "123:abc", "CHAT": "-100123"}))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Proxies[0]
	pw, _ := p.Parsed.User.Password()
	if p.Parsed.User.Username() != "user1-country-us" || pw != "null" {
		t.Fatalf("got user %q pass %q", p.Parsed.User.Username(), pw)
	}
	if cfg.Alerts.Email.Port != 2525 || cfg.Alerts.Email.Password != "${literal}" {
		t.Fatalf("email: %+v", cfg.Alerts.Email)
	}
	if cfg.Alerts.Telegram.ChatID != "-100123" {
		t.Fatalf("chat id %q", cfg.Alerts.Telegram.ChatID)
	}
	if got := redact.String("token 123:abc"); strings.Contains(got, "123:abc") {
		t.Fatalf("telegram token not registered as a secret: %s", got)
	}
}

func TestMissingEnv(t *testing.T) {
	_, err := LoadWithEnv(write(t, minimal+"    password: ${NOPE}\n    username: ${ALSO_NOPE}\n"), env(nil))
	if err == nil || !strings.Contains(err.Error(), "NOPE") || !strings.Contains(err.Error(), "ALSO_NOPE") {
		t.Fatalf("expected both missing variables named, got %v", err)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := LoadWithEnv(write(t, minimal+"    intervall: 30s\n"), env(nil))
	if err == nil || !strings.Contains(err.Error(), "intervall") {
		t.Fatalf("typo not reported: %v", err)
	}
}

func TestMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func validate(t *testing.T, body string) error {
	t.Helper()
	_, err := LoadWithEnv(write(t, body), env(map[string]string{"TOKEN": "0123456789abcdef0123"}))
	return err
}

func TestValidationRules(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"interval floor", minimal + "    interval: 5s\n", "below the minimum of 10s"},
		{"timeout vs interval", minimal + "    interval: 10s\n    timeout: 10s\n", "must be shorter than interval"},
		{"remote dashboard without token", "server:\n  listen: 0.0.0.0:8090\n" + minimal, "reachable from other machines"},
		{"short token", "server:\n  auth_token: short\n" + minimal, "at least 16 characters"},
		{"udp scheme", strings.Replace(minimal, "http://proxy.example.com:3128", "socks4://proxy.example.com:1080", 1), "unsupported scheme"},
		{"no port", strings.Replace(minimal, "http://proxy.example.com:3128", "http://proxy.example.com", 1), "host and a port"},
		{"forward to https", minimal + "    mode: forward\n", "cannot reach an https:// target"},
		{"mode on socks", strings.Replace(minimal, "http://proxy.example.com:3128", "socks5://proxy.example.com:1080", 1) + "    mode: connect\n", "only to http"},
		{"unknown target", minimal + "    target: other\n", "not defined under targets"},
		{"duplicate proxy", minimal + "  - name: p1\n    url: http://b.example.com:1\n", "duplicate name"},
		{"bad name", strings.Replace(minimal, "name: p1", "name: \"has space\"", 1), "name must be"},
		{"credentials in target", strings.Replace(minimal, "https://health", "https://u:p@health", 1), "credentials in the target"},
		{"tls none remote", minimal + "alerts:\n  email:\n    host: smtp.example.com\n    tls: none\n    from: a@x.io\n    to: [b@x.io]\n", "only for an SMTP relay on localhost"},
		{"bad event", minimal + "alerts:\n  webhooks:\n    - url: https://h.example.com\n      events: [downn]\n", "unknown event"},
		{"repeat too short", minimal + "alerts:\n  repeat_interval: 1m\n", "at least 5m"},
		{"availability range", minimal + "thresholds:\n  availability: 150\n", "availability must be"},
		{"no proxies", "targets:\n  - name: a\n    url: http://x.example.com/\n", "no enabled proxies"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validate(t, c.body)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestRemoteDashboardAllowedWithToken(t *testing.T) {
	if err := validate(t, "server:\n  listen: 0.0.0.0:8090\n  auth_token: ${TOKEN}\n"+minimal); err != nil {
		t.Fatal(err)
	}
	if err := validate(t, "server:\n  listen: 0.0.0.0:8090\n  allow_remote_without_auth: true\n"+minimal); err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackProxyMayUseShortInterval(t *testing.T) {
	body := strings.Replace(minimal, "http://proxy.example.com:3128", "http://127.0.0.1:3128", 1) + "    interval: 2s\n    timeout: 1s\n"
	if err := validate(t, body); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialsFromFieldsOverrideURL(t *testing.T) {
	defer redact.Reset()
	cfg, err := LoadWithEnv(write(t, strings.Replace(minimal, "http://proxy.example.com:3128", "http://old:oldpw@proxy.example.com:3128", 1)+"    username: new-user\n    password: \"p@ss:w/rd\"\n"), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Proxies[0].Parsed.User
	pw, _ := u.Password()
	if u.Username() != "new-user" || pw != "p@ss:w/rd" {
		t.Fatalf("got %s / %s", u.Username(), pw)
	}
	if d := cfg.Proxies[0].DisplayURL(); strings.Contains(d, "p@ss") || strings.Contains(d, "new-user") {
		t.Fatalf("display URL leaks: %s", d)
	}
}

func TestThresholdOverrides(t *testing.T) {
	cfg, err := LoadWithEnv(write(t, minimal+"    thresholds:\n      latency: 800ms\n      failure_threshold: 5\n"), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	e := cfg.Proxies[0].Effective
	if e.Latency.D() != 800*time.Millisecond || e.FailureThreshold != 5 || e.RecoveryThreshold != 2 {
		t.Fatalf("effective thresholds: %+v", e)
	}
}

func TestDurations(t *testing.T) {
	cases := map[string]time.Duration{"0": 0, "90s": 90 * time.Second, "7d": 7 * 24 * time.Hour, "1.5d": 36 * time.Hour, "1h30m": 90 * time.Minute}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-5s", "abc", "5x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) should fail", bad)
		}
	}
	fmts := map[time.Duration]string{0: "0s", 7 * 24 * time.Hour: "7d", 5 * time.Minute: "5m", time.Hour: "1h", 90 * time.Second: "1m30s", 2*time.Hour + 5*time.Minute: "2h5m"}
	for in, want := range fmts {
		if got := FormatDuration(in); got != want {
			t.Errorf("FormatDuration(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"127.0.0.1": true, "::1": true, "[::1]": true, "localhost": true, "LOCALHOST": true, "": false, "0.0.0.0": false, "10.0.0.1": false, "example.com": false} {
		if IsLoopbackHost(h) != want {
			t.Errorf("IsLoopbackHost(%q) != %v", h, want)
		}
	}
}
