package doctor

import (
	"net/url"
	"strings"
	"testing"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

func levels(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, string(f.Level))
	}
	return strings.Join(s, ",")
}

func TestLintURL(t *testing.T) {
	defer redact.Reset()
	cases := []struct {
		raw, use, levels, mention string
		ok                        bool
	}{
		{"http://proxy.example.com:8080", "http://proxy.example.com:8080", "", "", true},
		{"  http://h.example:1  ", "http://h.example:1", "warn", "spaces", true},
		{"1.2.3.4:8080", "http://1.2.3.4:8080", "warn", "no scheme", true},
		{"user:pass@1.2.3.4:8080", "http://user:pass@1.2.3.4:8080", "warn", "no scheme", true},
		{"socks5://h.example:1080", "socks5://h.example:1080", "info", "socks5h", true},
		{"HTTPS://h.example:443", "https://h.example:443", "info", "TLS between you and the proxy", true},
		{"socks4://h.example:1080", "", "fail", "SOCKS4", false},
		{"ftp://h.example:21", "", "fail", "unknown proxy scheme", false},
		{"", "", "fail", "no proxy URL", false},
		{"http://a b:1", "", "fail", "spaces", false},
		{"justtext", "", "fail", "does not look like", false},
		{"http://user:pa/ss@h.example:8080", "", "fail", "/ ? or #", false},
		{"http://user:100%@h.example:8080", "", "fail", "two hex digits", false},
	}
	for _, c := range cases {
		use, fs, ok := LintURL(c.raw)
		if ok != c.ok || use != c.use || levels(fs) != c.levels {
			t.Errorf("%q: got use=%q ok=%v levels=%q, want %q %v %q", c.raw, use, ok, levels(fs), c.use, c.ok, c.levels)
			continue
		}
		if c.mention != "" && !strings.Contains(fs[0].Message+" "+fs[0].Fix, c.mention) {
			t.Errorf("%q: %+v does not mention %q", c.raw, fs[0], c.mention)
		}
	}
}

func TestLintURLRepairsCredentials(t *testing.T) {
	defer redact.Reset()
	// provider export format with an @ in the password
	use, fs, ok := LintURL("proxy.example.com:8080:customer-1:p@ss:w0rd")
	if !ok || len(fs) != 1 || fs[0].Level != Fail || !strings.Contains(fs[0].Message, "provider export format") {
		t.Fatalf("export format: %q %+v %v", use, fs, ok)
	}
	u, err := url.Parse(use)
	if err != nil || u.Scheme != "http" || u.Host != "proxy.example.com:8080" || u.User.Username() != "customer-1" {
		t.Fatalf("repaired URL: %q %v", use, err)
	}
	if pw, _ := u.User.Password(); pw != "p@ss:w0rd" {
		t.Fatalf("password: %q", pw)
	}
	if strings.Contains(fs[0].Fix, "p@ss") || strings.Contains(fs[0].Fix, "w0rd") {
		t.Fatalf("password shown in the fix: %s", fs[0].Fix)
	}

	// unencoded @ in a URL
	use, fs, ok = LintURL("http://user:se@cret@h.example:3128")
	if !ok || fs[0].Level != Fail || !strings.Contains(fs[0].Fix, "%40") {
		t.Fatalf("@ in password: %q %+v", use, fs)
	}
	u, _ = url.Parse(use)
	if pw, _ := u.User.Password(); pw != "se@cret" || u.Host != "h.example:3128" {
		t.Fatalf("repaired: %q", use)
	}
	if strings.Contains(fs[0].Fix, "se@cret") || strings.Contains(fs[0].Fix, "se%40cret") {
		t.Fatalf("password shown: %s", fs[0].Fix)
	}
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestLintEnv(t *testing.T) {
	defer redact.Reset()
	if fs := LintEnv(env(nil), "example.com", "https"); len(fs) != 1 || fs[0].Level != Info {
		t.Fatalf("empty env: %+v", fs)
	}
	has := func(fs []Finding, l Level, text string) bool {
		for _, f := range fs {
			if f.Level == l && strings.Contains(f.Message, text) {
				return true
			}
		}
		return false
	}
	fs := LintEnv(env(map[string]string{"HTTP_PROXY": "http://a.example:1", "http_proxy": "http://b.example:1"}), "example.com", "https")
	if !has(fs, Warn, "different values") || !has(fs, Warn, "only HTTP_PROXY") {
		t.Fatalf("upper/lower and https: %+v", fs)
	}
	fs = LintEnv(env(map[string]string{"HTTPS_PROXY": "https://u:topsecret-9@p.example:8080"}), "example.com", "https")
	if !has(fs, Warn, "starts with https://") || !has(fs, Info, "username and password") {
		t.Fatalf("https scheme and credentials: %+v", fs)
	}
	if strings.Contains(redact.String("x topsecret-9 y"), "topsecret-9") {
		t.Fatal("env password not registered for masking")
	}
	fs = LintEnv(env(map[string]string{"https_proxy": "p.example:8080", "no_proxy": "localhost,.example.com"}), "www.example.com", "https")
	if !has(fs, Info, "no scheme") || !has(fs, Warn, "NO_PROXY matches www.example.com") {
		t.Fatalf("no scheme and NO_PROXY: %+v", fs)
	}
}

func TestBypasses(t *testing.T) {
	for _, c := range []struct {
		list, host string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{".example.com", "example.com", true},
		{".example.com", "api.example.com", true},
		{"example.com", "notexample.com", false},
		{"*", "anything.test", true},
		{"10.0.0.1, other.test", "10.0.0.1", true},
		{"other.test:443", "other.test", true},
		{"", "example.com", false},
		{"other.test", "example.com", false},
	} {
		if got := bypasses(c.list, c.host); got != c.want {
			t.Errorf("bypasses(%q, %q) = %v", c.list, c.host, got)
		}
	}
}

func proxyFor(t *testing.T, raw, target, mode string) *config.Proxy {
	t.Helper()
	off := false
	p := &config.Proxy{Name: "p", URL: raw, Target: "t", Mode: mode}
	cfg := &config.Config{Server: config.Server{Enabled: &off}, Targets: []*config.Target{{Name: "t", URL: target}}, Proxies: []*config.Proxy{p}}
	if err := cfg.Validate(""); err != nil {
		t.Fatal(err)
	}
	return p
}

func statuses(ps []Phase) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.Key+"="+string(p.Status))
	}
	return strings.Join(s, " ")
}

func TestPhases(t *testing.T) {
	defer redact.Reset()
	connect := proxyFor(t, "http://p.example:8080", "https://example.com/", "")
	got := statuses(Phases(checks.Result{OK: true}, connect))
	if got != "dns=ok connect=ok proxy_handshake=ok target_tls=ok response=ok" {
		t.Fatalf("ok: %s", got)
	}
	got = statuses(Phases(checks.Result{Class: checks.ClassAuth, Phase: checks.PhaseHandshake}, connect))
	if got != "dns=ok connect=ok proxy_handshake=fail target_tls=info response=info" {
		t.Fatalf("auth: %s", got)
	}
	forward := proxyFor(t, "http://p.example:8080", "http://example.com/", "")
	got = statuses(Phases(checks.Result{Class: checks.ClassStatus, Phase: checks.PhaseResponse}, forward))
	if got != "dns=ok connect=ok response=fail" {
		t.Fatalf("forward: %s", got)
	}
	got = statuses(Phases(checks.Result{Class: checks.ClassProxyError}, forward))
	if got != "dns=ok connect=ok response=fail" {
		t.Fatalf("unknown phase: %s", got)
	}
	socks := proxyFor(t, "socks5h://p.example:1080", "http://example.com/", "")
	got = statuses(Phases(checks.Result{Class: checks.ClassDNS, Phase: checks.PhaseDNS}, socks))
	if got != "dns=fail connect=info proxy_handshake=info response=info" {
		t.Fatalf("socks dns: %s", got)
	}
}

func TestExplainCoversEveryClass(t *testing.T) {
	defer redact.Reset()
	p := proxyFor(t, "http://p.example:8080", "https://example.com/", "")
	s := proxyFor(t, "socks5://p.example:1080", "https://example.com/", "")
	if Explain(checks.Result{OK: true}, p) != nil {
		t.Fatal("advice for a working proxy")
	}
	for _, c := range checks.AllClasses {
		for _, ph := range []string{checks.PhaseDNS, checks.PhaseConnect, checks.PhaseHandshake, checks.PhaseTargetTLS, checks.PhaseResponse} {
			for _, px := range []*config.Proxy{p, s} {
				a := Explain(checks.Result{Class: c, Phase: ph, StatusCode: 403, Error: "x"}, px)
				if a == nil || a.Title == "" || a.Why == "" || len(a.Fixes) == 0 {
					t.Fatalf("%s/%s: %+v", c, ph, a)
				}
			}
		}
	}
}

func TestExplainSpecifics(t *testing.T) {
	defer redact.Reset()
	p := proxyFor(t, "http://p.example:8080", "https://example.com/", "")
	s := proxyFor(t, "socks5://p.example:1080", "https://example.com/", "")
	tlsProxy := proxyFor(t, "https://p.example:8443", "https://example.com/", "")
	all := func(a *Advice) string { return a.Title + " " + a.Why + " " + strings.Join(a.Fixes, " ") }

	if a := all(Explain(checks.Result{Class: checks.ClassDNS, Phase: checks.PhaseHandshake, Error: "the local DNS lookup of the target failed"}, s)); !strings.Contains(a, "socks5h://") {
		t.Errorf("socks5 target DNS: %s", a)
	}
	if a := all(Explain(checks.Result{Class: checks.ClassAuth, Phase: checks.PhaseHandshake}, p)); !strings.Contains(a, "407") || !strings.Contains(a, "%40") {
		t.Errorf("http auth: %s", a)
	}
	if a := all(Explain(checks.Result{Class: checks.ClassAuth, Phase: checks.PhaseHandshake}, s)); !strings.Contains(a, "SOCKS5") {
		t.Errorf("socks auth: %s", a)
	}
	if a := all(Explain(checks.Result{Class: checks.ClassAuth, Error: "the proxy requires authentication (HTTP 407), but no username is configured"}, p)); !strings.Contains(a, "add the credentials") {
		t.Errorf("no username: %s", a)
	}
	if a := all(Explain(checks.Result{Class: checks.ClassTLS, Phase: checks.PhaseHandshake}, tlsProxy)); !strings.Contains(a, "use http://") {
		t.Errorf("tls to proxy: %s", a)
	}
	if a := all(Explain(checks.Result{Class: checks.ClassStatus, StatusCode: 403}, p)); !strings.Contains(a, "datacenter") {
		t.Errorf("403: %s", a)
	}
	if a := all(Explain(checks.Result{Class: checks.ClassTimeout, Phase: checks.PhaseHandshake}, p)); !strings.Contains(a, "socks5h://p.example:8080") {
		t.Errorf("silent handshake: %s", a)
	}
}

func TestPortHint(t *testing.T) {
	defer redact.Reset()
	if h := PortHint(proxyFor(t, "http://p.example:1080", "https://example.com/", "")); !strings.Contains(h, "SOCKS") {
		t.Errorf("http on 1080: %q", h)
	}
	if h := PortHint(proxyFor(t, "socks5h://p.example:3128", "https://example.com/", "")); !strings.Contains(h, "HTTP") {
		t.Errorf("socks on 3128: %q", h)
	}
	if h := PortHint(proxyFor(t, "http://p.example:8000", "https://example.com/", "")); h != "" {
		t.Errorf("neutral port: %q", h)
	}
}
