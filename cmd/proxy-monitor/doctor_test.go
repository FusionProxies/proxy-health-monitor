package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/testproxy"
)

func withEnv(t *testing.T, m map[string]string) {
	t.Helper()
	old := lookupEnv
	lookupEnv = func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	t.Cleanup(func() { lookupEnv = old })
}

func noSecrets(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("%q printed:\n%s", s, out)
		}
	}
}

func TestDoctorHTTPProxy(t *testing.T) {
	defer redact.Reset()
	withEnv(t, nil)
	tg, err := testproxy.StartTarget(false)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	px, err := testproxy.StartHTTP("", "doc-user", "doc-pass-123")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()

	// working proxy, flags after the URL
	code, out, errs := runCLI("doctor", "http://doc-user:doc-pass-123@"+px.Addr(), "-target", tg.URL, "-timeout", "5s")
	if code != exitOK || !strings.Contains(out, "Result: the proxy works (HTTP 200") || !strings.Contains(out, "no proxy environment variables") {
		t.Fatalf("good: %d\n%s\n%s", code, out, errs)
	}
	noSecrets(t, out, "doc-pass-123", "doc-user")

	// wrong password
	code, out, _ = runCLI("doctor", "-target", tg.URL, "-timeout", "5s", "http://doc-user:wrong-pass-456@"+px.Addr())
	if code != exitFailed || !strings.Contains(out, "auth_failed") || !strings.Contains(out, "The proxy rejected the login") || !strings.Contains(out, "What to try:") {
		t.Fatalf("bad password: %d\n%s", code, out)
	}
	noSecrets(t, out, "wrong-pass-456", "doc-pass-123")

	// provider export format host:port:user:pass is repaired, and the check still runs
	code, out, _ = runCLI("doctor", "-target", tg.URL, "-timeout", "5s", px.Addr()+":doc-user:doc-pass-123")
	if code != exitOK || !strings.Contains(out, "provider export format") || !strings.Contains(out, "the proxy works") {
		t.Fatalf("export format: %d\n%s", code, out)
	}
	noSecrets(t, out, "doc-pass-123")

	// password from PROXY_PASSWORD, JSON report
	withEnv(t, map[string]string{"PROXY_PASSWORD": "doc-pass-123"})
	code, out, _ = runCLI("doctor", "-json", "-no-env", "-target", tg.URL, "http://doc-user@"+px.Addr())
	var rep struct {
		OK          bool  `json:"ok"`
		Checked     bool  `json:"checked"`
		EnvFindings []any `json:"env_findings"`
		Phases      []struct {
			Key, Status string
		} `json:"phases"`
		Result struct {
			StatusCode int `json:"status_code"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != exitOK || !rep.OK || !rep.Checked || rep.Result.StatusCode != 200 || len(rep.Phases) != 3 || len(rep.EnvFindings) != 0 {
		t.Fatalf("json: %d %v %+v\n%s", code, err, rep, out)
	}
	noSecrets(t, out, "doc-pass-123")
}

func TestDoctorWrongProtocolAndRefused(t *testing.T) {
	defer redact.Reset()
	withEnv(t, nil)
	tg, err := testproxy.StartTarget(false)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	socks, err := testproxy.StartSOCKS5("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()

	// a SOCKS5 port checked as HTTP
	code, out, _ := runCLI("doctor", "-no-env", "-target", tg.URL, "-timeout", "2s", "http://"+socks.Addr())
	if code != exitFailed || !strings.Contains(out, "socks5h://"+socks.Addr()) {
		t.Fatalf("socks as http: %d\n%s", code, out)
	}
	// the same port with the right scheme works
	if code, out, _ = runCLI("doctor", "-no-env", "-target", tg.URL, "socks5h://"+socks.Addr()); code != exitOK {
		t.Fatalf("socks5h: %d\n%s", code, out)
	}

	// nothing listening
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	code, out, _ = runCLI("doctor", "-no-env", "-target", tg.URL, "-timeout", "3s", "http://"+addr)
	if code != exitFailed || !strings.Contains(out, "connection_refused") || !strings.Contains(out, "Nothing accepts connections") {
		t.Fatalf("refused: %d\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "TCP connect to "+addr) {
		t.Fatalf("phase table: %s", out)
	}
}

func TestDoctorSilentProxy(t *testing.T) {
	defer redact.Reset()
	withEnv(t, nil)
	bh, err := testproxy.StartBlackhole("")
	if err != nil {
		t.Fatal(err)
	}
	defer bh.Close()
	code, out, _ := runCLI("doctor", "-no-env", "-target", "https://example.com/", "-timeout", "1s", "http://"+bh.Addr())
	if code != exitFailed || !strings.Contains(out, "timeout") || !strings.Contains(out, "went silent during the handshake") {
		t.Fatalf("blackhole: %d\n%s", code, out)
	}
}

func TestDoctorEnvAndUsage(t *testing.T) {
	defer redact.Reset()
	tg, err := testproxy.StartTarget(false)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	px, err := testproxy.StartHTTP("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer px.Close()

	// proxy taken from the environment, with a NO_PROXY that covers the target
	withEnv(t, map[string]string{"HTTPS_PROXY": "http://" + px.Addr(), "NO_PROXY": "127.0.0.1"})
	code, out, _ := runCLI("doctor", "-target", tg.URL)
	if code != exitOK || !strings.Contains(out, "from HTTPS_PROXY") || !strings.Contains(out, "NO_PROXY matches 127.0.0.1") {
		t.Fatalf("env: %d\n%s", code, out)
	}

	withEnv(t, nil)
	if code, _, errs := runCLI("doctor"); code != exitUsage || !strings.Contains(errs, "no proxy URL") {
		t.Fatalf("no url: %d %s", code, errs)
	}
	if code, out, _ := runCLI("doctor", "socks4://127.0.0.1:1080"); code != exitUsage || !strings.Contains(out, "Not checked") || !strings.Contains(out, "SOCKS4") {
		t.Fatalf("socks4: %d %s", code, out)
	}
	if code, out, _ := runCLI("doctor", "-mode", "sideways", "http://127.0.0.1:3128"); code != exitUsage || !strings.Contains(out, "mode must be") {
		t.Fatalf("bad mode: %d %s", code, out)
	}
	if code, _, errs := runCLI("doctor", "http://a.example:1", "http://b.example:1"); code != exitUsage || !strings.Contains(errs, "one proxy URL") {
		t.Fatalf("two urls: %d %s", code, errs)
	}
	if code, _, _ := runCLI("doctor", "-h"); code != exitOK {
		t.Fatalf("-h: %d", code)
	}
}
