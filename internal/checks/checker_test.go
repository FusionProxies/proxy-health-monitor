package checks

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/testproxy"
)

const (
	testUser = "monitor-user-7731"
	testPass = "s3cr3t-P@ss:word"
)

type fakeResolver map[string]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ip, ok := f[host]; ok {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func newChecker() *Checker {
	c := New("proxy-health-monitor-test")
	c.Resolver = fakeResolver{"localhost": "127.0.0.1"}
	return c
}

// build resolves a one-proxy configuration the same way the real loader does.
func build(t *testing.T, proxyURL, user, pass string, target *testproxy.Target, mut func(*config.Config)) *config.Proxy {
	t.Helper()
	cfg := &config.Config{
		Targets: []*config.Target{{Name: "t", URL: target.URL, ExpectBody: "ok"}},
		Proxies: []*config.Proxy{{Name: "p", URL: proxyURL, Username: user, Password: pass, Target: "t",
			Interval: config.Duration(5 * time.Second), Timeout: config.Duration(3 * time.Second)}},
	}
	if mut != nil {
		mut(cfg)
	}
	if err := cfg.Validate(""); err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].RootCAs = target.Pool
	return cfg.Proxies[0]
}

func startTarget(t *testing.T, tlsOn bool) *testproxy.Target {
	t.Helper()
	tg, err := testproxy.StartTarget(tlsOn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tg.Close)
	return tg
}

func startHTTP(t *testing.T, user, pass string) *testproxy.Server {
	t.Helper()
	s, err := testproxy.StartHTTP("", user, pass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func startSOCKS(t *testing.T, user, pass string) *testproxy.Server {
	t.Helper()
	s, err := testproxy.StartSOCKS5("", user, pass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func expectOK(t *testing.T, r Result) {
	t.Helper()
	if !r.OK {
		t.Fatalf("expected success, got %s: %s", r.Class, r.Error)
	}
	// Durations are not asserted: on Windows the clock ticks every ~0.5ms and
	// a local test proxy can answer a whole check faster than that.
	if r.Total < 0 {
		t.Fatalf("negative total: %+v", r)
	}
	if r.BytesIn == 0 || r.BytesOut == 0 {
		t.Fatalf("bytes not counted: in=%d out=%d", r.BytesIn, r.BytesOut)
	}
}

func expectClass(t *testing.T, r Result, want Class) {
	t.Helper()
	if r.OK || r.Class != want {
		t.Fatalf("expected %s, got ok=%v class=%s error=%q", want, r.OK, r.Class, r.Error)
	}
	if strings.Contains(r.Error, testPass) || strings.Contains(r.Error, testUser) {
		t.Fatalf("credentials leaked into the error: %q", r.Error)
	}
}

func TestHTTPForwardProxy(t *testing.T) {
	tg := startTarget(t, false)
	px := startHTTP(t, "", "")
	p := build(t, "http://"+px.Addr(), "", "", tg, nil)
	if p.Mode != config.ModeForward {
		t.Fatalf("http target should default to forward mode, got %q", p.Mode)
	}
	r := newChecker().Check(context.Background(), p)
	expectOK(t, r)
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	if r.Handshake != 0 || r.TLS != 0 {
		t.Fatalf("forward mode has no handshake or TLS: %+v", r)
	}
}

func TestHTTPForwardProxyAuth(t *testing.T) {
	tg := startTarget(t, false)
	px := startHTTP(t, testUser, testPass)
	c := newChecker()

	expectOK(t, c.Check(context.Background(), build(t, "http://"+px.Addr(), testUser, testPass, tg, nil)))

	r := c.Check(context.Background(), build(t, "http://"+px.Addr(), testUser, "wrong-password", tg, nil))
	expectClass(t, r, ClassAuth)
	if r.StatusCode != 407 {
		t.Fatalf("expected the 407 to be recorded, got %d", r.StatusCode)
	}

	r = c.Check(context.Background(), build(t, "http://"+px.Addr(), "", "", tg, nil))
	expectClass(t, r, ClassAuth)
	if !strings.Contains(r.Error, "no username") {
		t.Fatalf("missing-credentials hint absent: %q", r.Error)
	}
}

func TestHTTPSConnectProxy(t *testing.T) {
	tg := startTarget(t, true)
	px := startHTTP(t, testUser, testPass)
	p := build(t, "http://"+px.Addr(), testUser, testPass, tg, nil)
	if p.Mode != config.ModeConnect {
		t.Fatalf("https target should default to connect mode, got %q", p.Mode)
	}
	r := newChecker().Check(context.Background(), p)
	expectOK(t, r)
}

func TestConnectToPlainHTTPTarget(t *testing.T) {
	tg := startTarget(t, false)
	px := startHTTP(t, "", "")
	p := build(t, "http://"+px.Addr(), "", "", tg, func(c *config.Config) { c.Proxies[0].Mode = config.ModeConnect })
	r := newChecker().Check(context.Background(), p)
	expectOK(t, r)
	if r.TLS != 0 {
		t.Fatalf("CONNECT to an http target has no TLS: %+v", r)
	}
}

func TestConnectAuthFailure(t *testing.T) {
	tg := startTarget(t, true)
	px := startHTTP(t, testUser, testPass)
	r := newChecker().Check(context.Background(), build(t, "http://"+px.Addr(), testUser, "nope-nope", tg, nil))
	expectClass(t, r, ClassAuth)
}

func TestSOCKS5RemoteDNS(t *testing.T) {
	tg := startTarget(t, true)
	px := startSOCKS(t, testUser, testPass)
	// socks5h sends the name; the proxy resolves "localhost" itself.
	target := strings.Replace(tg.URL, "127.0.0.1", "localhost", 1)
	tg2 := &testproxy.Target{URL: target, Pool: tg.Pool}
	r := newChecker().Check(context.Background(), build(t, "socks5h://"+px.Addr(), testUser, testPass, tg2, nil))
	expectOK(t, r)
	if r.DNS != 0 {
		t.Fatalf("socks5h with an IP proxy needs no local DNS, got %s", r.DNS)
	}
}

func TestSOCKS5LocalDNS(t *testing.T) {
	tg := startTarget(t, false)
	px := startSOCKS(t, "", "")
	target := strings.Replace(tg.URL, "127.0.0.1", "localhost", 1)
	tg2 := &testproxy.Target{URL: target}
	r := newChecker().Check(context.Background(), build(t, "socks5://"+px.Addr(), "", "", tg2, nil))
	expectOK(t, r)

	// A target name that does not resolve locally is a DNS failure.
	tg3 := &testproxy.Target{URL: "http://missing.invalid:80/healthz"}
	r = newChecker().Check(context.Background(), build(t, "socks5://"+px.Addr(), "", "", tg3, nil))
	expectClass(t, r, ClassDNS)
}

func TestSOCKS5AuthErrors(t *testing.T) {
	tg := startTarget(t, false)
	px := startSOCKS(t, testUser, testPass)
	c := newChecker()

	r := c.Check(context.Background(), build(t, "socks5h://"+px.Addr(), testUser, "bad-password", tg, nil))
	expectClass(t, r, ClassAuth)
	if !strings.Contains(r.Error, "rejected the username or password") {
		t.Fatalf("unexpected message %q", r.Error)
	}

	r = c.Check(context.Background(), build(t, "socks5h://"+px.Addr(), "", "", tg, nil))
	expectClass(t, r, ClassAuth)
	if !strings.Contains(r.Error, "requires authentication") {
		t.Fatalf("unexpected message %q", r.Error)
	}
}

func TestUpstreamUnreachable(t *testing.T) {
	tg := startTarget(t, true)
	c := newChecker()

	sx := startSOCKS(t, "", "")
	sx.SetFaults(testproxy.Faults{FailRate: 1})
	r := c.Check(context.Background(), build(t, "socks5h://"+sx.Addr(), "", "", tg, nil))
	expectClass(t, r, ClassUpstream)

	hx := startHTTP(t, "", "")
	hx.SetFaults(testproxy.Faults{FailRate: 1})
	r = c.Check(context.Background(), build(t, "http://"+hx.Addr(), "", "", tg, nil))
	expectClass(t, r, ClassUpstream)
}

func TestTimeout(t *testing.T) {
	tg := startTarget(t, false)
	bh, err := testproxy.StartBlackhole("")
	if err != nil {
		t.Fatal(err)
	}
	defer bh.Close()
	for _, scheme := range []string{"http", "socks5h"} {
		p := build(t, scheme+"://"+bh.Addr(), "", "", tg, func(c *config.Config) {
			c.Proxies[0].Timeout = config.Duration(300 * time.Millisecond)
		})
		start := time.Now()
		r := newChecker().Check(context.Background(), p)
		expectClass(t, r, ClassTimeout)
		if el := time.Since(start); el > 3*time.Second {
			t.Fatalf("%s: timeout not enforced, took %s", scheme, el)
		}
	}
}

func TestUnavailableProxy(t *testing.T) {
	tg := startTarget(t, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	p := build(t, "http://"+addr, "", "", tg, func(c *config.Config) { c.Proxies[0].Timeout = config.Duration(4 * time.Second) })
	r := newChecker().Check(context.Background(), p)
	if r.OK || (r.Class != ClassRefused && r.Class != ClassTimeout) {
		t.Fatalf("expected connection_refused (or a timeout on a host that drops), got %s: %s", r.Class, r.Error)
	}

	// A proxy that accepts and immediately closes.
	px := startHTTP(t, "", "")
	px.SetDown(true)
	r = newChecker().Check(context.Background(), build(t, "http://"+px.Addr(), "", "", tg, nil))
	expectClass(t, r, ClassConnect)
}

func TestDNSFailure(t *testing.T) {
	tg := startTarget(t, false)
	p := build(t, "http://proxy.does-not-exist.invalid:3128", testUser, testPass, tg, func(c *config.Config) {
		c.Proxies[0].Interval = config.Duration(30 * time.Second)
	})
	r := newChecker().Check(context.Background(), p)
	expectClass(t, r, ClassDNS)
	if r.Connect != 0 {
		t.Fatalf("no connect phase after a DNS failure: %+v", r)
	}
}

func TestWrongProtocol(t *testing.T) {
	tg := startTarget(t, false)

	// A server that answers anything with an HTTP error, as many HTTP proxies
	// do when they receive SOCKS bytes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the client's bytes first, as a real proxy does: closing a
			// socket with unread data sends a reset that can overtake the
			// answer (Windows does this reliably).
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	}()
	r := newChecker().Check(context.Background(), build(t, "socks5h://"+ln.Addr().String(), "", "", tg, nil))
	expectClass(t, r, ClassProtocol)
	if !strings.Contains(r.Error, "HTTP proxy") {
		t.Fatalf("expected a hint about an HTTP proxy, got %q", r.Error)
	}

	// An HTTP CONNECT client talking to a SOCKS5 proxy gets no answer.
	sx := startSOCKS(t, "", "")
	r = newChecker().Check(context.Background(), build(t, "http://"+sx.Addr(), "", "", startTarget(t, true), nil))
	if r.OK || !strings.Contains(r.Error, "may not speak HTTP") {
		t.Fatalf("expected the wrong-protocol hint, got %s: %q", r.Class, r.Error)
	}
}

func TestUnexpectedStatusAndBody(t *testing.T) {
	tg := startTarget(t, true)
	px := startHTTP(t, "", "")
	c := newChecker()

	tg.SetStatus(503)
	r := c.Check(context.Background(), build(t, "http://"+px.Addr(), "", "", tg, nil))
	expectClass(t, r, ClassStatus)
	if r.StatusCode != 503 {
		t.Fatalf("status not recorded: %d", r.StatusCode)
	}
	tg.SetStatus(200)

	r = c.Check(context.Background(), build(t, "http://"+px.Addr(), "", "", tg, func(c *config.Config) { c.Targets[0].ExpectBody = "something else" }))
	expectClass(t, r, ClassBody)
}

func TestTunnelOnlyCheck(t *testing.T) {
	tg := startTarget(t, true)
	px := startSOCKS(t, "", "")
	p := build(t, "socks5h://"+px.Addr(), "", "", tg, func(c *config.Config) { c.Targets[0].Check = config.CheckTunnel })
	r := newChecker().Check(context.Background(), p)
	expectOK(t, r)
	if r.StatusCode != 0 || r.TTFB != 0 {
		t.Fatalf("tunnel check should stop after TLS: %+v", r)
	}
}

func TestTLSVerificationFailure(t *testing.T) {
	tg := startTarget(t, true)
	px := startHTTP(t, "", "")
	p := build(t, "http://"+px.Addr(), "", "", tg, nil)
	p.TargetRef.RootCAs = nil // system roots do not trust the test certificate
	r := newChecker().Check(context.Background(), p)
	expectClass(t, r, ClassTLS)
}

func TestCanceledCheck(t *testing.T) {
	tg := startTarget(t, false)
	bh, err := testproxy.StartBlackhole("")
	if err != nil {
		t.Fatal(err)
	}
	defer bh.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	r := newChecker().Check(ctx, build(t, "http://"+bh.Addr(), "", "", tg, nil))
	if r.Class != ClassCanceled {
		t.Fatalf("expected canceled, got %s", r.Class)
	}
}

func TestCredentialsAreRedactedInProxyURL(t *testing.T) {
	defer redact.Reset()
	tg := startTarget(t, false)
	p := build(t, "http://"+testUser+":"+strings.ReplaceAll(testPass, "@", "%40")+"@127.0.0.1:9", "", "", tg, nil)
	shown := p.DisplayURL()
	if strings.Contains(shown, testPass) || strings.Contains(shown, testUser) || !strings.Contains(shown, "***") {
		t.Fatalf("display URL leaks credentials: %s", shown)
	}
}

func TestPhaseTimings(t *testing.T) {
	tg := startTarget(t, true)
	const delay = 40 * time.Millisecond
	for _, kind := range []string{"http", "socks5h"} {
		var px *testproxy.Server
		if kind == "http" {
			px = startHTTP(t, testUser, testPass)
		} else {
			px = startSOCKS(t, testUser, testPass)
		}
		px.SetFaults(testproxy.Faults{Latency: delay})
		r := newChecker().Check(context.Background(), build(t, kind+"://"+px.Addr(), testUser, testPass, tg, nil))
		expectOK(t, r)
		if r.Handshake < delay-5*time.Millisecond {
			t.Fatalf("%s: the proxy delay belongs to the handshake phase, got %s", kind, r.Handshake)
		}
		if r.Total < r.Handshake+r.TLS {
			t.Fatalf("%s: total %s shorter than its phases %+v", kind, r.Total, r)
		}
		if r.ConnectionLatency() < r.Handshake {
			t.Fatalf("%s: connection latency must include the handshake", kind)
		}
	}
}
