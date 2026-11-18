package checks

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
)

func TestPhaseOf(t *testing.T) {
	for desc, want := range map[string]string{
		"": "",
		"the DNS lookup of the proxy host p.example": PhaseDNS,
		"the TCP connect to the proxy":               PhaseConnect,
		"the TLS handshake with the proxy":           PhaseHandshake,
		"the SOCKS5 handshake":                       PhaseHandshake,
		"the CONNECT handshake":                      PhaseHandshake,
		"the local DNS lookup of the target t.example (socks5:// resolves on this machine)": PhaseHandshake,
		"the TLS handshake with the target":                                                 PhaseTargetTLS,
		"the request":                                                                       PhaseResponse,
		"the wait for the response":                                                         PhaseResponse,
		"the response body":                                                                 PhaseResponse,
	} {
		if got := phaseOf(desc); got != want {
			t.Errorf("phaseOf(%q) = %q, want %q", desc, got, want)
		}
	}
}

func TestFailedResultNamesItsPhase(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	off := false
	p := &config.Proxy{Name: "p", URL: "http://" + addr, Target: "t", Timeout: config.Duration(3 * time.Second)}
	cfg := &config.Config{Server: config.Server{Enabled: &off}, Targets: []*config.Target{{Name: "t", URL: "http://example.com/"}}, Proxies: []*config.Proxy{p}}
	if err := cfg.Validate(""); err != nil {
		t.Fatal(err)
	}
	r := New("test").Check(context.Background(), p)
	if r.OK || r.Class != ClassRefused || r.Phase != PhaseConnect {
		t.Fatalf("got %+v", r)
	}
}
