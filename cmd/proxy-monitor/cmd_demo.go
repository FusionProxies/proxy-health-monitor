package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/app"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/logging"
	"github.com/FusionProxies/proxy-health-monitor/internal/testproxy"
)

// cmdTarget runs a minimal health endpoint. Deploy it on a server you control
// and point your targets at it, so checks never touch third-party sites.
func cmdTarget(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("target", stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on (use 0.0.0.0:8080 to accept checks from proxies)")
	path := fs.String("path", "/healthz", "URL path that answers \"ok\"")
	cert := fs.String("tls-cert", "", "TLS certificate file (serve HTTPS)")
	key := fs.String("tls-key", "", "TLS key file")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if (*cert == "") != (*key == "") {
		fmt.Fprintln(stderr, "-tls-cert and -tls-key go together")
		return exitUsage
	}
	mux := http.NewServeMux()
	mux.HandleFunc(*path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	ctx, stop := signalContext()
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	fmt.Fprintf(stdout, "health target listening on %s://%s%s (answers \"ok\"; logs no requests)\n", scheme, *listen, *path)
	var err error
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	return exitOK
}

// cmdDemo starts local test proxies with different fault profiles and runs
// the real monitor against them, so the dashboard can be tried (and
// screenshotted) without any real proxy. Everything stays on 127.0.0.1.
func cmdDemo(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("demo", stderr)
	listen := fs.String("listen", "127.0.0.1:8090", "dashboard address")
	db := fs.String("db", filepath.Join(os.TempDir(), "proxy-monitor-demo.db"), "database file for the demo data")
	interval := fs.Duration("interval", 5*time.Second, "check interval for the demo proxies")
	level := fs.String("log-level", "warn", "debug, info, warn or error")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	log, err := logging.New(stderr, *level, "text")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}

	var closers []func()
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()
	httpT, err := testproxy.StartTarget(false)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	closers = append(closers, httpT.Close)
	tlsT, err := testproxy.StartTarget(true)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	closers = append(closers, tlsT.Close)

	type profile struct {
		name, kind, scheme, user, pass, clientPass, target string
		faults                                             testproxy.Faults
		labels                                             map[string]string
	}
	profiles := []profile{
		{name: "office-squid", kind: "http", scheme: "http", target: "health-http",
			faults: testproxy.Faults{Latency: 25 * time.Millisecond, Jitter: 40 * time.Millisecond},
			labels: map[string]string{"site": "office"}},
		{name: "eu-gateway", kind: "http", scheme: "http", user: "demo-eu", pass: "demo-secret-eu", target: "health-https",
			faults: testproxy.Faults{Latency: 110 * time.Millisecond, Jitter: 90 * time.Millisecond, FailRate: 0.02},
			labels: map[string]string{"region": "eu"}},
		{name: "us-socks5", kind: "socks5", scheme: "socks5h", user: "demo-us", pass: "demo-secret-us", target: "health-https",
			faults: testproxy.Faults{Latency: 170 * time.Millisecond, Jitter: 120 * time.Millisecond, FailRate: 0.01},
			labels: map[string]string{"region": "us"}},
		{name: "apac-socks5", kind: "socks5", scheme: "socks5h", user: "demo-apac", pass: "demo-secret-apac", target: "health-https",
			faults: testproxy.Faults{Latency: 1300 * time.Millisecond, Jitter: 1100 * time.Millisecond, FailRate: 0.03},
			labels: map[string]string{"region": "apac"}},
		{name: "flaky-connect", kind: "http", scheme: "http", user: "demo-flaky", pass: "demo-secret-flaky", target: "health-https",
			faults: testproxy.Faults{Latency: 220 * time.Millisecond, Jitter: 200 * time.Millisecond, FailRate: 0.22},
			labels: map[string]string{"region": "eu", "tier": "budget"}},
		{name: "backup-http", kind: "http", scheme: "http", target: "health-http",
			faults: testproxy.Faults{Latency: 60 * time.Millisecond, Jitter: 50 * time.Millisecond},
			labels: map[string]string{"site": "dc2"}},
		{name: "rotated-credentials", kind: "socks5", scheme: "socks5h", user: "demo-old", pass: "demo-secret-new", clientPass: "demo-secret-old", target: "health-https",
			faults: testproxy.Faults{Latency: 90 * time.Millisecond},
			labels: map[string]string{"region": "us"}},
	}

	cfg := &config.Config{Demo: true}
	cfg.Storage.Path = *db
	cfg.Storage.Retention = config.Duration(48 * time.Hour)
	cfg.Storage.IncidentRetention = config.Duration(7 * 24 * time.Hour)
	cfg.Server.Listen = *listen
	cfg.Monitor.Interval = config.Duration(*interval)
	cfg.Monitor.Timeout = config.Duration(min(*interval-500*time.Millisecond, 4*time.Second))
	cfg.Monitor.Concurrency = 8
	cfg.Thresholds = config.Thresholds{FailureThreshold: 3, RecoveryThreshold: 2, Latency: config.Duration(1500 * time.Millisecond), LatencySamples: 5,
		Availability: 90, AvailabilityWindow: config.Duration(15 * time.Minute), AvailabilityMinChecks: 12}
	cfg.Alerts.Cooldown = config.Duration(3 * time.Minute)
	cfg.Targets = []*config.Target{
		{Name: "health-http", URL: httpT.URL, ExpectBody: "ok", MaxConcurrent: 8, MinSpacing: config.Duration(50 * time.Millisecond)},
		{Name: "health-https", URL: tlsT.URL, ExpectBody: "ok", MaxConcurrent: 8, MinSpacing: config.Duration(50 * time.Millisecond)},
	}

	servers := map[string]*testproxy.Server{}
	for _, p := range profiles {
		var s *testproxy.Server
		if p.kind == "socks5" {
			s, err = testproxy.StartSOCKS5("127.0.0.1:0", p.user, p.pass)
		} else {
			s, err = testproxy.StartHTTP("127.0.0.1:0", p.user, p.pass)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		closers = append(closers, s.Close)
		s.SetFaults(p.faults)
		servers[p.name] = s
		pass := p.pass
		if p.clientPass != "" {
			pass = p.clientPass
		}
		cp := &config.Proxy{Name: p.name, URL: fmt.Sprintf("%s://%s", p.scheme, s.Addr()), Username: p.user, Password: pass, Target: p.target, Labels: p.labels}
		cfg.Proxies = append(cfg.Proxies, cp)
	}
	if err := cfg.Validate(""); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	// The HTTPS target uses a fresh self-signed certificate; trust only it.
	for _, t := range cfg.Targets {
		if t.Name == "health-https" {
			t.RootCAs = tlsT.Pool
		}
	}

	ctx, stop := signalContext()
	defer stop()

	// Scripted outage: backup-http goes down for 2 minutes in every 9.
	go func() {
		start := time.Now()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				phase := time.Since(start) % (9 * time.Minute)
				servers["backup-http"].SetDown(phase >= 4*time.Minute && phase < 6*time.Minute)
			}
		}
	}()

	ready := make(chan string, 1)
	go func() {
		addr := <-ready
		fmt.Fprintf(stdout, "Demo running with %d local test proxies (all on 127.0.0.1). Demo data goes to %s\n", len(profiles), *db)
		fmt.Fprintf(stdout, "Dashboard: http://%s   (Ctrl+C to stop)\n", addr)
		fmt.Fprintln(stdout, "Profiles: healthy forward proxy, CONNECT with auth, SOCKS5 with auth, a slow SOCKS5, a flaky CONNECT (22% failures), a proxy with a scripted outage (2 min in every 9) and one with a rotated password.")
	}()
	if err := app.Run(ctx, cfg, log, app.Options{Ready: ready}); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	return exitOK
}
