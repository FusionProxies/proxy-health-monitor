// Package server serves the dashboard, the read-only REST API, one
// authenticated management endpoint and the Prometheus metrics.
package server

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
	"github.com/FusionProxies/proxy-health-monitor/internal/metrics"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/scheduler"
	"github.com/FusionProxies/proxy-health-monitor/internal/stats"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
	"github.com/FusionProxies/proxy-health-monitor/web"
)

// Triggerer starts an immediate check. *scheduler.Scheduler satisfies it.
type Triggerer interface {
	Trigger(name string) error
}

// Options configure a Server.
type Options struct {
	Config    *config.Config
	Store     *storage.Store
	Metrics   *metrics.Registry
	Trigger   Triggerer // nil disables "check now"
	Channels  []string  // alert channel names, for the settings page
	Version   string
	Log       *slog.Logger
	StartedAt time.Time
}

// Server is the HTTP side of the monitor.
type Server struct {
	Options
	cfg      *config.Config
	throttle *throttle
	mux      *http.ServeMux

	cacheMu sync.Mutex
	cache   map[string]cached
}

type cached struct {
	at  time.Time
	sum stats.Summary
	sp  []float64
}

// New builds the server.
func New(o Options) *Server {
	if o.StartedAt.IsZero() {
		o.StartedAt = time.Now()
	}
	s := &Server{Options: o, cfg: o.Config, throttle: newThrottle(), mux: http.NewServeMux(), cache: map[string]cached{}}
	s.routes()
	return s
}

// Handler returns the guarded handler.
func (s *Server) Handler() http.Handler { return s.guard(s.mux) }

// ListenAndServe serves until ctx ends, then shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.Log.Info("dashboard and API listening", "url", "http://"+ln.Addr().String(), "auth", s.cfg.Server.AuthToken != "")
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(sctx)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/health", s.handleHealth)
	m.HandleFunc("GET /api/proxies", s.handleProxies)
	m.HandleFunc("GET /api/proxies/{name}", s.handleProxy)
	m.HandleFunc("GET /api/proxies/{name}/checks", s.handleChecks)
	m.HandleFunc("GET /api/proxies/{name}/series", s.handleSeries)
	m.HandleFunc("POST /api/proxies/{name}/check", s.handleCheckNow)
	m.HandleFunc("GET /api/metrics", s.handleSummary)
	m.HandleFunc("GET /api/incidents", s.handleIncidents)
	m.HandleFunc("GET /api/alerts", s.handleAlerts)
	m.HandleFunc("GET /api/settings", s.handleSettings)
	m.HandleFunc("GET /metrics", s.handlePrometheus)

	static, _ := fs.Sub(web.Static, "static")
	files := http.FileServer(http.FS(static))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, static, "index.html")
	})
	m.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})))
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such endpoint"})
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"status": "ok"}
	if s.authorized(r) {
		out["version"] = s.Version
		out["uptime_seconds"] = int(time.Since(s.StartedAt).Seconds())
		out["proxies"] = len(s.cfg.EnabledProxies())
		out["demo"] = s.cfg.Demo
	}
	writeJSON(w, http.StatusOK, out)
}

// ProxyView is one proxy in the API.
type ProxyView struct {
	Name                string            `json:"name"`
	Protocol            string            `json:"protocol"`
	Scheme              string            `json:"scheme"`
	Mode                string            `json:"mode,omitempty"`
	URL                 string            `json:"url"`
	Target              string            `json:"target"`
	TargetURL           string            `json:"target_url"`
	Check               string            `json:"check"`
	Labels              map[string]string `json:"labels,omitempty"`
	Interval            string            `json:"interval"`
	Timeout             string            `json:"timeout"`
	State               string            `json:"state"`
	LastCheck           *time.Time        `json:"last_check"`
	LastOK              *time.Time        `json:"last_ok"`
	LastFailure         *time.Time        `json:"last_failure"`
	LastError           string            `json:"last_error,omitempty"`
	LastErrorClass      string            `json:"last_error_class,omitempty"`
	ConsecutiveFailures int               `json:"consecutive_failures"`
	LastTotalMS         float64           `json:"last_total_ms"`
	Day                 stats.Summary     `json:"last_24h"`
	Spark               []float64         `json:"spark_24h"` // hourly uptime, -1 = no checks
	Disabled            bool              `json:"disabled,omitempty"`
}

func tptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Server) view(p *config.Proxy, st storage.ProxyState, ok bool) ProxyView {
	v := ProxyView{
		Name: p.Name, Protocol: p.Protocol(), Scheme: p.Scheme, Mode: p.Mode, URL: p.DisplayURL(),
		Target: p.Target, Labels: p.Labels, Interval: p.Interval.String(), Timeout: p.Timeout.String(),
		State: string(health.Unknown), Disabled: p.Disabled,
	}
	if p.TargetRef != nil {
		v.TargetURL = p.TargetRef.DisplayURL()
		v.Check = p.TargetRef.Check
	}
	if p.Disabled {
		v.State = "disabled"
	}
	if ok {
		if !p.Disabled {
			v.State = st.State
		}
		v.LastCheck, v.LastOK, v.LastFailure = tptr(st.LastCheck), tptr(st.LastOK), tptr(st.LastFailure)
		v.LastError, v.LastErrorClass = redact.String(st.LastError), st.LastErrorClass
		v.ConsecutiveFailures, v.LastTotalMS = st.ConsecutiveFailures, st.LastTotalMS
	}
	v.Day, v.Spark = s.daySummary(p.Name)
	return v
}

// daySummary returns the 24h summary and hourly sparkline, cached for 5s so
// a dashboard refresh loop costs little.
func (s *Server) daySummary(name string) (stats.Summary, []float64) {
	s.cacheMu.Lock()
	c, ok := s.cache[name]
	s.cacheMu.Unlock()
	if ok && time.Since(c.at) < 5*time.Second {
		return c.sum, c.sp
	}
	now := time.Now()
	from := now.Add(-24 * time.Hour)
	samples, err := s.Store.Samples(name, from, now.Add(time.Second))
	if err != nil {
		s.Log.Error("reading samples", "proxy", name, "err", err)
		return stats.Summary{}, nil
	}
	sum := stats.Summarize(samples)
	buckets := stats.Series(samples, now.Add(-23*time.Hour).Truncate(time.Hour), now.Add(time.Second), time.Hour)
	sp := make([]float64, len(buckets))
	for i, b := range buckets {
		sp[i] = -1
		if b.Checks > 0 {
			sp[i] = b.Uptime
		}
	}
	s.cacheMu.Lock()
	s.cache[name] = cached{at: time.Now(), sum: sum, sp: sp}
	s.cacheMu.Unlock()
	return sum, sp
}

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	states, err := s.Store.States()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	out := make([]ProxyView, 0, len(s.cfg.Proxies))
	for _, p := range s.cfg.Proxies {
		st, ok := states[p.Name]
		out = append(out, s.view(p, st, ok))
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": out, "demo": s.cfg.Demo})
}

func (s *Server) proxyOr404(w http.ResponseWriter, r *http.Request) *config.Proxy {
	p := s.cfg.ProxyByName(r.PathValue("name"))
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown proxy"})
	}
	return p
}

var windows = map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

func windowParam(r *http.Request, def string) (time.Duration, string) {
	w := r.URL.Query().Get("window")
	if d, ok := windows[w]; ok {
		return d, w
	}
	return windows[def], def
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	p := s.proxyOr404(w, r)
	if p == nil {
		return
	}
	states, err := s.Store.States()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	st, ok := states[p.Name]
	now := time.Now()
	sums := map[string]stats.Summary{}
	for _, k := range []string{"1h", "24h", "7d", "30d"} {
		samples, err := s.Store.Samples(p.Name, now.Add(-windows[k]), now.Add(time.Second))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}
		sums[k] = stats.Summarize(samples)
	}
	recent, _ := s.Store.Checks(p.Name, now.Add(-24*time.Hour), now.Add(time.Second), false, 200)
	phases := phaseMedians(recent)
	errorsList, _ := s.Store.Checks(p.Name, now.Add(-7*24*time.Hour), now.Add(time.Second), true, 25)
	incidents, _ := s.Store.Incidents(storage.IncidentFilter{Proxy: p.Name, Limit: 20})
	if len(recent) > 30 {
		recent = recent[:30]
	}
	redactRows(recent)
	redactRows(errorsList)
	redactIncidents(incidents)
	writeJSON(w, http.StatusOK, map[string]any{
		"proxy":         s.view(p, st, ok),
		"summaries":     sums,
		"phases_24h":    phases,
		"recent_checks": nz(recent),
		"recent_errors": nz(errorsList),
		"incidents":     nzi(incidents),
		"thresholds": map[string]any{
			"failure_threshold": p.Effective.FailureThreshold, "recovery_threshold": p.Effective.RecoveryThreshold,
			"latency": p.Effective.Latency.String(), "latency_ms": p.Effective.Latency.D().Milliseconds(),
			"availability": p.Effective.Availability, "availability_window": p.Effective.AvailabilityWindow.String(),
		},
		"management": s.managementEnabled(),
		"demo":       s.cfg.Demo,
	})
}

func nz(v []storage.CheckRow) []storage.CheckRow {
	if v == nil {
		return []storage.CheckRow{}
	}
	return v
}

func nzi(v []storage.Incident) []storage.Incident {
	if v == nil {
		return []storage.Incident{}
	}
	return v
}

func redactRows(rows []storage.CheckRow) {
	for i := range rows {
		rows[i].Error = redact.String(rows[i].Error)
	}
}

func redactIncidents(in []storage.Incident) {
	for i := range in {
		in[i].Reason = redact.String(in[i].Reason)
		in[i].LastError = redact.String(in[i].LastError)
	}
}

// phaseMedians returns the median of each phase over successful checks.
func phaseMedians(rows []storage.CheckRow) map[string]float64 {
	cols := map[string][]float64{}
	for _, c := range rows {
		if !c.OK {
			continue
		}
		cols["dns"] = append(cols["dns"], c.DNSMS)
		cols["connect"] = append(cols["connect"], c.ConnectMS)
		cols["proxy_handshake"] = append(cols["proxy_handshake"], c.HandshakeMS)
		cols["tls"] = append(cols["tls"], c.TLSMS)
		cols["ttfb"] = append(cols["ttfb"], c.TTFBMS)
		cols["total"] = append(cols["total"], c.TotalMS)
	}
	out := map[string]float64{}
	for k, v := range cols {
		sort.Float64s(v)
		out[k] = stats.Percentile(v, 50)
	}
	return out
}

func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request) {
	p := s.proxyOr404(w, r)
	if p == nil {
		return
	}
	d, _ := windowParam(r, "24h")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	now := time.Now()
	rows, err := s.Store.Checks(p.Name, now.Add(-d), now.Add(time.Second), r.URL.Query().Get("failed") == "1", limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	redactRows(rows)
	writeJSON(w, http.StatusOK, map[string]any{"proxy": p.Name, "checks": nz(rows)})
}

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	p := s.proxyOr404(w, r)
	if p == nil {
		return
	}
	d, name := windowParam(r, "24h")
	now := time.Now()
	from := now.Add(-d)
	samples, err := s.Store.Samples(p.Name, from, now.Add(time.Second))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	width := stats.BucketWidth(d)
	writeJSON(w, http.StatusOK, map[string]any{
		"proxy": p.Name, "window": name, "bucket_seconds": int(width.Seconds()),
		"from": from.UTC(), "to": now.UTC(),
		"buckets": stats.Series(samples, from, now.Add(time.Second), width),
		"summary": stats.Summarize(samples),
	})
}

func (s *Server) managementEnabled() bool {
	return s.Trigger != nil && s.cfg.Server.AuthToken != ""
}

func (s *Server) handleCheckNow(w http.ResponseWriter, r *http.Request) {
	if !s.managementEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the management API is disabled: set server.auth_token to enable it"})
		return
	}
	if r.Header.Get("X-Proxy-Monitor-Request") != "1" || !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused (send X-Proxy-Monitor-Request: 1 from the same origin)"})
		return
	}
	p := s.proxyOr404(w, r)
	if p == nil {
		return
	}
	if err := s.Trigger.Trigger(p.Name); err != nil {
		code := http.StatusConflict
		if errors.Is(err, scheduler.ErrUnknownProxy) {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	s.Log.Info("manual check requested", "proxy", p.Name, "from", clientIP(r))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	states, err := s.Store.States()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	counts := map[string]int{"healthy": 0, "degraded": 0, "down": 0, "unknown": 0, "disabled": 0}
	var checksN, okN int
	now := time.Now()
	for _, p := range s.cfg.Proxies {
		if p.Disabled {
			counts["disabled"]++
			continue
		}
		st, ok := states[p.Name]
		if !ok || st.State == "" {
			counts["unknown"]++
		} else {
			counts[st.State]++
		}
		c, o, err := s.Store.Counts(p.Name, now.Add(-24*time.Hour), now.Add(time.Second))
		if err == nil {
			checksN += c
			okN += o
		}
	}
	open, _ := s.Store.Incidents(storage.IncidentFilter{OnlyOpen: true})
	uptime := 0.0
	if checksN > 0 {
		uptime = 100 * float64(okN) / float64(checksN)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"proxies":        len(s.cfg.Proxies),
		"states":         counts,
		"checks_24h":     checksN,
		"successes_24h":  okN,
		"uptime_24h":     uptime,
		"open_incidents": len(open),
		"demo":           s.cfg.Demo,
		"version":        s.Version,
	})
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.IncidentFilter{Proxy: q.Get("proxy"), OnlyOpen: q.Get("status") == "open"}
	if d, ok := windows[q.Get("window")]; ok {
		f.Since = time.Now().Add(-d)
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	in, err := s.Store.Incidents(f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	redactIncidents(in)
	writeJSON(w, http.StatusOK, map[string]any{"incidents": nzi(in), "demo": s.cfg.Demo})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	a, err := s.Store.Alerts(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	if a == nil {
		a = []storage.AlertRecord{}
	}
	for i := range a {
		a[i].Message = redact.String(a[i].Message)
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": a})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	c := s.cfg
	type targetView struct {
		Name          string `json:"name"`
		URL           string `json:"url"`
		Check         string `json:"check"`
		Method        string `json:"method"`
		ExpectStatus  []int  `json:"expect_status"`
		ExpectBody    bool   `json:"expect_body"`
		MaxConcurrent int    `json:"max_concurrent"`
		MinSpacing    string `json:"min_spacing"`
		Proxies       int    `json:"proxies"`
	}
	targets := make([]targetView, 0, len(c.Targets))
	for _, t := range c.Targets {
		n := 0
		for _, p := range c.Proxies {
			if p.Target == t.Name {
				n++
			}
		}
		targets = append(targets, targetView{t.Name, t.DisplayURL(), t.Check, t.Method, t.ExpectStatus, t.ExpectBody != "", t.MaxConcurrent, t.MinSpacing.String(), n})
	}
	proxies := make([]map[string]any, 0, len(c.Proxies))
	for _, p := range c.Proxies {
		proxies = append(proxies, map[string]any{"name": p.Name, "interval": p.Interval.String(), "timeout": p.Timeout.String(), "target": p.Target, "disabled": p.Disabled})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version,
		"demo":    c.Demo,
		"monitor": map[string]any{
			"interval": c.Monitor.Interval.String(), "timeout": c.Monitor.Timeout.String(), "jitter": c.Monitor.Jitter,
			"concurrency": c.Monitor.Concurrency, "min_interval": c.Monitor.MinInterval.String(),
		},
		"thresholds": map[string]any{
			"failure_threshold": c.Thresholds.FailureThreshold, "recovery_threshold": c.Thresholds.RecoveryThreshold,
			"latency": c.Thresholds.Latency.String(), "latency_samples": c.Thresholds.LatencySamples,
			"availability": c.Thresholds.Availability, "availability_window": c.Thresholds.AvailabilityWindow.String(),
			"availability_min_checks": c.Thresholds.AvailabilityMinChecks,
		},
		"storage": map[string]any{
			"file": filepath.Base(c.Storage.Path), "retention": c.Storage.Retention.String(), "incident_retention": c.Storage.IncidentRetention.String(),
		},
		"server": map[string]any{
			"listen": c.Server.Listen, "auth": c.Server.AuthToken != "", "allowed_hosts": c.Server.AllowedHosts,
			"management": s.managementEnabled(),
		},
		"alerts": map[string]any{
			"cooldown": c.Alerts.Cooldown.String(), "max_per_minute": c.Alerts.MaxPerMinute,
			"repeat_interval": c.Alerts.RepeatInterval.String(), "channels": s.Channels,
		},
		"targets":       targets,
		"proxies":       proxies,
		"error_classes": classTexts(),
		"config_file":   filepath.Base(c.Path),
	})
}

func classTexts() map[string]string {
	out := map[string]string{}
	for _, c := range checks.AllClasses {
		out[string(c)] = checks.ErrorClassText(c)
	}
	return out
}

func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.Metrics == nil {
		return
	}
	_ = s.Metrics.Write(w)
}
