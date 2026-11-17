package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/app"
	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/logging"
	"github.com/FusionProxies/proxy-health-monitor/internal/scheduler"
	"github.com/FusionProxies/proxy-health-monitor/internal/version"
)

func cmdStart(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("start", stderr)
	path := configFlag(fs)
	level := fs.String("log-level", envOr("PROXY_MONITOR_LOG_LEVEL", "info"), "debug, info, warn or error")
	format := fs.String("log-format", envOr("PROXY_MONITOR_LOG_FORMAT", "text"), "text or json")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	log, err := logging.New(stderr, *level, *format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	cfg, ok := loadConfig(*path, stderr)
	if !ok {
		return exitUsage
	}
	ctx, stop := signalContext()
	defer stop()
	log.Info("proxy-monitor starting", "version", version.Version, "config", *path, "database", cfg.Storage.Path)
	if err := app.Run(ctx, cfg, log, app.Options{}); err != nil {
		log.Error("stopped with an error", "err", err)
		return exitRuntime
	}
	return exitOK
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("check", stderr)
	path := configFlag(fs)
	only := fs.String("proxy", "", "comma-separated proxy names to check (default: all enabled)")
	asJSON := fs.Bool("json", false, "print results as JSON")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	cfg, ok := loadConfig(*path, stderr)
	if !ok {
		return exitUsage
	}
	var list []*config.Proxy
	if *only != "" {
		for _, n := range splitList(*only) {
			p := cfg.ProxyByName(n)
			if p == nil {
				fmt.Fprintf(stderr, "no proxy named %q in %s\n", n, *path)
				return exitUsage
			}
			list = append(list, p)
		}
	} else {
		list = cfg.EnabledProxies()
	}
	ctx, stop := signalContext()
	defer stop()
	results := runOnce(ctx, cfg, list, checks.New(version.UserAgent()))
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "interrupted")
		return exitFailed
	}
	failed := 0
	for _, r := range results {
		if !r.OK {
			failed++
		}
	}
	if *asJSON {
		type row struct {
			checks.Result
			Protocol string `json:"protocol"`
			URL      string `json:"url"`
		}
		out := make([]row, len(results))
		for i, r := range results {
			p := cfg.ProxyByName(r.Proxy)
			out[i] = row{Result: r, Protocol: p.Protocol(), URL: p.DisplayURL()}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"results": out, "total": len(results), "failed": failed})
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PROXY\tPROTOCOL\tRESULT\tTOTAL\tCONNECT\tTTFB\tDETAIL")
		for _, r := range results {
			p := cfg.ProxyByName(r.Proxy)
			res, detail := "ok", ""
			if !r.OK {
				res, detail = "FAIL", string(r.Class)+": "+r.Error
			} else if r.StatusCode != 0 {
				detail = fmt.Sprintf("HTTP %d", r.StatusCode)
			} else {
				detail = "tunnel established"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Proxy, p.Protocol(), res, msOrDash(r.Total, r.OK), msOrDash(r.ConnectionLatency(), r.OK), msOrDash(r.TTFB, r.OK && r.TTFB > 0), detail)
		}
		_ = tw.Flush()
		fmt.Fprintf(stdout, "\n%d of %d proxies passed\n", len(results)-failed, len(results))
	}
	if failed > 0 {
		return exitFailed
	}
	return exitOK
}

// runOnce checks the proxies in parallel under the configured limits and
// returns results in configuration order.
func runOnce(ctx context.Context, cfg *config.Config, list []*config.Proxy, c *checks.Checker) []checks.Result {
	limits := scheduler.NewLimits(cfg.Monitor.Concurrency, cfg.Targets)
	results := make([]checks.Result, len(list))
	var wg sync.WaitGroup
	for i, p := range list {
		wg.Add(1)
		go func(i int, p *config.Proxy) {
			defer wg.Done()
			release, err := limits.Acquire(ctx, p.TargetRef)
			if err != nil {
				results[i] = checks.Result{Proxy: p.Name, Time: time.Now(), Class: checks.ClassCanceled, Error: "interrupted"}
				return
			}
			defer release()
			results[i] = c.Check(ctx, p)
		}(i, p)
	}
	wg.Wait()
	order := map[string]int{}
	for i, p := range list {
		order[p.Name] = i
	}
	sort.SliceStable(results, func(a, b int) bool { return order[results[a].Proxy] < order[results[b].Proxy] })
	return results
}

func msOrDash(d time.Duration, show bool) string {
	if !show {
		return "-"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
