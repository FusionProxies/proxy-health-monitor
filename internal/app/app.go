// Package app wires storage, checks, scheduling, alerts, metrics and the
// HTTP server into one running monitor. `proxy-monitor start` and
// `proxy-monitor demo` both use it.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/alerts"
	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/metrics"
	"github.com/FusionProxies/proxy-health-monitor/internal/scheduler"
	"github.com/FusionProxies/proxy-health-monitor/internal/server"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
	"github.com/FusionProxies/proxy-health-monitor/internal/version"
)

// Options tune Run.
type Options struct {
	// Checker replaces the real checker (tests).
	Checker scheduler.Checker
	// Listener replaces net.Listen on cfg.Server.Listen (tests).
	Listener net.Listener
	// Ready, if set, receives the dashboard address once it listens.
	Ready chan<- string
}

// Run starts everything and blocks until ctx ends and shutdown completes.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) error {
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer store.Close()

	ua := version.UserAgent()
	checker := opts.Checker
	if checker == nil {
		checker = checks.New(ua)
	}
	notifiers := alerts.Build(cfg.Alerts, log, ua)
	am := alerts.NewManager(cfg.Alerts, cfg.Proxies, notifiers, store, log)
	reg := metrics.New(version.Version)
	sched, err := scheduler.New(cfg, store, checker, am, reg, log)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 3)

	alertCtx, stopAlerts := context.WithCancel(context.Background())
	alertsDone := make(chan struct{})
	go func() {
		am.Run(alertCtx, 10*time.Second)
		close(alertsDone)
	}()

	if cfg.Server.IsEnabled() {
		srv := server.New(server.Options{
			Config: cfg, Store: store, Metrics: reg, Trigger: sched, Channels: am.Channels(),
			Version: version.Version, Log: log,
		})
		ln := opts.Listener
		if ln == nil {
			ln, err = net.Listen("tcp", cfg.Server.Listen)
			if err != nil {
				stopAlerts()
				<-alertsDone
				return fmt.Errorf("dashboard: %w", err)
			}
		}
		if opts.Ready != nil {
			opts.Ready <- ln.Addr().String()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(runCtx, ln); err != nil {
				errc <- fmt.Errorf("dashboard: %w", err)
				cancel()
			}
		}()
	} else if opts.Ready != nil {
		opts.Ready <- ""
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sched.Run(runCtx); err != nil {
			errc <- err
			cancel()
		}
	}()

	<-runCtx.Done()
	wg.Wait()
	// Scheduler is done: no new events. Deliver what is queued, then stop.
	stopAlerts()
	<-alertsDone
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}
