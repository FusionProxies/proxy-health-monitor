// Command proxy-monitor monitors the health of HTTP, HTTPS and SOCKS5 proxies
// you own or are authorized to test: uptime, latency, incidents and alerts,
// with a local dashboard, a REST API and Prometheus metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/version"
)

const defaultConfig = "proxy-monitor.yaml"

// Exit codes.
const (
	exitOK      = 0
	exitFailed  = 1 // a check failed or a proxy is down
	exitUsage   = 2 // bad flags or configuration
	exitRuntime = 3 // the program could not run (database, network setup)
)

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

var commands []command

func init() {
	commands = []command{
		{"init", "write an annotated sample configuration", cmdInit},
		{"validate", "check a configuration file without contacting anything", cmdValidate},
		{"check", "check every proxy once and exit (non-zero if any fails)", cmdCheck},
		{"start", "run the monitor: scheduled checks, alerts, dashboard and API", cmdStart},
		{"status", "show the current state of every proxy from the database", cmdStatus},
		{"report", "uptime and latency report for a period (table, JSON, CSV, Markdown)", cmdReport},
		{"target", "run a minimal health endpoint to use as a check target", cmdTarget},
		{"demo", "run the dashboard against local test proxies (demo data)", cmdDemo},
		{"healthcheck", "exit 0 if the monitor's /api/health answers (for container health checks)", cmdHealthcheck},
		{"version", "print the version", func([]string, io.Writer, io.Writer) int { fmt.Println(version.Version); return exitOK }},
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stdout)
		return exitOK
	}
	if args[0] == "-version" || args[0] == "--version" {
		fmt.Fprintln(stdout, version.Version)
		return exitOK
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "proxy-monitor %s: health monitoring for HTTP, HTTPS and SOCKS5 proxies\n\n", version.Version)
	fmt.Fprintln(w, "Usage:\n  proxy-monitor <command> [flags]\n\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nRun 'proxy-monitor <command> -h' for the flags of a command.")
	fmt.Fprintln(w, "Docs: https://github.com/FusionProxies/proxy-health-monitor")
}

// newFlags returns a FlagSet that prints errors to stderr and does not exit.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("proxy-monitor "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		return exitUsage, false
	}
	return 0, true
}

func configFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("PROXY_MONITOR_CONFIG")
	if def == "" {
		def = defaultConfig
	}
	return fs.String("config", def, "configuration file (env PROXY_MONITOR_CONFIG)")
}

func loadConfig(path string, stderr io.Writer) (*config.Config, bool) {
	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "config file %s not found; create one with: proxy-monitor init -config %s\n", path, path)
		} else {
			fmt.Fprintln(stderr, err)
		}
		return nil, false
	}
	return cfg, true
}

// signalContext ends on Ctrl+C or SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("init", stderr)
	path := configFlag(fs)
	force := fs.Bool("force", false, "overwrite an existing file")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	if _, err := os.Stat(*path); err == nil && !*force {
		fmt.Fprintf(stderr, "%s already exists (use -force to overwrite)\n", *path)
		return exitUsage
	}
	if err := os.WriteFile(*path, []byte(config.Sample), 0o600); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	fmt.Fprintf(stdout, "Wrote %s.\n\nNext:\n  1. Replace the example proxies and the target with your own.\n  2. proxy-monitor validate -config %s\n  3. proxy-monitor check -config %s\n  4. proxy-monitor start -config %s, then open http://127.0.0.1:8090\n", *path, *path, *path, *path)
	return exitOK
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("validate", stderr)
	path := configFlag(fs)
	if code, ok := parse(fs, args); !ok {
		return code
	}
	cfg, ok := loadConfig(*path, stderr)
	if !ok {
		return exitUsage
	}
	enabled := len(cfg.EnabledProxies())
	fmt.Fprintf(stdout, "%s is valid: %d proxies (%d enabled), %d targets, ", *path, len(cfg.Proxies), enabled, len(cfg.Targets))
	if cfg.Server.IsEnabled() {
		auth := "no auth, localhost only"
		if cfg.Server.AuthToken != "" {
			auth = "token auth"
		}
		fmt.Fprintf(stdout, "dashboard on %s (%s).\n", cfg.Server.Listen, auth)
	} else {
		fmt.Fprintln(stdout, "dashboard disabled.")
	}
	for _, p := range cfg.Proxies {
		state := ""
		if p.Disabled {
			state = " (disabled)"
		}
		fmt.Fprintf(stdout, "  %-24s %-22s every %-6s -> %s%s\n", p.Name, p.Protocol(), p.Interval, p.TargetRef.DisplayURL(), state)
	}
	return exitOK
}

// splitList parses "a,b, c" into names.
func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func cmdHealthcheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("healthcheck", stderr)
	u := fs.String("url", "http://127.0.0.1:8090/api/health", "health endpoint of a running monitor")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(*u)
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy:", err)
		return exitFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "unhealthy: HTTP", resp.StatusCode)
		return exitFailed
	}
	fmt.Fprintln(stdout, "ok")
	return exitOK
}
