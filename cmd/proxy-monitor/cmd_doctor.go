package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/doctor"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/version"
)

const doctorDefaultTarget = "https://example.com/"

// lookupEnv is os.LookupEnv; tests replace it.
var lookupEnv = os.LookupEnv

// cmdDoctor checks one proxy URL without a configuration file and explains
// what is wrong in plain language.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("doctor", stderr)
	target := fs.String("target", doctorDefaultTarget, "URL to request through the proxy (use one you are allowed to test)")
	mode := fs.String("mode", "", "HTTP proxies only: connect (tunnel) or forward; default connect for https:// targets")
	timeout := fs.Duration("timeout", 15*time.Second, "time limit for the whole check (max 2m)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	noEnv := fs.Bool("no-env", false, "skip the checks of HTTP_PROXY, HTTPS_PROXY, ALL_PROXY and NO_PROXY")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: proxy-monitor doctor [flags] [proxy-url]\n\n"+
			"Checks one proxy and explains what is wrong. Without proxy-url it uses HTTPS_PROXY, HTTP_PROXY or ALL_PROXY.\n"+
			"Put the password in PROXY_PASSWORD to keep it out of your shell history.\n\nFlags:")
		fs.PrintDefaults()
	}
	// Accept flags before and after the proxy URL.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return exitOK
			}
			return exitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(positional) > 1 {
		fmt.Fprintln(stderr, "give one proxy URL")
		return exitUsage
	}

	raw, from := "", "argument"
	if len(positional) == 1 {
		raw = positional[0]
	} else {
		for _, n := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			if v, ok := lookupEnv(n); ok && v != "" {
				raw, from = v, n
				break
			}
		}
		if raw == "" {
			fmt.Fprintln(stderr, "no proxy URL: pass one, e.g. proxy-monitor doctor http://user:pass@proxy.example.com:8080")
			return exitUsage
		}
	}

	rep := report{From: from, Target: *target}
	use, urlFindings, ok := doctor.LintURL(raw)
	rep.URLFindings = urlFindings
	if !ok {
		return rep.print(stdout, stderr, *asJSON, exitUsage)
	}

	interval := time.Minute
	if 2**timeout > interval {
		interval = 2 * *timeout
	}
	p := &config.Proxy{Name: "proxy", URL: use, Mode: *mode, Target: "doctor",
		Timeout: config.Duration(*timeout), Interval: config.Duration(interval)}
	if pw, ok := lookupEnv("PROXY_PASSWORD"); ok && pw != "" {
		p.Password = pw
	}
	disabled := false
	cfg := &config.Config{
		Server:  config.Server{Enabled: &disabled},
		Targets: []*config.Target{{Name: "doctor", URL: *target}},
		Proxies: []*config.Proxy{p},
	}
	if err := cfg.Validate(""); err != nil {
		rep.URLFindings = append(rep.URLFindings, doctor.Finding{Level: doctor.Fail, Message: redact.String(strings.TrimPrefix(err.Error(), "invalid configuration: "))})
		return rep.print(stdout, stderr, *asJSON, exitUsage)
	}
	rep.Proxy, rep.Protocol, rep.Target = p.DisplayURL(), p.Protocol(), p.TargetRef.DisplayURL()
	if hint := doctor.PortHint(p); hint != "" {
		rep.URLFindings = append(rep.URLFindings, doctor.Finding{Level: doctor.Info, Message: hint})
	}
	if !*noEnv {
		rep.EnvFindings = doctor.LintEnv(lookupEnv, p.TargetRef.Parsed.Hostname(), p.TargetRef.Parsed.Scheme)
	}

	ctx, stop := signalContext()
	defer stop()
	res := checks.New(version.UserAgent()).Check(ctx, p)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "interrupted")
		return exitFailed
	}
	rep.Ran, rep.OK = true, res.OK
	rep.Result = &res
	rep.Phases = doctor.Phases(res, p)
	rep.Advice = doctor.Explain(res, p)
	if res.OK {
		return rep.print(stdout, stderr, *asJSON, exitOK)
	}
	return rep.print(stdout, stderr, *asJSON, exitFailed)
}

type report struct {
	Proxy       string           `json:"proxy,omitempty"`
	From        string           `json:"proxy_from"`
	Protocol    string           `json:"protocol,omitempty"`
	Target      string           `json:"target"`
	URLFindings []doctor.Finding `json:"url_findings"`
	EnvFindings []doctor.Finding `json:"env_findings"`
	Ran         bool             `json:"checked"`
	OK          bool             `json:"ok"`
	Phases      []doctor.Phase   `json:"phases,omitempty"`
	Result      *checks.Result   `json:"result,omitempty"`
	Advice      *doctor.Advice   `json:"advice,omitempty"`
}

func (r report) print(stdout, stderr io.Writer, asJSON bool, code int) int {
	if r.URLFindings == nil {
		r.URLFindings = []doctor.Finding{}
	}
	if r.EnvFindings == nil {
		r.EnvFindings = []doctor.Finding{}
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return code
	}
	w := stdout
	fmt.Fprintln(w, "proxy-monitor doctor")
	if r.Proxy != "" {
		fmt.Fprintf(w, "  proxy   %s  (%s, from %s)\n", r.Proxy, r.Protocol, r.From)
	}
	fmt.Fprintf(w, "  target  %s\n", r.Target)
	section := func(title string, fs []doctor.Finding) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, f := range fs {
			fmt.Fprintf(w, "  %-5s %s\n", label(f.Level), redact.String(f.Message))
			if f.Fix != "" {
				fmt.Fprintf(w, "        fix: %s\n", redact.String(f.Fix))
			}
		}
	}
	section("Proxy URL", r.URLFindings)
	if len(r.URLFindings) == 0 && r.Ran {
		fmt.Fprintf(w, "\nProxy URL\n  %-5s parsed as %s\n", label(doctor.OK), r.Protocol)
	}
	section("Environment", r.EnvFindings)
	if !r.Ran {
		fmt.Fprintln(w, "\nNot checked: fix the URL first.")
		return code
	}
	fmt.Fprintln(w, "\nConnection")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, ph := range r.Phases {
		mark, d := "-", "" // not reached
		if ph.Status != doctor.Info {
			mark, d = label(ph.Status), durationText(ph.Duration)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", mark, ph.Name, d)
	}
	_ = tw.Flush()
	res := r.Result
	if r.OK {
		detail := "tunnel established"
		if res.StatusCode != 0 {
			detail = fmt.Sprintf("HTTP %d", res.StatusCode)
		}
		fmt.Fprintf(w, "\nResult: the proxy works (%s in %s).\n", detail, durationText(res.Total))
		return code
	}
	fmt.Fprintf(w, "\nResult: %s: %s\n", res.Class, res.Error)
	if a := r.Advice; a != nil {
		fmt.Fprintf(w, "\n%s\n  %s\n\nWhat to try:\n", a.Title, a.Why)
		for i, f := range a.Fixes {
			fmt.Fprintf(w, "  %d. %s\n", i+1, redact.String(f))
		}
	}
	return code
}

func label(l doctor.Level) string {
	switch l {
	case doctor.Fail:
		return "FAIL"
	case doctor.Info:
		return "info"
	}
	return string(l)
}

func durationText(d time.Duration) string {
	switch {
	case d <= 0:
		return "0ms"
	case d < time.Millisecond:
		return "<1ms"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
