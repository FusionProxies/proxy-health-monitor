package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/stats"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
)

func openStoreReadOnly(cfg *config.Config, stderr io.Writer) (*storage.Store, bool) {
	if _, err := os.Stat(cfg.Storage.Path); err != nil {
		fmt.Fprintf(stderr, "no database at %s yet: run `proxy-monitor start` first\n", cfg.Storage.Path)
		return nil, false
	}
	st, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false
	}
	return st, true
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("status", stderr)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	cfg, ok := loadConfig(*path, stderr)
	if !ok {
		return exitUsage
	}
	st, ok := openStoreReadOnly(cfg, stderr)
	if !ok {
		return exitRuntime
	}
	defer st.Close()
	states, err := st.States()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	open, _ := st.Incidents(storage.IncidentFilter{OnlyOpen: true})
	now := time.Now()
	type row struct {
		Name                string        `json:"name"`
		Protocol            string        `json:"protocol"`
		State               string        `json:"state"`
		LastCheck           *time.Time    `json:"last_check"`
		ConsecutiveFailures int           `json:"consecutive_failures"`
		LastError           string        `json:"last_error,omitempty"`
		Day                 stats.Summary `json:"last_24h"`
		OpenIncidents       []string      `json:"open_incidents,omitempty"`
	}
	var rows []row
	down := 0
	for _, p := range cfg.Proxies {
		s, has := states[p.Name]
		r := row{Name: p.Name, Protocol: p.Protocol(), State: "unknown"}
		if p.Disabled {
			r.State = "disabled"
		} else if has {
			r.State = s.State
			r.ConsecutiveFailures = s.ConsecutiveFailures
			if !s.LastCheck.IsZero() {
				t := s.LastCheck
				r.LastCheck = &t
			}
			if s.State != "healthy" {
				r.LastError = s.LastError
			}
		}
		samples, _ := st.Samples(p.Name, now.Add(-24*time.Hour), now.Add(time.Second))
		r.Day = stats.Summarize(samples)
		for _, in := range open {
			if in.Proxy == p.Name {
				r.OpenIncidents = append(r.OpenIncidents, fmt.Sprintf("#%d %s since %s", in.ID, in.Kind, in.StartedAt.Local().Format("2006-01-02 15:04")))
			}
		}
		if r.State == "down" {
			down++
		}
		rows = append(rows, r)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"proxies": rows, "down": down})
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PROXY\tSTATE\tLAST CHECK\t24H UPTIME\tP50\tP95\tFAILS\tLAST ERROR")
		for _, r := range rows {
			last := "never"
			if r.LastCheck != nil {
				last = now.Sub(*r.LastCheck).Round(time.Second).String() + " ago"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.Name, strings.ToUpper(r.State), last, pct(r.Day), msf(r.Day.P50MS, r.Day.Successes), msf(r.Day.P95MS, r.Day.Successes), r.ConsecutiveFailures, trunc(r.LastError, 70))
		}
		_ = tw.Flush()
		if len(open) > 0 {
			fmt.Fprintln(stdout, "\nOpen incidents:")
			for _, r := range rows {
				for _, in := range r.OpenIncidents {
					fmt.Fprintf(stdout, "  %s: %s\n", r.Name, in)
				}
			}
		}
	}
	if down > 0 {
		return exitFailed
	}
	return exitOK
}

func pct(s stats.Summary) string {
	if s.Checks == 0 {
		return "-"
	}
	return strconv.FormatFloat(s.Uptime, 'f', 2, 64) + "%"
}

func msf(v float64, n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0fms", v)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("report", stderr)
	path := configFlag(fs)
	since := fs.String("since", "24h", "period to report: a duration such as 24h, 7d or 30d")
	format := fs.String("format", "table", "table, json, csv or markdown")
	only := fs.String("proxy", "", "comma-separated proxy names (default: all)")
	if code, ok := parse(fs, args); !ok {
		return code
	}
	period, err := config.ParseDuration(*since)
	if err != nil || period <= 0 {
		fmt.Fprintf(stderr, "invalid -since %q\n", *since)
		return exitUsage
	}
	cfg, ok := loadConfig(*path, stderr)
	if !ok {
		return exitUsage
	}
	st, ok := openStoreReadOnly(cfg, stderr)
	if !ok {
		return exitRuntime
	}
	defer st.Close()

	now := time.Now()
	from := now.Add(-period)
	want := map[string]bool{}
	for _, n := range splitList(*only) {
		want[n] = true
	}
	type entry struct {
		Proxy     string             `json:"proxy"`
		Protocol  string             `json:"protocol"`
		Summary   stats.Summary      `json:"summary"`
		Incidents int                `json:"incidents"`
		Downtime  float64            `json:"downtime_seconds"`
		List      []storage.Incident `json:"incident_list"`
	}
	var entries []entry
	for _, p := range cfg.Proxies {
		if len(want) > 0 && !want[p.Name] {
			continue
		}
		samples, err := st.Samples(p.Name, from, now.Add(time.Second))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		inc, _ := st.Incidents(storage.IncidentFilter{Proxy: p.Name, Since: from})
		e := entry{Proxy: p.Name, Protocol: p.Protocol(), Summary: stats.Summarize(samples), List: inc}
		if e.List == nil {
			e.List = []storage.Incident{}
		}
		for _, in := range inc {
			e.Incidents++
			if in.Kind == "down" {
				start := in.StartedAt
				if start.Before(from) {
					start = from
				}
				end := now
				if in.EndedAt != nil {
					end = *in.EndedAt
				}
				e.Downtime += end.Sub(start).Seconds()
			}
		}
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Proxy < entries[j].Proxy })
	label := config.FormatDuration(period)

	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"from": from.UTC(), "to": now.UTC(), "period": label, "proxies": entries})
	case "csv":
		w := csv.NewWriter(stdout)
		_ = w.Write([]string{"proxy", "protocol", "checks", "successes", "uptime_percent", "avg_ms", "p50_ms", "p95_ms", "max_ms", "incidents", "downtime_seconds"})
		for _, e := range entries {
			s := e.Summary
			_ = w.Write([]string{e.Proxy, e.Protocol, strconv.Itoa(s.Checks), strconv.Itoa(s.Successes), f2(s.Uptime), f2(s.AvgMS), f2(s.P50MS), f2(s.P95MS), f2(s.MaxMS), strconv.Itoa(e.Incidents), f2(e.Downtime)})
		}
		w.Flush()
	case "markdown", "md":
		fmt.Fprintf(stdout, "## Proxy health report, last %s\n\n%s to %s\n\n", label, from.Local().Format("2006-01-02 15:04"), now.Local().Format("2006-01-02 15:04 MST"))
		fmt.Fprintln(stdout, "| Proxy | Protocol | Checks | Uptime | p50 | p95 | Incidents | Downtime |")
		fmt.Fprintln(stdout, "|---|---|---:|---:|---:|---:|---:|---:|")
		for _, e := range entries {
			s := e.Summary
			fmt.Fprintf(stdout, "| %s | %s | %d | %s | %s | %s | %d | %s |\n", e.Proxy, e.Protocol, s.Checks, pct(s), msf(s.P50MS, s.Successes), msf(s.P95MS, s.Successes), e.Incidents, dur(e.Downtime))
		}
		for _, e := range entries {
			if len(e.List) == 0 {
				continue
			}
			fmt.Fprintf(stdout, "\n### %s incidents\n\n", e.Proxy)
			for _, in := range e.List {
				end := "ongoing"
				if in.EndedAt != nil {
					end = in.EndedAt.Local().Format("2006-01-02 15:04")
				}
				fmt.Fprintf(stdout, "- %s, %s to %s (%s): %s\n", in.Kind, in.StartedAt.Local().Format("2006-01-02 15:04"), end, dur(in.DurationS), in.Reason)
			}
		}
	case "table":
		fmt.Fprintf(stdout, "Report for the last %s (%s to %s)\n\n", label, from.Local().Format("2006-01-02 15:04"), now.Local().Format("2006-01-02 15:04"))
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PROXY\tCHECKS\tUPTIME\tAVG\tP50\tP95\tMAX\tINCIDENTS\tDOWNTIME\tTOP ERROR")
		for _, e := range entries {
			s := e.Summary
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", e.Proxy, s.Checks, pct(s), msf(s.AvgMS, s.Successes), msf(s.P50MS, s.Successes), msf(s.P95MS, s.Successes), msf(s.MaxMS, s.Successes), e.Incidents, dur(e.Downtime), topError(s.Errors))
		}
		_ = tw.Flush()
	default:
		fmt.Fprintf(stderr, "unknown -format %q (table, json, csv, markdown)\n", *format)
		return exitUsage
	}
	return exitOK
}

func f2(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

func dur(sec float64) string {
	if sec <= 0 {
		return "0s"
	}
	return time.Duration(sec * float64(time.Second)).Round(time.Second).String()
}

func topError(m map[string]int) string {
	best, n := "", 0
	for k, v := range m {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%s (%d)", best, n)
}
