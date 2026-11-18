// Package doctor explains why a proxy does not work: it lints the proxy URL
// and the proxy environment variables, runs one check through the proxy and
// turns the failure class into a plain-language cause and concrete fixes.
//
// It never prints a password: every value shown goes through package redact.
package doctor

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/checks"
	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

// Level is how serious a finding is.
type Level string

const (
	OK   Level = "ok"
	Info Level = "info"
	Warn Level = "warn"
	Fail Level = "fail"
)

// Finding is one observation about the configuration or the environment.
type Finding struct {
	Level   Level  `json:"level"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// Phase is one step of the connection, with its outcome.
type Phase struct {
	Key      string        `json:"key"`
	Name     string        `json:"name"`
	Status   Level         `json:"status"` // ok, fail, or info for "not reached"
	Duration time.Duration `json:"duration"`
}

// Advice is the explanation for a failed check.
type Advice struct {
	Title string   `json:"title"`
	Why   string   `json:"why"`
	Fixes []string `json:"fixes"`
}

var (
	hostPortRe         = regexp.MustCompile(`^([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\]):(\d{1,5})$`)
	hostPortUserPassRe = regexp.MustCompile(`^([A-Za-z0-9.\-]+):(\d{1,5}):([^:]+):(.+)$`)
	badPercentRe       = regexp.MustCompile(`%([^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|[0-9A-Fa-f]?$)`)
)

// LintURL looks at the proxy URL as typed, before it is parsed. It returns
// the URL to use (a corrected one when the intent is clear) and what it found.
// ok is false when nothing usable could be derived.
func LintURL(raw string) (use string, findings []Finding, ok bool) {
	add := func(l Level, msg, fix string) { findings = append(findings, Finding{l, msg, fix}) }
	s := strings.TrimSpace(raw)
	if s != raw {
		add(Warn, "the proxy URL has spaces or line breaks around it", "remove them; many tools do not trim")
	}
	if s == "" {
		add(Fail, "no proxy URL given", "pass one, for example http://user:pass@proxy.example.com:8080")
		return "", findings, false
	}
	if strings.ContainsAny(s, " \t\r\n") {
		add(Fail, "the proxy URL contains spaces", "percent-encode a space in a password as %20")
		return "", findings, false
	}

	if !strings.Contains(s, "://") {
		switch {
		case hostPortUserPassRe.MatchString(s):
			m := hostPortUserPassRe.FindStringSubmatch(s)
			u := &url.URL{Scheme: "http", Host: net.JoinHostPort(m[1], m[2]), User: url.UserPassword(m[3], m[4])}
			redact.Register(m[4])
			add(Fail, "host:port:user:pass is a provider export format, not a proxy URL",
				"write it as a URL, scheme first and the login before the @: "+redact.URL(u)+" (doctor checks that form; special characters in the password get percent-encoded)")
			return u.String(), findings, true
		case strings.Contains(s, "@"):
			add(Warn, "the proxy URL has no scheme; assuming http://", "write http:// (or socks5h://) in front")
			s = "http://" + s
		case hostPortRe.MatchString(s):
			add(Warn, "the proxy URL has no scheme; assuming http://", "write http://"+s+" (or socks5h://"+s+" for a SOCKS5 port)")
			s = "http://" + s
		default:
			add(Fail, "this does not look like a proxy address", "expected scheme://user:pass@host:port")
			return "", findings, false
		}
	}

	scheme, rest, _ := strings.Cut(s, "://")
	scheme = strings.ToLower(scheme)
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 && strings.LastIndex(rest, "@") < i {
		authority = rest[:i]
	}
	switch scheme {
	case "http", "socks5h":
	case "https":
		add(Info, "https:// means TLS between you and the proxy itself",
			"most \"HTTPS proxies\" sold by providers are http:// proxies that tunnel HTTPS sites; if the TLS handshake with the proxy fails, use http://")
	case "socks5":
		add(Info, "socks5:// resolves the target's host name on this machine",
			"use socks5h:// to let the proxy resolve it: your DNS stays private and geo-targeted proxies see the right name")
	case "socks4", "socks4a":
		add(Fail, "SOCKS4 is not supported by this check", "use proxy-checker (github.com/FusionProxies/proxy-checker), or the provider's SOCKS5 or HTTP port")
		return "", findings, false
	default:
		add(Fail, fmt.Sprintf("unknown proxy scheme %q", scheme), "use http://, https://, socks5:// or socks5h://")
		return "", findings, false
	}

	// Credentials with reserved characters are the most common hand-written mistake.
	if strings.Count(authority, "@") > 1 {
		at := strings.LastIndex(authority, "@")
		user, pass, _ := strings.Cut(authority[:at], ":")
		redact.Register(pass)
		u := &url.URL{Scheme: scheme, Host: authority[at+1:], User: url.UserPassword(user, pass)}
		add(Fail, "the username or password contains @, which ends the credentials early",
			"percent-encode it as %40: "+redact.URL(u))
		return u.String(), findings, true
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 && strings.ContainsAny(rest[:at], "/?#") {
		add(Fail, "the username or password contains / ? or #, which cut the URL in the wrong place",
			"percent-encode them (%2F %3F %23), or pass the password in the PROXY_PASSWORD environment variable")
		return "", findings, false
	}
	if badPercentRe.MatchString(authority) {
		add(Fail, "a % in the URL is not followed by two hex digits", "write a literal % in a password as %25")
		return "", findings, false
	}
	return scheme + "://" + rest, findings, true
}

// envNames are checked in this order: lowercase and uppercase differ between tools.
var envNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

// LintEnv reports problems with the proxy environment variables that curl,
// Python, Go, Node and most CLIs read. targetHost is the host being checked.
func LintEnv(lookup func(string) (string, bool), targetHost, targetScheme string) []Finding {
	var out []Finding
	add := func(l Level, msg, fix string) { out = append(out, Finding{l, msg, fix}) }
	val := map[string]string{}
	anySet := false
	for _, n := range envNames {
		up, okUp := lookup(n)
		lo, okLo := lookup(strings.ToLower(n))
		switch {
		case okUp && okLo && up != lo:
			add(Warn, fmt.Sprintf("%s and %s are both set, to different values", n, strings.ToLower(n)),
				"tools disagree on which one wins (curl ignores uppercase HTTP_PROXY); keep one, or make them equal")
			val[n] = lo
		case okLo:
			val[n] = lo
		case okUp:
			val[n] = up
		}
		if v, ok := val[n]; ok && v != "" {
			anySet = true
		}
	}
	if !anySet {
		return []Finding{{Level: Info, Message: "no proxy environment variables are set (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY)"}}
	}
	for _, n := range envNames[:3] {
		v := val[n]
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		switch {
		case !strings.Contains(v, "://"):
			add(Info, n+" has no scheme; most tools assume http://", "write it as http://host:port to be explicit")
		case err != nil:
			add(Fail, n+" is not a valid URL", "percent-encode special characters in the password")
		default:
			if u.User != nil {
				if pw, set := u.User.Password(); set {
					redact.Register(pw)
				}
				add(Info, n+" holds a username and password", "every program you start can read it; that is normal for CI, but keep it out of shared shells and logs")
			}
			if n == "HTTPS_PROXY" && u.Scheme == "https" {
				add(Warn, "HTTPS_PROXY starts with https://",
					"HTTPS_PROXY names the proxy used FOR https:// sites; the proxy itself is usually http://, so write HTTPS_PROXY=http://...")
			}
		}
	}
	if targetScheme == "https" && val["HTTPS_PROXY"] == "" && val["ALL_PROXY"] == "" && val["HTTP_PROXY"] != "" {
		add(Warn, "only HTTP_PROXY is set, so https:// requests go direct in curl, Python and Go",
			"set HTTPS_PROXY too (to the same http:// proxy URL)")
	}
	if np := val["NO_PROXY"]; np != "" && bypasses(np, targetHost) {
		add(Warn, "NO_PROXY matches "+targetHost+", so tools that read the environment skip the proxy for it",
			"remove the matching entry from NO_PROXY if this host should use the proxy")
	}
	return out
}

// bypasses reports whether a NO_PROXY list covers host (exact name, a domain
// suffix, *, or an IP).
func bypasses(list, host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, e := range strings.Split(list, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		e = strings.Trim(e, "[]")
		switch {
		case e == "":
		case e == "*":
			return true
		case e == host:
			return true
		case strings.HasPrefix(e, "."):
			if strings.HasSuffix(host, e) || host == e[1:] {
				return true
			}
		case strings.HasSuffix(host, "."+e):
			return true
		}
	}
	return false
}

// Phases lists the connection steps of a check with their outcome.
func Phases(r checks.Result, p *config.Proxy) []Phase {
	tunneled := p.IsSOCKS() || p.Mode == config.ModeConnect
	handshake := "proxy handshake (" + p.Protocol() + ")"
	if p.Scheme == "http" && !tunneled {
		handshake = ""
	}
	all := []Phase{
		{Key: checks.PhaseDNS, Name: "resolve the proxy host " + p.Host, Duration: r.DNS},
		{Key: checks.PhaseConnect, Name: "TCP connect to " + net.JoinHostPort(p.Host, p.Port), Duration: r.Connect},
		{Key: checks.PhaseHandshake, Name: handshake, Duration: r.Handshake},
		{Key: checks.PhaseTargetTLS, Name: "TLS with " + p.TargetRef.Parsed.Hostname() + " through the tunnel", Duration: r.TLS},
		{Key: checks.PhaseResponse, Name: "request and response", Duration: r.TTFB},
	}
	var out []Phase
	reached := true
	for _, ph := range all {
		if ph.Name == "" || (ph.Key == checks.PhaseTargetTLS && !(tunneled && p.TargetRef.Parsed.Scheme == "https")) {
			continue
		}
		if ph.Key == checks.PhaseResponse && p.TargetRef.Check == config.CheckTunnel {
			continue
		}
		switch {
		case !reached:
			ph.Status, ph.Duration = Info, 0
		case !r.OK && r.Phase == ph.Key:
			ph.Status = Fail
			reached = false
		default:
			ph.Status = OK
		}
		out = append(out, ph)
	}
	if !r.OK && reached && len(out) > 0 { // failure without a known phase: blame the last step
		out[len(out)-1].Status = Fail
	}
	return out
}

// Explain turns a failed check into a cause and fixes. It returns nil for a
// successful check.
func Explain(r checks.Result, p *config.Proxy) *Advice {
	if r.OK {
		return nil
	}
	e := strings.ToLower(r.Error)
	socks := p.IsSOCKS()
	switch r.Class {
	case checks.ClassDNS:
		if strings.Contains(e, "target") {
			return &Advice{"This machine cannot resolve the target's name",
				"With socks5:// the target is looked up here, before the proxy is asked to connect.",
				[]string{"use socks5h:// so the proxy resolves the name", "check the target host name for typos"}}
		}
		return &Advice{"The proxy host name does not resolve",
			"The name of the proxy server could not be found in DNS from this machine.",
			[]string{"check the spelling against your provider's dashboard",
				"try the proxy's IP address instead of its name",
				"if you are on a company network or VPN, its DNS may not know public names: try another network"}}
	case checks.ClassRefused:
		return &Advice{"Nothing accepts connections on that port",
			"The proxy host answered, but no service listens on " + p.Port + ".",
			[]string{"check the port: providers often use different ports for HTTP and SOCKS5, and for rotating and sticky sessions",
				"check that the proxy or the plan is active",
				"a local firewall or antivirus can also refuse outgoing connections"}}
	case checks.ClassConnect:
		if r.Phase == checks.PhaseConnect {
			return &Advice{"The TCP connection to the proxy failed",
				"The network path to the proxy is blocked or the host is unreachable.",
				[]string{"check that this network allows outgoing connections to port " + p.Port + " (company networks often block non-web ports)",
					"if the provider uses an IP allowlist, add this machine's public IP",
					"try from another network to tell a local block from a proxy problem"}}
		}
		return &Advice{"The proxy closed the connection",
			"The proxy accepted the connection and then dropped it during " + phaseName(r.Phase) + ".",
			[]string{"if the provider uses an IP allowlist, add this machine's public IP (some proxies drop unknown clients silently)",
				"check that the scheme matches the port: " + otherScheme(p),
				"the proxy may be overloaded or rate-limiting you: wait and retry, or use another session or port"}}
	case checks.ClassTimeout:
		switch r.Phase {
		case checks.PhaseDNS, checks.PhaseConnect:
			return &Advice{"The proxy did not answer the connection attempt",
				"Packets to the proxy are probably dropped by a firewall, or the address is wrong.",
				[]string{"check the host and port", "if the provider uses an IP allowlist, add this machine's public IP",
					"check that this network allows outgoing connections to port " + p.Port}}
		case checks.PhaseHandshake:
			return &Advice{"The proxy went silent during the handshake",
				"The connection opened, but the proxy did not answer the " + p.Protocol() + " handshake in time.",
				[]string{"check that the scheme matches the port: " + otherScheme(p),
					"the proxy may be overloaded: retry with a longer -timeout"}}
		default:
			return &Advice{"The answer took too long",
				"The tunnel worked, but the target did not answer through it in time.",
				[]string{"retry with a longer -timeout", "check the target without the proxy",
					"with rotating proxies, a slow exit IP is common: retry, or use another session"}}
		}
	case checks.ClassAuth:
		fixes := []string{
			"copy the username and password again from your provider's dashboard",
			"percent-encode special characters in the password (@ as %40, : as %3A, # as %23)",
			"check that the account still has traffic or an active plan: many providers answer 407 when it runs out",
			"if you use username parameters (country, session), check their syntax in your provider's docs",
		}
		if socks {
			fixes = append(fixes, "if your plan only allows IP allowlisting on SOCKS5, add this machine's public IP and drop the credentials")
		}
		if strings.Contains(e, "no username") {
			fixes = []string{"add the credentials: scheme://user:pass@host:port", "or allowlist this machine's public IP with your provider"}
		}
		return &Advice{"The proxy rejected the login",
			map[bool]string{true: "The SOCKS5 server refused the username/password.", false: "The proxy answered HTTP 407 Proxy Authentication Required."}[socks],
			fixes}
	case checks.ClassProtocol:
		return &Advice{"The port does not speak the protocol in the URL",
			"Something answered, but not as a " + p.Protocol() + " proxy would.",
			[]string{"check that the scheme matches the port: " + otherScheme(p),
				"make sure the address is a proxy and not a web server or VPN endpoint"}}
	case checks.ClassRejected:
		return &Advice{"The proxy refused to connect to this target",
			"The proxy's policy blocks the target host or port (HTTP 403/405 to CONNECT, or a SOCKS5 rule).",
			[]string{"try another target to confirm (for example https://example.com/)",
				"some providers block certain sites or ports (mail, banking, government): check their acceptable-use list",
				"some proxies only allow CONNECT to port 443"}}
	case checks.ClassUpstream:
		return &Advice{"The proxy could not reach the target",
			"The proxy works, but its connection to the target failed (HTTP 502/503/504 or a SOCKS5 network error).",
			[]string{"check the target without the proxy", "try another target to tell a target problem from a proxy problem",
				"with rotating proxies, retry: the next exit IP may reach it"}}
	case checks.ClassProxyError:
		return &Advice{"The proxy reported an error",
			"The proxy answered with an error that does not fit a more specific class.",
			[]string{"retry; if it repeats, send the error line below to your provider"}}
	case checks.ClassTLS:
		if r.Phase == checks.PhaseHandshake {
			return &Advice{"TLS with the proxy itself failed",
				"With https:// the connection to the proxy is encrypted; most proxies do not support that.",
				[]string{"use http:// for the proxy (HTTPS sites still work through it)",
					"if the provider really offers TLS to the proxy, check the certificate and this machine's clock"}}
		}
		return &Advice{"TLS with the target failed through the tunnel",
			"The tunnel was open, but the target's certificate did not verify.",
			[]string{"check this machine's date and time",
				"a proxy that intercepts TLS presents its own certificate: do not send passwords or cookies through it",
				"a company network or antivirus that inspects HTTPS can cause this too"}}
	case checks.ClassStatus:
		fixes := []string{"open the target without the proxy to compare"}
		if r.StatusCode == 403 || r.StatusCode == 429 {
			fixes = append(fixes, "403 and 429 usually mean the site blocks or rate-limits this exit IP: datacenter IPs are blocked most often; try another IP, a rotating session, or residential IPs")
		}
		if r.StatusCode >= 500 {
			fixes = append(fixes, "a 5xx can come from the proxy itself in forward mode: try -mode connect")
		}
		return &Advice{fmt.Sprintf("The target answered HTTP %d", r.StatusCode),
			"The proxy worked; the target's answer was not the expected one.", fixes}
	case checks.ClassBody:
		return &Advice{"The response body was not what was expected",
			"The proxy worked; the target's page content differed (a block page or captcha is common).",
			[]string{"open the target through the proxy in a browser to see what it returns"}}
	}
	return &Advice{checks.ErrorClassText(r.Class), r.Error, []string{"retry, and send the error line to your provider if it repeats"}}
}

func phaseName(key string) string {
	switch key {
	case checks.PhaseDNS:
		return "the DNS lookup"
	case checks.PhaseConnect:
		return "the TCP connect"
	case checks.PhaseHandshake:
		return "the proxy handshake"
	case checks.PhaseTargetTLS:
		return "TLS with the target"
	}
	return "the request"
}

func otherScheme(p *config.Proxy) string {
	if p.IsSOCKS() {
		return "if this is an HTTP port, use http://" + net.JoinHostPort(p.Host, p.Port)
	}
	return "if this is a SOCKS5 port, use socks5h://" + net.JoinHostPort(p.Host, p.Port)
}

// PortHint returns a note when the port is a well-known one for the other
// protocol (1080 is SOCKS, 3128/8080/8888 are HTTP).
func PortHint(p *config.Proxy) string {
	n, _ := strconv.Atoi(p.Port)
	switch {
	case p.IsSOCKS() && (n == 3128 || n == 8080 || n == 8888 || n == 80):
		return fmt.Sprintf("port %d is usually an HTTP proxy port", n)
	case !p.IsSOCKS() && (n == 1080 || n == 1081 || n == 9050):
		return fmt.Sprintf("port %d is usually a SOCKS port", n)
	}
	return ""
}
