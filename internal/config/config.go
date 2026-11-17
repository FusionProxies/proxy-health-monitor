// Package config loads and validates the YAML configuration.
//
// Only proxies and targets listed in the file are ever contacted. Every
// request the monitor sends goes through a configured proxy to a configured
// target, at the configured interval, so the file is the complete list of
// what the program is authorized to touch.
package config

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

// Hard limits that keep the monitor conservative no matter what the file says.
const (
	// FloorInterval is the shortest interval allowed for a proxy that is not
	// on the local machine.
	FloorInterval = 10 * time.Second
	// LoopbackFloorInterval applies to proxies on 127.0.0.1, ::1 or localhost
	// (test setups and the demo).
	LoopbackFloorInterval = 1 * time.Second
	MaxTimeout            = 2 * time.Minute
	MaxConcurrency        = 64
	MinTokenLength        = 16
)

// Config is the whole configuration file.
type Config struct {
	Storage    Storage    `yaml:"storage" json:"storage"`
	Server     Server     `yaml:"server" json:"server"`
	Monitor    Monitor    `yaml:"monitor" json:"monitor"`
	Thresholds Thresholds `yaml:"thresholds" json:"thresholds"`
	Targets    []*Target  `yaml:"targets" json:"targets"`
	Proxies    []*Proxy   `yaml:"proxies" json:"proxies"`
	Alerts     Alerts     `yaml:"alerts" json:"alerts"`

	// Demo marks data produced by `proxy-monitor demo`. The dashboard shows a
	// banner and the API reports it.
	Demo bool `yaml:"-" json:"demo"`
	// Path is the file the configuration was read from.
	Path string `yaml:"-" json:"-"`
}

// Storage controls the SQLite database.
type Storage struct {
	Path              string   `yaml:"path" json:"path"`
	Retention         Duration `yaml:"retention" json:"retention"`
	IncidentRetention Duration `yaml:"incident_retention" json:"incident_retention"`
}

// Server controls the dashboard, the REST API and the Prometheus endpoint.
type Server struct {
	Enabled                *bool    `yaml:"enabled" json:"enabled"`
	Listen                 string   `yaml:"listen" json:"listen"`
	AuthToken              string   `yaml:"auth_token" json:"-"`
	AllowRemoteWithoutAuth bool     `yaml:"allow_remote_without_auth" json:"allow_remote_without_auth"`
	AllowedHosts           []string `yaml:"allowed_hosts" json:"allowed_hosts"`
}

// IsEnabled reports whether the HTTP server should run (default true).
func (s Server) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// Monitor holds scheduling defaults.
type Monitor struct {
	Interval    Duration `yaml:"interval" json:"interval"`
	Timeout     Duration `yaml:"timeout" json:"timeout"`
	Jitter      float64  `yaml:"jitter" json:"jitter"`
	Concurrency int      `yaml:"concurrency" json:"concurrency"`
	MinInterval Duration `yaml:"min_interval" json:"min_interval"`
}

// Thresholds decide when a proxy is degraded or down and when alerts fire.
type Thresholds struct {
	FailureThreshold      int      `yaml:"failure_threshold" json:"failure_threshold"`
	RecoveryThreshold     int      `yaml:"recovery_threshold" json:"recovery_threshold"`
	Latency               Duration `yaml:"latency" json:"latency"`
	LatencySamples        int      `yaml:"latency_samples" json:"latency_samples"`
	Availability          float64  `yaml:"availability" json:"availability"`
	AvailabilityWindow    Duration `yaml:"availability_window" json:"availability_window"`
	AvailabilityMinChecks int      `yaml:"availability_min_checks" json:"availability_min_checks"`
}

// Target is an endpoint the user controls (or may test) that checks request
// through a proxy.
type Target struct {
	Name               string            `yaml:"name" json:"name"`
	URL                string            `yaml:"url" json:"-"`
	Check              string            `yaml:"check" json:"check"`
	Method             string            `yaml:"method" json:"method"`
	ExpectStatus       []int             `yaml:"expect_status" json:"expect_status"`
	ExpectBody         string            `yaml:"expect_body" json:"expect_body,omitempty"`
	Headers            map[string]string `yaml:"headers" json:"-"`
	MaxBodyBytes       int64             `yaml:"max_body_bytes" json:"max_body_bytes"`
	CAFile             string            `yaml:"ca_file" json:"ca_file,omitempty"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	MaxConcurrent      int               `yaml:"max_concurrent" json:"max_concurrent"`
	MinSpacing         Duration          `yaml:"min_spacing" json:"min_spacing"`

	Parsed  *url.URL       `yaml:"-" json:"-"`
	RootCAs *x509.CertPool `yaml:"-" json:"-"`
}

// DisplayURL is the target URL with query values masked.
func (t *Target) DisplayURL() string { return redact.URL(t.Parsed) }

// ThresholdOverrides lets one proxy use different thresholds. Zero values
// inherit the global setting.
type ThresholdOverrides struct {
	FailureThreshold      int      `yaml:"failure_threshold"`
	RecoveryThreshold     int      `yaml:"recovery_threshold"`
	Latency               Duration `yaml:"latency"`
	LatencySamples        int      `yaml:"latency_samples"`
	Availability          float64  `yaml:"availability"`
	AvailabilityWindow    Duration `yaml:"availability_window"`
	AvailabilityMinChecks int      `yaml:"availability_min_checks"`
}

// Proxy is one monitored proxy endpoint.
type Proxy struct {
	Name               string              `yaml:"name" json:"name"`
	URL                string              `yaml:"url" json:"-"`
	Username           string              `yaml:"username" json:"-"`
	Password           string              `yaml:"password" json:"-"`
	Mode               string              `yaml:"mode" json:"mode"`
	Target             string              `yaml:"target" json:"target"`
	Interval           Duration            `yaml:"interval" json:"interval"`
	Timeout            Duration            `yaml:"timeout" json:"timeout"`
	Labels             map[string]string   `yaml:"labels" json:"labels,omitempty"`
	Thresholds         *ThresholdOverrides `yaml:"thresholds" json:"-"`
	CAFile             string              `yaml:"ca_file" json:"-"`
	InsecureSkipVerify bool                `yaml:"insecure_skip_verify" json:"-"`
	Disabled           bool                `yaml:"disabled" json:"disabled"`

	// Filled in by Validate.
	Parsed    *url.URL       `yaml:"-" json:"-"`
	Scheme    string         `yaml:"-" json:"scheme"`
	Host      string         `yaml:"-" json:"-"`
	Port      string         `yaml:"-" json:"-"`
	TargetRef *Target        `yaml:"-" json:"-"`
	Effective Thresholds     `yaml:"-" json:"-"`
	RootCAs   *x509.CertPool `yaml:"-" json:"-"`
}

// DisplayURL is the proxy URL with the username masked and no password.
func (p *Proxy) DisplayURL() string { return redact.URL(p.Parsed) }

// Protocol is a short human label such as "HTTP CONNECT" or "SOCKS5 (remote DNS)".
func (p *Proxy) Protocol() string {
	switch p.Scheme {
	case "socks5":
		return "SOCKS5"
	case "socks5h":
		return "SOCKS5 (remote DNS)"
	}
	name := "HTTP"
	if p.Scheme == "https" {
		name = "HTTPS"
	}
	if p.Mode == ModeConnect {
		return name + " CONNECT"
	}
	return name + " forward"
}

// IsSOCKS reports whether the proxy speaks SOCKS5.
func (p *Proxy) IsSOCKS() bool { return p.Scheme == "socks5" || p.Scheme == "socks5h" }

// Alerts configures notifications.
type Alerts struct {
	Cooldown       Duration   `yaml:"cooldown" json:"cooldown"`
	MaxPerMinute   int        `yaml:"max_per_minute" json:"max_per_minute"`
	RepeatInterval Duration   `yaml:"repeat_interval" json:"repeat_interval"`
	Console        *bool      `yaml:"console" json:"console"`
	Webhooks       []*Webhook `yaml:"webhooks" json:"-"`
	Email          *Email     `yaml:"email" json:"-"`
	Telegram       *Telegram  `yaml:"telegram" json:"-"`
	Discord        []*Discord `yaml:"discord" json:"-"`
}

// ConsoleEnabled reports whether alerts go to the log (default true).
func (a Alerts) ConsoleEnabled() bool { return a.Console == nil || *a.Console }

// Webhook posts each alert as JSON.
type Webhook struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Secret  string            `yaml:"secret"`
	Headers map[string]string `yaml:"headers"`
	Events  []string          `yaml:"events"`
}

// Email sends alerts over SMTP.
type Email struct {
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	TLS      string   `yaml:"tls"`
	Events   []string `yaml:"events"`
}

// Telegram sends alerts through a bot.
type Telegram struct {
	BotToken string   `yaml:"bot_token"`
	ChatID   string   `yaml:"chat_id"`
	Events   []string `yaml:"events"`
	APIURL   string   `yaml:"api_url"`
}

// Discord posts alerts to a channel webhook.
type Discord struct {
	Name       string   `yaml:"name"`
	WebhookURL string   `yaml:"webhook_url"`
	Events     []string `yaml:"events"`
}

// Proxy modes for HTTP and HTTPS proxies.
const (
	ModeForward = "forward" // absolute-form request, the classic HTTP proxy
	ModeConnect = "connect" // CONNECT tunnel
)

// Target check types.
const (
	CheckHTTP   = "http"   // full request and response
	CheckTunnel = "tunnel" // tunnel to the target (plus TLS handshake for https), no request
)

// Alert event names, used in `events:` filters.
var EventNames = []string{"down", "still_down", "recovered", "latency", "latency_resolved", "availability", "availability_resolved"}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) { return LoadWithEnv(path, os.LookupEnv) }

// LoadWithEnv is Load with a custom environment lookup, for tests.
func LoadWithEnv(path string, lookup func(string) (string, bool)) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(raw, lookup)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	if err := cfg.Validate(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes YAML, replacing ${VAR} with environment values first. It does
// not validate.
func Parse(raw []byte, lookup func(string) (string, bool)) (*Config, error) {
	cfg := &Config{}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if root.Kind == 0 {
		return cfg, nil // empty file
	}
	var missing []string
	expandNode(&root, lookup, &missing)
	if len(missing) > 0 {
		return nil, fmt.Errorf("environment variable(s) not set: %s", strings.Join(unique(missing), ", "))
	}
	expanded, err := yaml.Marshal(&root)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return cfg, nil
		}
		return nil, err
	}
	return cfg, nil
}

var (
	envRe     = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	numericRe = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
)

func expandNode(n *yaml.Node, lookup func(string) (string, bool), missing *[]string) {
	if n.Kind == yaml.ScalarNode && strings.Contains(n.Value, "$") {
		n.Value = envRe.ReplaceAllStringFunc(n.Value, func(m string) string {
			if m == "$$" {
				return "$"
			}
			name := m[2 : len(m)-1]
			v, ok := lookup(name)
			if !ok {
				*missing = append(*missing, name)
				return ""
			}
			return v
		})
		// A plain number may fill a numeric field (a port); anything else stays
		// a string, so a password such as "null" or "~" is not read as YAML.
		if numericRe.MatchString(n.Value) || n.Value == "true" || n.Value == "false" {
			n.Tag, n.Style = "", 0
		} else {
			n.Tag, n.Style = "!!str", yaml.DoubleQuotedStyle
		}
	}
	for _, c := range n.Content {
		expandNode(c, lookup, missing)
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// applyDefaults fills every unset field.
func (c *Config) applyDefaults() {
	if c.Storage.Path == "" {
		c.Storage.Path = "proxy-monitor.db"
	}
	if c.Storage.Retention == 0 {
		c.Storage.Retention = Duration(30 * 24 * time.Hour)
	}
	if c.Storage.IncidentRetention == 0 {
		c.Storage.IncidentRetention = Duration(180 * 24 * time.Hour)
	}
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8090"
	}
	if c.Monitor.Interval == 0 {
		c.Monitor.Interval = Duration(60 * time.Second)
	}
	if c.Monitor.Timeout == 0 {
		c.Monitor.Timeout = Duration(10 * time.Second)
	}
	if c.Monitor.Jitter == 0 {
		c.Monitor.Jitter = 0.1
	}
	if c.Monitor.Concurrency == 0 {
		c.Monitor.Concurrency = 4
	}
	if c.Monitor.MinInterval == 0 {
		c.Monitor.MinInterval = Duration(FloorInterval)
	}
	t := &c.Thresholds
	if t.FailureThreshold == 0 {
		t.FailureThreshold = 3
	}
	if t.RecoveryThreshold == 0 {
		t.RecoveryThreshold = 2
	}
	if t.Latency == 0 {
		t.Latency = Duration(3 * time.Second)
	}
	if t.LatencySamples == 0 {
		t.LatencySamples = 5
	}
	if t.Availability == 0 {
		t.Availability = 95
	}
	if t.AvailabilityWindow == 0 {
		t.AvailabilityWindow = Duration(time.Hour)
	}
	if t.AvailabilityMinChecks == 0 {
		t.AvailabilityMinChecks = 10
	}
	if c.Alerts.Cooldown == 0 {
		c.Alerts.Cooldown = Duration(10 * time.Minute)
	}
	if c.Alerts.MaxPerMinute == 0 {
		c.Alerts.MaxPerMinute = 20
	}
	for _, tg := range c.Targets {
		if tg.Check == "" {
			tg.Check = CheckHTTP
		}
		if tg.Method == "" {
			tg.Method = "GET"
		}
		if len(tg.ExpectStatus) == 0 {
			tg.ExpectStatus = []int{200}
		}
		if tg.MaxBodyBytes == 0 {
			tg.MaxBodyBytes = 64 << 10
		}
		if tg.MaxConcurrent == 0 {
			tg.MaxConcurrent = 2
		}
		if tg.MinSpacing == 0 {
			tg.MinSpacing = Duration(500 * time.Millisecond)
		}
	}
	if c.Alerts.Email != nil {
		if c.Alerts.Email.Port == 0 {
			c.Alerts.Email.Port = 587
		}
		if c.Alerts.Email.TLS == "" {
			c.Alerts.Email.TLS = "starttls"
		}
	}
	if c.Alerts.Telegram != nil && c.Alerts.Telegram.APIURL == "" {
		c.Alerts.Telegram.APIURL = "https://api.telegram.org"
	}
}

// Validate applies defaults, checks every value and resolves references.
// Relative file paths are taken relative to baseDir.
func (c *Config) Validate(baseDir string) error {
	c.applyDefaults()
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if !filepath.IsAbs(c.Storage.Path) && baseDir != "" {
		c.Storage.Path = filepath.Join(baseDir, c.Storage.Path)
	}
	if c.Storage.Retention.D() < time.Hour {
		add("storage.retention must be at least 1h")
	}
	if c.Storage.IncidentRetention.D() < c.Storage.Retention.D() {
		add("storage.incident_retention must not be shorter than storage.retention")
	}

	// Server exposure rules.
	if c.Server.IsEnabled() {
		host, port, err := net.SplitHostPort(c.Server.Listen)
		if err != nil {
			add("server.listen %q: %v", c.Server.Listen, err)
		} else if _, err := strconv.Atoi(port); err != nil {
			add("server.listen %q: invalid port", c.Server.Listen)
		} else if !IsLoopbackHost(host) {
			if c.Server.AuthToken == "" && !c.Server.AllowRemoteWithoutAuth {
				add("server.listen %q is reachable from other machines: set server.auth_token, or bind to 127.0.0.1, or (only behind an authenticating reverse proxy or a port mapped to localhost) set server.allow_remote_without_auth: true", c.Server.Listen)
			}
		}
		if c.Server.AuthToken != "" && len(c.Server.AuthToken) < MinTokenLength {
			add("server.auth_token must be at least %d characters", MinTokenLength)
		}
	}

	m := &c.Monitor
	if m.MinInterval.D() < FloorInterval {
		add("monitor.min_interval cannot be lower than %s", FormatDuration(FloorInterval))
	}
	if m.Jitter < 0 || m.Jitter > 0.5 {
		add("monitor.jitter must be between 0 and 0.5")
	}
	if m.Concurrency < 1 || m.Concurrency > MaxConcurrency {
		add("monitor.concurrency must be between 1 and %d", MaxConcurrency)
	}
	if m.Timeout.D() > MaxTimeout {
		add("monitor.timeout cannot exceed %s", FormatDuration(MaxTimeout))
	}

	if err := c.Thresholds.check("thresholds"); err != nil {
		add("%v", err)
	}

	targets := map[string]*Target{}
	for i, t := range c.Targets {
		where := fmt.Sprintf("targets[%d]", i)
		if t.Name != "" {
			where = "target " + strconv.Quote(t.Name)
		}
		if !nameRe.MatchString(t.Name) {
			add("%s: name must be 1-64 letters, digits, '.', '_' or '-'", where)
		} else if targets[t.Name] != nil {
			add("%s: duplicate name", where)
		}
		targets[t.Name] = t
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			add("%s: url must be an http:// or https:// URL with a host", where)
			continue
		}
		if u.User != nil {
			add("%s: do not put credentials in the target URL; use headers", where)
		}
		t.Parsed = u
		switch t.Check {
		case CheckHTTP, CheckTunnel:
		default:
			add("%s: check must be %q or %q", where, CheckHTTP, CheckTunnel)
		}
		switch strings.ToUpper(t.Method) {
		case "GET", "HEAD":
			t.Method = strings.ToUpper(t.Method)
		default:
			add("%s: method must be GET or HEAD", where)
		}
		for _, s := range t.ExpectStatus {
			if s < 100 || s > 599 {
				add("%s: expect_status %d is not an HTTP status", where, s)
			}
		}
		if t.MaxBodyBytes < 0 || t.MaxBodyBytes > 1<<20 {
			add("%s: max_body_bytes must be between 0 and 1048576", where)
		}
		if t.MaxConcurrent < 1 || t.MaxConcurrent > 16 {
			add("%s: max_concurrent must be between 1 and 16", where)
		}
		if t.CAFile != "" {
			pool, err := loadCAFile(resolvePath(baseDir, t.CAFile))
			if err != nil {
				add("%s: ca_file: %v", where, err)
			}
			t.RootCAs = pool
		}
	}

	names := map[string]bool{}
	enabled := 0
	for i, p := range c.Proxies {
		where := fmt.Sprintf("proxies[%d]", i)
		if p.Name != "" {
			where = "proxy " + strconv.Quote(p.Name)
		}
		if !nameRe.MatchString(p.Name) {
			add("%s: name must be 1-64 letters, digits, '.', '_' or '-'", where)
		} else if names[p.Name] {
			add("%s: duplicate name", where)
		}
		names[p.Name] = true
		if !p.Disabled {
			enabled++
		}
		if err := p.resolve(); err != nil {
			add("%s: %v", where, err)
			continue
		}
		if p.Target == "" {
			if len(c.Targets) == 1 {
				p.Target = c.Targets[0].Name
			} else {
				add("%s: target is required (the name of an entry under targets)", where)
				continue
			}
		}
		t := targets[p.Target]
		if t == nil {
			add("%s: target %q is not defined under targets", where, p.Target)
			continue
		}
		p.TargetRef = t
		if t.Parsed == nil {
			continue
		}
		if !p.IsSOCKS() {
			switch p.Mode {
			case "":
				if t.Parsed.Scheme == "https" || t.Check == CheckTunnel {
					p.Mode = ModeConnect
				} else {
					p.Mode = ModeForward
				}
			case ModeForward:
				if t.Parsed.Scheme == "https" {
					add("%s: mode forward cannot reach an https:// target; use mode connect", where)
				}
				if t.Check == CheckTunnel {
					add("%s: a tunnel check needs mode connect", where)
				}
			case ModeConnect:
			default:
				add("%s: mode must be %q or %q", where, ModeForward, ModeConnect)
			}
		} else if p.Mode != "" {
			add("%s: mode applies only to http:// and https:// proxies", where)
		}
		if p.Interval == 0 {
			p.Interval = c.Monitor.Interval
		}
		if p.Timeout == 0 {
			p.Timeout = c.Monitor.Timeout
		}
		floor := c.Monitor.MinInterval.D()
		if IsLoopbackHost(p.Host) {
			floor = LoopbackFloorInterval
		}
		if p.Interval.D() < floor {
			add("%s: interval %s is below the minimum of %s", where, p.Interval, FormatDuration(floor))
		}
		if p.Timeout.D() <= 0 || p.Timeout.D() > MaxTimeout {
			add("%s: timeout must be between 1ms and %s", where, FormatDuration(MaxTimeout))
		} else if p.Timeout.D() >= p.Interval.D() {
			add("%s: timeout (%s) must be shorter than interval (%s)", where, p.Timeout, p.Interval)
		}
		p.Effective = c.Thresholds.merge(p.Thresholds)
		if err := p.Effective.check(where + " thresholds"); err != nil {
			add("%v", err)
		}
		for k := range p.Labels {
			if !labelKeyRe.MatchString(k) {
				add("%s: label key %q must match [a-zA-Z_][a-zA-Z0-9_]*", where, k)
			}
		}
		if p.CAFile != "" {
			pool, err := loadCAFile(resolvePath(baseDir, p.CAFile))
			if err != nil {
				add("%s: ca_file: %v", where, err)
			}
			p.RootCAs = pool
		}
	}
	if enabled == 0 {
		add("no enabled proxies: add at least one entry under proxies")
	}

	c.validateAlerts(add)
	c.registerSecrets()

	if len(errs) > 0 {
		return &ValidationError{Problems: errs}
	}
	return nil
}

var labelKeyRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ValidationError lists every problem found, so all of them can be fixed at once.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid configuration: " + redact.String(e.Problems[0])
	}
	return "invalid configuration:\n  - " + redact.String(strings.Join(e.Problems, "\n  - "))
}

func (p *Proxy) resolve() error {
	if p.URL == "" {
		return errors.New("url is required, for example http://proxy.example.com:3128")
	}
	raw := p.URL
	if !strings.Contains(raw, "://") {
		return errors.New("url needs a scheme: http://, https://, socks5:// or socks5h://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse errors quote the input, which can hold a password.
		return errors.New("url is not a valid URL (percent-encode special characters in the password, or use the username and password fields)")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("unsupported scheme %q: use http, https, socks5 or socks5h (SOCKS5 is checked over TCP CONNECT only)", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return errors.New("url must include a host and a port")
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return errors.New("url has an invalid port")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("a proxy url has no path")
	}
	user, pass := "", ""
	hasPass := false
	if u.User != nil {
		user = u.User.Username()
		pass, hasPass = u.User.Password()
	}
	if p.Username != "" {
		user = p.Username
	}
	if p.Password != "" {
		pass, hasPass = p.Password, true
	}
	if user == "" && hasPass && pass != "" {
		return errors.New("a password needs a username")
	}
	if user != "" {
		if hasPass {
			u.User = url.UserPassword(user, pass)
		} else {
			u.User = url.User(user)
		}
	}
	if (u.Scheme == "socks5" || u.Scheme == "socks5h") && (len(user) > 255 || len(pass) > 255) {
		return errors.New("SOCKS5 usernames and passwords are limited to 255 bytes")
	}
	p.Parsed = u
	p.Scheme = u.Scheme
	p.Host = u.Hostname()
	p.Port = u.Port()
	return nil
}

func (t Thresholds) check(where string) error {
	var errs []string
	if t.FailureThreshold < 1 || t.FailureThreshold > 100 {
		errs = append(errs, "failure_threshold must be between 1 and 100")
	}
	if t.RecoveryThreshold < 1 || t.RecoveryThreshold > 100 {
		errs = append(errs, "recovery_threshold must be between 1 and 100")
	}
	if t.LatencySamples < 1 || t.LatencySamples > 100 {
		errs = append(errs, "latency_samples must be between 1 and 100")
	}
	if t.Availability <= 0 || t.Availability > 100 {
		errs = append(errs, "availability must be a percentage above 0 and at most 100")
	}
	if t.AvailabilityWindow.D() < time.Minute || t.AvailabilityWindow.D() > 7*24*time.Hour {
		errs = append(errs, "availability_window must be between 1m and 7d")
	}
	if t.AvailabilityMinChecks < 1 {
		errs = append(errs, "availability_min_checks must be at least 1")
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %s", where, strings.Join(errs, "; "))
}

func (t Thresholds) merge(o *ThresholdOverrides) Thresholds {
	if o == nil {
		return t
	}
	if o.FailureThreshold != 0 {
		t.FailureThreshold = o.FailureThreshold
	}
	if o.RecoveryThreshold != 0 {
		t.RecoveryThreshold = o.RecoveryThreshold
	}
	if o.Latency != 0 {
		t.Latency = o.Latency
	}
	if o.LatencySamples != 0 {
		t.LatencySamples = o.LatencySamples
	}
	if o.Availability != 0 {
		t.Availability = o.Availability
	}
	if o.AvailabilityWindow != 0 {
		t.AvailabilityWindow = o.AvailabilityWindow
	}
	if o.AvailabilityMinChecks != 0 {
		t.AvailabilityMinChecks = o.AvailabilityMinChecks
	}
	return t
}

func (c *Config) validateAlerts(add func(string, ...any)) {
	a := &c.Alerts
	if a.MaxPerMinute < 1 || a.MaxPerMinute > 1000 {
		add("alerts.max_per_minute must be between 1 and 1000")
	}
	if a.RepeatInterval != 0 && a.RepeatInterval.D() < 5*time.Minute {
		add("alerts.repeat_interval must be 0 (off) or at least 5m")
	}
	checkEvents := func(where string, evs []string) {
		for _, e := range evs {
			ok := false
			for _, n := range EventNames {
				if e == n {
					ok = true
				}
			}
			if !ok {
				add("%s: unknown event %q (known: %s)", where, e, strings.Join(EventNames, ", "))
			}
		}
	}
	for i, w := range a.Webhooks {
		where := fmt.Sprintf("alerts.webhooks[%d]", i)
		u, err := url.Parse(w.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			add("%s: url must be an http:// or https:// URL", where)
		}
		if w.Name == "" {
			w.Name = fmt.Sprintf("webhook-%d", i+1)
		}
		checkEvents(where, w.Events)
	}
	if e := a.Email; e != nil {
		if e.Host == "" || e.From == "" || len(e.To) == 0 {
			add("alerts.email: host, from and to are required")
		}
		switch e.TLS {
		case "starttls", "tls":
		case "none":
			if !IsLoopbackHost(e.Host) {
				add("alerts.email: tls none is allowed only for an SMTP relay on localhost")
			}
		default:
			add("alerts.email: tls must be starttls, tls or none")
		}
		checkEvents("alerts.email", e.Events)
	}
	if t := a.Telegram; t != nil {
		if t.BotToken == "" || t.ChatID == "" {
			add("alerts.telegram: bot_token and chat_id are required")
		}
		checkEvents("alerts.telegram", t.Events)
	}
	for i, d := range a.Discord {
		where := fmt.Sprintf("alerts.discord[%d]", i)
		if !strings.HasPrefix(d.WebhookURL, "https://") {
			add("%s: webhook_url must be an https:// URL", where)
		}
		if d.Name == "" {
			d.Name = fmt.Sprintf("discord-%d", i+1)
		}
		checkEvents(where, d.Events)
	}
}

// registerSecrets hands every credential to the redactor.
func (c *Config) registerSecrets() {
	redact.Register(c.Server.AuthToken)
	for _, p := range c.Proxies {
		redact.Register(p.Password)
		if p.Parsed != nil && p.Parsed.User != nil {
			pw, _ := p.Parsed.User.Password()
			redact.Register(p.Parsed.User.Username(), pw)
		}
	}
	for _, t := range c.Targets {
		for k, v := range t.Headers {
			if isSensitiveHeader(k) {
				redact.Register(v)
			}
		}
	}
	for _, w := range c.Alerts.Webhooks {
		redact.Register(w.Secret, w.URL)
		for k, v := range w.Headers {
			if isSensitiveHeader(k) {
				redact.Register(v)
			}
		}
	}
	if e := c.Alerts.Email; e != nil {
		redact.Register(e.Password)
	}
	if t := c.Alerts.Telegram; t != nil {
		redact.Register(t.BotToken)
	}
	for _, d := range c.Alerts.Discord {
		redact.Register(d.WebhookURL)
	}
}

func isSensitiveHeader(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "auth") || strings.Contains(k, "token") || strings.Contains(k, "key") || strings.Contains(k, "secret") || strings.Contains(k, "cookie")
}

// IsLoopbackHost reports whether host is localhost or a loopback address.
// An empty host (listen on every interface) is not loopback.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func resolvePath(base, p string) string {
	if filepath.IsAbs(p) || base == "" {
		return p
	}
	return filepath.Join(base, p)
}

func loadCAFile(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no PEM certificates found")
	}
	return pool, nil
}

// EnabledProxies returns the proxies that are not disabled.
func (c *Config) EnabledProxies() []*Proxy {
	var out []*Proxy
	for _, p := range c.Proxies {
		if !p.Disabled {
			out = append(out, p)
		}
	}
	return out
}

// ProxyByName finds a proxy.
func (c *Config) ProxyByName(name string) *Proxy {
	for _, p := range c.Proxies {
		if p.Name == name {
			return p
		}
	}
	return nil
}
