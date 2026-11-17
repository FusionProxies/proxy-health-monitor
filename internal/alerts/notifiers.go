package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

// Build creates the notifiers configured in cfg.
func Build(cfg config.Alerts, log *slog.Logger, userAgent string) []Notifier {
	client := &http.Client{Timeout: 15 * time.Second}
	var out []Notifier
	if cfg.ConsoleEnabled() {
		out = append(out, &Console{Log: log})
	}
	for _, w := range cfg.Webhooks {
		out = append(out, &Webhook{Cfg: w, Client: client, UserAgent: userAgent})
	}
	if cfg.Email != nil {
		out = append(out, &Email{Cfg: cfg.Email})
	}
	if cfg.Telegram != nil {
		out = append(out, &Telegram{Cfg: cfg.Telegram, Client: client})
	}
	for _, d := range cfg.Discord {
		out = append(out, &Discord{Cfg: d, Client: client, UserAgent: userAgent})
	}
	return out
}

func accepts(filter []string, k health.Kind) bool {
	if len(filter) == 0 {
		return true
	}
	for _, f := range filter {
		if f == string(k) {
			return true
		}
	}
	return false
}

// Console writes alerts to the log.
type Console struct{ Log *slog.Logger }

func (c *Console) Name() string             { return "console" }
func (c *Console) Accepts(health.Kind) bool { return true }
func (c *Console) Send(_ context.Context, a Alert) error {
	level := slog.LevelInfo
	if a.Severity != SevInfo {
		level = slog.LevelWarn
	}
	c.Log.Log(context.Background(), level, "ALERT "+a.Title, "message", a.Message, "incident", a.IncidentID)
	return nil
}

// Webhook posts the alert as JSON. With a secret, the body is signed:
//
//	X-Proxy-Monitor-Timestamp: <unix seconds>
//	X-Proxy-Monitor-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">
type Webhook struct {
	Cfg       *config.Webhook
	Client    *http.Client
	UserAgent string
	now       func() time.Time
}

func (w *Webhook) Name() string               { return "webhook:" + w.Cfg.Name }
func (w *Webhook) Accepts(k health.Kind) bool { return accepts(w.Cfg.Events, k) }

// WebhookPayload is the JSON body of a webhook alert.
type WebhookPayload struct {
	Event               string            `json:"event"`
	Severity            string            `json:"severity"`
	Proxy               string            `json:"proxy,omitempty"`
	Protocol            string            `json:"protocol,omitempty"`
	ProxyURL            string            `json:"proxy_url,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
	Time                time.Time         `json:"time"`
	IncidentID          int64             `json:"incident_id,omitempty"`
	Title               string            `json:"title"`
	Message             string            `json:"message"`
	ErrorClass          string            `json:"error_class,omitempty"`
	Error               string            `json:"error,omitempty"`
	ConsecutiveFailures int               `json:"consecutive_failures,omitempty"`
	DurationSeconds     float64           `json:"duration_seconds,omitempty"`
	LatencyMS           float64           `json:"latency_ms,omitempty"`
	Availability        float64           `json:"availability,omitempty"`
	Source              string            `json:"source"`
}

// Payload converts an alert to the webhook body.
func Payload(a Alert) WebhookPayload {
	return WebhookPayload{
		Event: string(a.Kind), Severity: a.Severity, Proxy: a.Proxy, Protocol: a.Protocol, ProxyURL: a.ProxyURL,
		Labels: a.Labels, Time: a.Time.UTC(), IncidentID: a.IncidentID, Title: a.Title, Message: a.Message,
		ErrorClass: a.ErrorClass, Error: a.Error, ConsecutiveFailures: a.ConsecutiveFailures,
		DurationSeconds: a.Duration.Seconds(), LatencyMS: a.LatencyMS, Availability: a.Availability,
		Source: "proxy-health-monitor",
	}
}

// Sign returns the signature header value for body.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (w *Webhook) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal(Payload(a))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.Cfg.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", w.UserAgent)
	for k, v := range w.Cfg.Headers {
		req.Header.Set(k, v)
	}
	if w.Cfg.Secret != "" {
		now := time.Now
		if w.now != nil {
			now = w.now
		}
		ts := strconv.FormatInt(now().Unix(), 10)
		req.Header.Set("X-Proxy-Monitor-Timestamp", ts)
		req.Header.Set("X-Proxy-Monitor-Signature", Sign(w.Cfg.Secret, ts, body))
	}
	return doPost(w.Client, req)
}

func doPost(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return errors.New(redact.Error(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Telegram sends alerts through the Bot API.
type Telegram struct {
	Cfg    *config.Telegram
	Client *http.Client
}

func (t *Telegram) Name() string               { return "telegram" }
func (t *Telegram) Accepts(k health.Kind) bool { return accepts(t.Cfg.Events, k) }

func (t *Telegram) Send(ctx context.Context, a Alert) error {
	text := a.Title + "\n" + a.Text
	if len(text) > 4000 {
		text = text[:4000]
	}
	body, _ := json.Marshal(map[string]any{"chat_id": t.Cfg.ChatID, "text": text, "disable_web_page_preview": true})
	u := strings.TrimRight(t.Cfg.APIURL, "/") + "/bot" + t.Cfg.BotToken + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid Telegram API URL")
	}
	req.Header.Set("Content-Type", "application/json")
	return doPost(t.Client, req)
}

// Discord posts alerts to a channel webhook.
type Discord struct {
	Cfg       *config.Discord
	Client    *http.Client
	UserAgent string
}

func (d *Discord) Name() string               { return "discord:" + d.Cfg.Name }
func (d *Discord) Accepts(k health.Kind) bool { return accepts(d.Cfg.Events, k) }

func (d *Discord) Send(ctx context.Context, a Alert) error {
	content := "**" + a.Title + "**\n" + a.Text
	if len(content) > 1900 {
		content = content[:1900]
	}
	body, _ := json.Marshal(map[string]any{"content": content, "allowed_mentions": map[string]any{"parse": []string{}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid Discord webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", d.UserAgent)
	return doPost(d.Client, req)
}

// Email sends alerts over SMTP with STARTTLS, implicit TLS, or (localhost
// only) no TLS.
type Email struct {
	Cfg *config.Email
	// tlsConfig is replaced in tests.
	tlsConfig *tls.Config
}

func (e *Email) Name() string               { return "email" }
func (e *Email) Accepts(k health.Kind) bool { return accepts(e.Cfg.Events, k) }

func (e *Email) Send(ctx context.Context, a Alert) error {
	c := e.Cfg
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tcfg := e.tlsConfig
	if tcfg == nil {
		tcfg = &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if c.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tcfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP connect: %s", redact.Error(err))
	}
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP: %s", redact.Error(err))
	}
	defer cl.Close()
	if c.TLS == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not offer STARTTLS; set tls: tls for port 465")
		}
		if err := cl.StartTLS(tcfg); err != nil {
			return fmt.Errorf("STARTTLS: %s", redact.Error(err))
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("SMTP auth: %s", redact.Error(err))
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %s", redact.Error(err))
	}
	for _, to := range c.To {
		if err := cl.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO %s: %s", to, redact.Error(err))
		}
	}
	wc, err := cl.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %s", redact.Error(err))
	}
	if _, err := wc.Write(buildMessage(c, a)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("SMTP: %s", redact.Error(err))
	}
	return cl.Quit()
}

func buildMessage(c *config.Email, a Alert) []byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	host := c.From
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace("[proxy-monitor] " + a.Title)
	var b strings.Builder
	b.WriteString("From: " + c.From + "\r\n")
	b.WriteString("To: " + strings.Join(c.To, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + hex.EncodeToString(id[:]) + "@" + host + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	text := strings.ReplaceAll(a.Text, "\r\n", "\n")
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		b.WriteString(line + "\r\n")
	}
	b.WriteString("\r\n-- \r\nproxy-health-monitor\r\n")
	return []byte(b.String())
}
