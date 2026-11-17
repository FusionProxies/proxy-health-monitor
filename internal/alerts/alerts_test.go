package alerts

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/health"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
	"github.com/FusionProxies/proxy-health-monitor/internal/storage"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeNotifier struct {
	mu   sync.Mutex
	got  []Alert
	only []string
}

func (f *fakeNotifier) Name() string { return "fake" }
func (f *fakeNotifier) Accepts(k health.Kind) bool {
	return accepts(f.only, k)
}
func (f *fakeNotifier) Send(_ context.Context, a Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, a)
	return nil
}
func (f *fakeNotifier) titles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.got {
		out = append(out, a.Title)
	}
	return out
}

type fakeRecorder struct {
	mu   sync.Mutex
	recs []storage.AlertRecord
}

func (r *fakeRecorder) RecordAlert(a storage.AlertRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, a)
	return nil
}

func (r *fakeRecorder) count(status string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, x := range r.recs {
		if x.Status == status {
			n++
		}
	}
	return n
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newManager(cfg config.Alerts, n Notifier) (*Manager, *fakeRecorder, *clock) {
	if cfg.Cooldown == 0 {
		cfg.Cooldown = config.Duration(10 * time.Minute)
	}
	if cfg.MaxPerMinute == 0 {
		cfg.MaxPerMinute = 20
	}
	rec := &fakeRecorder{}
	m := NewManager(cfg, nil, []Notifier{n}, rec, quiet)
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	m.SetClock(c.now)
	return m, rec, c
}

func ev(kind health.Kind, proxy string, id int64, at time.Time) health.Event {
	return health.Event{Kind: kind, Proxy: proxy, IncidentID: id, Time: at, Message: string(kind)}
}

func TestDeduplication(t *testing.T) {
	n := &fakeNotifier{}
	m, rec, c := newManager(config.Alerts{}, n)
	m.Handle(ev(health.EvDown, "a", 1, c.t))
	m.Handle(ev(health.EvDown, "a", 1, c.t)) // same incident, same kind
	m.DeliverPending(context.Background())
	if len(n.got) != 1 || rec.count("suppressed") != 1 {
		t.Fatalf("sent %v, suppressed %d", n.titles(), rec.count("suppressed"))
	}
}

func TestCooldownSuppressesFlappingPairs(t *testing.T) {
	n := &fakeNotifier{}
	m, _, c := newManager(config.Alerts{}, n)
	m.Handle(ev(health.EvDown, "a", 1, c.t))
	c.add(time.Minute)
	m.Handle(ev(health.EvRecovered, "a", 1, c.t))
	c.add(time.Minute)
	m.Handle(ev(health.EvDown, "a", 2, c.t)) // within cooldown: suppressed
	c.add(time.Minute)
	m.Handle(ev(health.EvRecovered, "a", 2, c.t)) // its pair: suppressed too
	m.Handle(ev(health.EvDown, "b", 3, c.t))      // another proxy: not affected
	c.add(10 * time.Minute)
	m.Handle(ev(health.EvDown, "a", 4, c.t)) // cooldown over
	m.DeliverPending(context.Background())
	want := []string{"[DOWN] a", "[RECOVERED] a", "[DOWN] b", "[DOWN] a"}
	if got := n.titles(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCooldownIsPerKind(t *testing.T) {
	n := &fakeNotifier{}
	m, _, c := newManager(config.Alerts{}, n)
	m.Handle(ev(health.EvLatency, "a", 1, c.t))
	m.Handle(ev(health.EvDown, "a", 2, c.t))
	m.DeliverPending(context.Background())
	if len(n.got) != 2 {
		t.Fatalf("latency and down are separate kinds: %v", n.titles())
	}
}

func TestRateLimitAndSummary(t *testing.T) {
	n := &fakeNotifier{}
	m, rec, c := newManager(config.Alerts{MaxPerMinute: 3}, n)
	for i := 0; i < 8; i++ {
		m.Handle(ev(health.EvDown, "p"+strconv.Itoa(i), int64(i+1), c.t))
	}
	m.DeliverPending(context.Background())
	if len(n.got) != 3 || rec.count("suppressed") != 5 {
		t.Fatalf("sent %d suppressed %d", len(n.got), rec.count("suppressed"))
	}
	m.flushSummary() // same minute: nothing yet
	if m.Pending() != 0 {
		t.Fatal("summary sent before the minute ended")
	}
	c.add(61 * time.Second)
	m.flushSummary()
	m.DeliverPending(context.Background())
	last := n.got[len(n.got)-1]
	if !last.Summary || !strings.Contains(last.Message, "5 alerts were not sent") || !strings.Contains(last.Message, "p7") {
		t.Fatalf("summary %+v", last)
	}
	// A new minute has a fresh budget.
	m.Handle(ev(health.EvDown, "z", 99, c.t))
	m.DeliverPending(context.Background())
	if n.got[len(n.got)-1].Title != "[DOWN] z" {
		t.Fatal("budget not reset")
	}
}

func TestEventFilter(t *testing.T) {
	n := &fakeNotifier{only: []string{"down"}}
	m, rec, c := newManager(config.Alerts{}, n)
	m.Handle(ev(health.EvLatency, "a", 1, c.t))
	m.Handle(ev(health.EvDown, "a", 2, c.t))
	m.DeliverPending(context.Background())
	if len(n.got) != 1 || n.got[0].Kind != health.EvDown {
		t.Fatalf("filter: %v", n.titles())
	}
	if rec.count("suppressed") != 1 { // the latency alert had no accepting channel
		t.Fatalf("records %+v", rec.recs)
	}
}

func TestRestoreKeepsCooldown(t *testing.T) {
	n := &fakeNotifier{}
	m, _, c := newManager(config.Alerts{}, n)
	m.Restore(map[[2]string]time.Time{{"a", "down"}: c.t.Add(-time.Minute)})
	m.Handle(ev(health.EvDown, "a", 5, c.t))
	m.DeliverPending(context.Background())
	if len(n.got) != 0 {
		t.Fatal("cooldown from before the restart must apply")
	}
}

func TestAlertTextIsRedacted(t *testing.T) {
	defer redact.Reset()
	redact.Register("SuperSecretPassword1")
	n := &fakeNotifier{}
	m, _, c := newManager(config.Alerts{}, n)
	e := ev(health.EvDown, "a", 1, c.t)
	e.Message = "auth failed for http://user:SuperSecretPassword1@proxy:1"
	e.Error = "SuperSecretPassword1 rejected"
	m.Handle(e)
	m.DeliverPending(context.Background())
	a := n.got[0]
	if strings.Contains(a.Text+a.Message+a.Error, "SuperSecret") {
		t.Fatalf("secret in alert: %+v", a)
	}
}

func TestWebhookSignature(t *testing.T) {
	var gotBody []byte
	var gotSig, gotTS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Proxy-Monitor-Signature")
		gotTS = r.Header.Get("X-Proxy-Monitor-Timestamp")
		if r.Header.Get("X-Custom") != "yes" {
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	w := &Webhook{Cfg: &config.Webhook{Name: "t", URL: srv.URL, Secret: "shh-secret", Headers: map[string]string{"X-Custom": "yes"}}, Client: srv.Client(), UserAgent: "test"}
	a := Alert{Event: health.Event{Kind: health.EvDown, Proxy: "a", IncidentID: 3, Time: time.Now(), Message: "down"}, Severity: SevCritical, Title: "[DOWN] a"}
	if err := w.Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if gotSig != Sign("shh-secret", gotTS, gotBody) {
		t.Fatal("signature does not verify")
	}
	var p WebhookPayload
	if err := json.Unmarshal(gotBody, &p); err != nil || p.Event != "down" || p.IncidentID != 3 || p.Source != "proxy-health-monitor" {
		t.Fatalf("payload %+v %v", p, err)
	}
}

func TestWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	w := &Webhook{Cfg: &config.Webhook{URL: srv.URL}, Client: srv.Client()}
	if err := w.Send(context.Background(), Alert{}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("got %v", err)
	}
}

func TestTelegramAndDiscord(t *testing.T) {
	var paths []string
	var bodies []map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		bodies = append(bodies, m)
		mu.Unlock()
	}))
	defer srv.Close()
	a := Alert{Event: health.Event{Kind: health.EvRecovered, Proxy: "a"}, Title: "[RECOVERED] a", Text: "a: back"}
	tg := &Telegram{Cfg: &config.Telegram{BotToken: "123:tok", ChatID: "-100", APIURL: srv.URL}, Client: srv.Client()}
	if err := tg.Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	dc := &Discord{Cfg: &config.Discord{Name: "d", WebhookURL: srv.URL + "/api/webhooks/1/x"}, Client: srv.Client()}
	if err := dc.Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/bot123:tok/sendMessage" || bodies[0]["chat_id"] != "-100" || !strings.Contains(bodies[0]["text"].(string), "RECOVERED") {
		t.Fatalf("telegram request %v %v", paths[0], bodies[0])
	}
	if !strings.Contains(bodies[1]["content"].(string), "**[RECOVERED] a**") {
		t.Fatalf("discord body %v", bodies[1])
	}
	if am, ok := bodies[1]["allowed_mentions"].(map[string]any); !ok || len(am["parse"].([]any)) != 0 {
		t.Fatalf("discord must not ping anyone: %v", bodies[1])
	}
}

// fakeSMTP is a minimal SMTP server: enough for net/smtp without TLS.
func fakeSMTP(t *testing.T) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
		say("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					say("250 queued")
					got <- data.String()
					continue
				}
				data.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				say("250 ok")
			case cmd == "DATA":
				inData = true
				say("354 go")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestEmail(t *testing.T) {
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	e := &Email{Cfg: &config.Email{Host: host, Port: p, TLS: "none", From: "mon@example.com", To: []string{"ops@example.com"}}}
	a := Alert{Event: health.Event{Kind: health.EvDown, Proxy: "a"}, Title: "[DOWN] a", Text: "a: down\n.leading dot"}
	if err := e.Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	for _, want := range []string{"Subject: [proxy-monitor] [DOWN] a", "To: ops@example.com", "a: down", "..leading dot"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message lacks %q:\n%s", want, msg)
		}
	}
}

func TestEmailStartTLSRequired(t *testing.T) {
	addr, _ := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	e := &Email{Cfg: &config.Email{Host: host, Port: p, TLS: "starttls", From: "a@b.c", To: []string{"d@e.f"}}}
	if err := e.Send(context.Background(), Alert{}); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("must refuse to send without STARTTLS, got %v", err)
	}
}
