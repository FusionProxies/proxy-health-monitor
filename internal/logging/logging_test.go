package logging

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

func TestLogsAreRedacted(t *testing.T) {
	defer redact.Reset()
	redact.Register("log-secret-value")
	for _, format := range []string{"text", "json"} {
		var buf bytes.Buffer
		log, err := New(&buf, "debug", format)
		if err != nil {
			t.Fatal(err)
		}
		log.With("url", "http://bob:pw123456@proxy.example:8080").Info("check log-secret-value failed",
			"err", errors.New("auth log-secret-value rejected"),
			"detail", "socks5h://alice:hunter22@10.0.0.1:1080",
			"group", map[string]string{"k": "log-secret-value"})
		out := buf.String()
		for _, leak := range []string{"log-secret-value", "pw123456", "hunter22"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s log leaks %q: %s", format, leak, out)
			}
		}
	}
}

func TestBadOptions(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, "loud", "text"); err == nil {
		t.Fatal("unknown level accepted")
	}
	if _, err := New(&bytes.Buffer{}, "info", "xml"); err == nil {
		t.Fatal("unknown format accepted")
	}
}
