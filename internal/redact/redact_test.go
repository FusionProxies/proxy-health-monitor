package redact

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestRegisteredSecretsAreMasked(t *testing.T) {
	defer Reset()
	Register("hunter2-long-password", "customer-12345-country-us", "abc") // "abc" is too short to register
	in := `dial failed for customer-12345-country-us with hunter2-long-password (abc)`
	out := String(in)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "customer-12345") {
		t.Fatalf("secret left in %q", out)
	}
	if !strings.Contains(out, "(abc)") {
		t.Fatalf("short value must not be masked: %q", out)
	}
}

func TestEscapedSecretsAreMasked(t *testing.T) {
	defer Reset()
	Register("p@ss word/with:chars")
	for _, in := range []string{"p%40ss+word%2Fwith%3Achars", "p@ss%20word%2Fwith:chars", "p@ss word/with:chars"} {
		if out := String("x " + in + " y"); strings.Contains(out, "word") {
			t.Fatalf("encoded secret %q left in %q", in, out)
		}
	}
}

func TestURLCredentialsMaskedByPattern(t *testing.T) {
	defer Reset()
	cases := map[string]string{
		"proxyconnect tcp: http://alice-session-9:topsecret@proxy.example:8080 failed": "http://al***:***@proxy.example:8080",
		"socks5h://bob:pw@10.0.0.1:1080":                                               "socks5h://***:***@10.0.0.1:1080",
		"Authorization: Bearer abcdef0123456789":                                       "Bearer ***",
		"post https://api.telegram.org/bot123456:AAH-secret_token/sendMessage":         "/bot***/sendMessage",
	}
	for in, want := range cases {
		out := String(in)
		if !strings.Contains(out, want) {
			t.Errorf("String(%q) = %q, want it to contain %q", in, out, want)
		}
		for _, leak := range []string{"topsecret", ":pw@", "abcdef0123456789", "AAH-secret_token"} {
			if strings.Contains(out, leak) {
				t.Errorf("leak %q in %q", leak, out)
			}
		}
	}
}

func TestUsername(t *testing.T) {
	cases := map[string]string{"": "", "bob": "***", "abcd": "***", "customer-1": "cu***", "cu***": "cu***"}
	for in, want := range cases {
		if got := Username(in); got != want {
			t.Errorf("Username(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestURL(t *testing.T) {
	u, _ := url.Parse("socks5h://user-country-de:pa55@resi.example.com:5390")
	if got := URL(u); got != "socks5h://us***:***@resi.example.com:5390" {
		t.Fatalf("got %s", got)
	}
	u, _ = url.Parse("https://health.example.com/healthz?token=abc123&x=1#frag")
	got := URL(u)
	if strings.Contains(got, "abc123") || !strings.Contains(got, "token=***") || strings.Contains(got, "frag") {
		t.Fatalf("got %s", got)
	}
	u, _ = url.Parse("http://proxy.example:3128")
	if got := URL(u); got != "http://proxy.example:3128" {
		t.Fatalf("got %s", got)
	}
}

func TestError(t *testing.T) {
	defer Reset()
	Register("very-secret-token")
	if Error(nil) != "" {
		t.Fatal("nil error")
	}
	if got := Error(errors.New("token very-secret-token rejected")); strings.Contains(got, "very-secret") {
		t.Fatalf("got %q", got)
	}
}
