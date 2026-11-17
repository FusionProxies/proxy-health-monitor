// Package checks runs one health check through one proxy: resolve the proxy
// host, connect, negotiate the proxy protocol (HTTP forward, HTTP CONNECT or
// SOCKS5 CONNECT), optionally complete TLS with the target, send one request
// and read the answer. Every phase is timed and every failure is classified.
package checks

import (
	"fmt"
	"time"
)

// Class is the kind of failure. An empty class means success.
type Class string

// Failure classes. They are stable: dashboards, alerts and Prometheus labels
// use them.
const (
	ClassDNS        Class = "dns_failure"          // the proxy host (or, for socks5://, the target) did not resolve
	ClassRefused    Class = "connection_refused"   // nothing listens on the proxy port
	ClassConnect    Class = "connection_failed"    // TCP failed (unreachable, reset, closed early)
	ClassTimeout    Class = "timeout"              // a phase did not finish within the timeout
	ClassAuth       Class = "auth_failed"          // the proxy rejected or required credentials
	ClassProtocol   Class = "protocol_error"       // the proxy did not speak the expected protocol
	ClassRejected   Class = "proxy_rejected"       // the proxy refused the request (policy, forbidden)
	ClassUpstream   Class = "upstream_unreachable" // the proxy could not reach the target
	ClassProxyError Class = "proxy_error"          // other proxy-side failure
	ClassTLS        Class = "tls_error"            // TLS with the proxy or the target failed
	ClassStatus     Class = "unexpected_status"    // the target answered with a status not in expect_status
	ClassBody       Class = "body_mismatch"        // the body did not contain expect_body
	ClassCanceled   Class = "canceled"             // the monitor is shutting down; not recorded
)

// AllClasses lists every failure class, for documentation and metrics.
var AllClasses = []Class{ClassDNS, ClassRefused, ClassConnect, ClassTimeout, ClassAuth, ClassProtocol, ClassRejected, ClassUpstream, ClassProxyError, ClassTLS, ClassStatus, ClassBody}

// Result is the outcome of one check. Durations are zero for phases that did
// not run.
type Result struct {
	Proxy      string        `json:"proxy"`
	Time       time.Time     `json:"time"`
	OK         bool          `json:"ok"`
	Class      Class         `json:"error_class,omitempty"`
	Error      string        `json:"error,omitempty"` // already redacted
	StatusCode int           `json:"status_code,omitempty"`
	DNS        time.Duration `json:"dns"`
	Connect    time.Duration `json:"connect"`
	Handshake  time.Duration `json:"proxy_handshake"`
	TLS        time.Duration `json:"tls"`
	TTFB       time.Duration `json:"ttfb"`
	Total      time.Duration `json:"total"`
	BytesIn    int64         `json:"bytes_in"`
	BytesOut   int64         `json:"bytes_out"`
}

// ConnectionLatency is the time until a usable tunnel or connection to the
// proxy existed: DNS, TCP connect and proxy handshake.
func (r Result) ConnectionLatency() time.Duration { return r.DNS + r.Connect + r.Handshake }

// Summary is a one-line description for logs and the CLI.
func (r Result) Summary() string {
	if r.OK {
		return fmt.Sprintf("ok in %s (connect %s, ttfb %s)", ms(r.Total), ms(r.ConnectionLatency()), ms(r.TTFB))
	}
	return fmt.Sprintf("%s: %s", r.Class, r.Error)
}

func ms(d time.Duration) string {
	if d == 0 {
		return "0ms"
	}
	if d < time.Millisecond {
		return "<1ms"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// checkError is a classified failure inside one phase.
type checkError struct {
	class Class
	msg   string
}

func (e *checkError) Error() string { return e.msg }

func fail(class Class, format string, a ...any) *checkError {
	return &checkError{class: class, msg: fmt.Sprintf(format, a...)}
}
