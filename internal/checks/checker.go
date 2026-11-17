package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

// Resolver looks up host names. *net.Resolver satisfies it; tests use fakes.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DialFunc opens a TCP connection.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Checker runs checks. The zero value is not usable; call New.
type Checker struct {
	Resolver  Resolver
	Dial      DialFunc
	UserAgent string
}

// New returns a Checker that uses the system resolver and dialer.
func New(userAgent string) *Checker {
	d := &net.Dialer{KeepAlive: -1}
	return &Checker{Resolver: net.DefaultResolver, Dial: d.DialContext, UserAgent: userAgent}
}

// Check runs one check of p against its target. It never panics on network
// input and always returns within p.Timeout (plus a few milliseconds).
func (c *Checker) Check(parent context.Context, p *config.Proxy) Result {
	start := time.Now()
	res := Result{Proxy: p.Name, Time: start}
	t := p.TargetRef
	ctx, cancel := context.WithTimeout(parent, p.Timeout.D())
	defer cancel()

	var mc *meteredConn
	finish := func(err error, phase string) Result {
		res.Total = time.Since(start)
		if mc != nil {
			res.BytesIn, res.BytesOut = mc.in.Load(), mc.out.Load()
		}
		if err == nil {
			res.OK = true
			return res
		}
		ce := classify(ctx, phase, p.Timeout.D(), err)
		msg := ce.msg
		// Silence during a handshake usually means the port speaks another
		// protocol (an HTTP proxy checked as SOCKS5, or the other way round).
		if mc != nil && mc.in.Load() == 0 && (ce.class == ClassTimeout || ce.class == ClassConnect) &&
			(phase == "the SOCKS5 handshake" || phase == "the CONNECT handshake") {
			msg += "; the proxy sent nothing back: it may be overloaded, or this port may not speak " + map[bool]string{true: "SOCKS5", false: "HTTP"}[p.IsSOCKS()]
		}
		res.Class = ce.class
		res.Error = redact.String(msg)
		return res
	}

	// 1. Resolve the proxy host.
	phase := "the DNS lookup of the proxy host " + p.Host
	t0 := time.Now()
	ips, err := c.resolve(ctx, p.Host)
	res.DNS = time.Since(t0)
	if err != nil {
		return finish(err, phase)
	}

	// 2. TCP connect.
	phase = "the TCP connect to the proxy"
	t0 = time.Now()
	raw, err := c.dialAny(ctx, ips, p.Port)
	res.Connect = time.Since(t0)
	if err != nil {
		return finish(err, phase)
	}
	mc = &meteredConn{Conn: raw}
	defer mc.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = mc.SetDeadline(dl)
	}
	// Unblock any read or write the moment the context ends.
	stop := context.AfterFunc(ctx, func() { _ = mc.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	var conn net.Conn = mc
	user, pass, hasUser := credentials(p.Parsed)
	targetHost := t.Parsed.Hostname()
	targetPort := portOf(t.Parsed)

	// 3. Proxy handshake (TLS to an https:// proxy, then CONNECT or SOCKS5).
	t0 = time.Now()
	if p.Scheme == "https" {
		phase = "the TLS handshake with the proxy"
		tc := tls.Client(conn, &tls.Config{
			ServerName:         p.Host,
			RootCAs:            p.RootCAs,
			InsecureSkipVerify: p.InsecureSkipVerify, //nolint:gosec // explicit opt-in per proxy
			MinVersion:         tls.VersionTLS12,
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			res.Handshake = time.Since(t0)
			return finish(tlsError("the proxy", err), phase)
		}
		conn = tc
	}
	switch {
	case p.IsSOCKS():
		phase = "the SOCKS5 handshake"
		host := targetHost
		if p.Scheme == "socks5" && net.ParseIP(targetHost) == nil {
			// socks5:// resolves the target here; socks5h:// sends the name.
			t1 := time.Now()
			tips, err := c.resolve(ctx, targetHost)
			res.DNS += time.Since(t1)
			if err != nil {
				return finish(err, "the local DNS lookup of the target "+targetHost+" (socks5:// resolves on this machine, socks5h:// on the proxy)")
			}
			host = tips[0].IP.String()
		}
		if err := socks5Connect(conn, user, pass, hasUser, host, targetPort); err != nil {
			res.Handshake = time.Since(t0)
			return finish(err, phase)
		}
	case p.Mode == config.ModeConnect:
		phase = "the CONNECT handshake"
		tunnel, err := httpConnect(conn, net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), user, pass, hasUser, c.UserAgent)
		if err != nil {
			res.Handshake = time.Since(t0)
			return finish(err, phase)
		}
		conn = tunnel
	}
	if p.IsSOCKS() || p.Mode == config.ModeConnect || p.Scheme == "https" {
		res.Handshake = time.Since(t0)
	}

	// 4. TLS with the target, through the tunnel.
	tunneled := p.IsSOCKS() || p.Mode == config.ModeConnect
	if tunneled && t.Parsed.Scheme == "https" {
		phase = "the TLS handshake with the target"
		t0 = time.Now()
		tc := tls.Client(conn, &tls.Config{
			ServerName:         targetHost,
			RootCAs:            t.RootCAs,
			InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // explicit opt-in per target
			MinVersion:         tls.VersionTLS12,
		})
		err := tc.HandshakeContext(ctx)
		res.TLS = time.Since(t0)
		if err != nil {
			return finish(tlsError("the target", err), phase)
		}
		conn = tc
	}
	if t.Check == config.CheckTunnel {
		return finish(nil, "")
	}

	// 5. One request, one response.
	phase = "the request"
	req, err := c.buildRequest(t, p, hasUser, user, pass, tunneled)
	if err != nil {
		return finish(fail(ClassProtocol, "building the request: %v", err), phase)
	}
	if tunneled {
		err = req.Write(conn)
	} else {
		err = req.WriteProxy(conn)
	}
	if err != nil {
		return finish(err, phase)
	}
	sent := time.Now()
	phase = "the wait for the response"
	fb := &firstByteReader{r: conn}
	br := bufio.NewReader(fb)
	if !tunneled {
		if b, err := br.Peek(1); err == nil && b[0] == 0x05 {
			return finish(fail(ClassProtocol, "the proxy answered with SOCKS5 bytes: use a socks5:// URL"), phase)
		}
	}
	resp, err := http.ReadResponse(br, req)
	if !fb.first.IsZero() {
		res.TTFB = fb.first.Sub(sent)
	}
	if err != nil {
		if !fb.first.IsZero() && isMalformed(err) {
			return finish(fail(ClassProtocol, "the answer is not HTTP: %s", shortErr(err)), phase)
		}
		return finish(err, phase)
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode
	if !tunneled && resp.StatusCode == http.StatusProxyAuthRequired {
		return finish(authError(hasUser, resp), phase)
	}

	phase = "the response body"
	var body []byte
	if t.Method != http.MethodHead && t.MaxBodyBytes > 0 {
		body, err = io.ReadAll(io.LimitReader(resp.Body, t.MaxBodyBytes))
		if err != nil {
			return finish(err, phase)
		}
	}
	if !statusExpected(resp.StatusCode, t.ExpectStatus) {
		hint := ""
		if !tunneled && (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) {
			hint = " (in forward mode the proxy itself may have produced it)"
		}
		return finish(fail(ClassStatus, "the target answered HTTP %d, expected %s%s", resp.StatusCode, joinInts(t.ExpectStatus), hint), phase)
	}
	if t.ExpectBody != "" && !bytes.Contains(body, []byte(t.ExpectBody)) {
		return finish(fail(ClassBody, "the response body (first %d bytes) does not contain the expected text", len(body)), phase)
	}
	return finish(nil, "")
}

func (c *Checker) resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	ips, err := c.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	return ips, nil
}

// dialAny tries each address in turn until one connects.
func (c *Checker) dialAny(ctx context.Context, ips []net.IPAddr, port string) (net.Conn, error) {
	var last error
	for _, ip := range ips {
		conn, err := c.Dial(ctx, "tcp", net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (c *Checker) buildRequest(t *config.Target, p *config.Proxy, hasUser bool, user, pass string, tunneled bool) (*http.Request, error) {
	req, err := http.NewRequest(t.Method, t.Parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range t.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Close = true
	if !tunneled && hasUser {
		req.Header.Set("Proxy-Authorization", basicAuth(user, pass))
	}
	return req, nil
}

// httpConnect asks an HTTP proxy for a tunnel to hostport.
func httpConnect(conn net.Conn, hostport, user, pass string, hasUser bool, ua string) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: hostport},
		Host:   hostport,
		Header: http.Header{"User-Agent": {ua}},
	}
	if hasUser {
		req.Header.Set("Proxy-Authorization", basicAuth(user, pass))
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	if b, err := br.Peek(1); err == nil && b[0] == 0x05 {
		return nil, fail(ClassProtocol, "the proxy answered with SOCKS5 bytes: use a socks5:// URL")
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		if isMalformed(err) {
			return nil, fail(ClassProtocol, "the proxy's answer to CONNECT is not HTTP: %s", shortErr(err))
		}
		return nil, err
	}
	_ = resp.Body.Close()
	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
	case code == http.StatusProxyAuthRequired:
		return nil, authError(hasUser, resp)
	case code == http.StatusForbidden || code == http.StatusMethodNotAllowed:
		return nil, fail(ClassRejected, "the proxy refused CONNECT with HTTP %d", code)
	case code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout:
		return nil, fail(ClassUpstream, "the proxy could not reach the target (HTTP %d to CONNECT)", code)
	default:
		return nil, fail(ClassProxyError, "the proxy answered CONNECT with HTTP %d", code)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

func authError(hasUser bool, resp *http.Response) error {
	if !hasUser {
		return fail(ClassAuth, "the proxy requires authentication (HTTP 407), but no username is configured")
	}
	scheme := resp.Header.Get("Proxy-Authenticate")
	if scheme != "" && !strings.HasPrefix(strings.ToLower(scheme), "basic") {
		return fail(ClassAuth, "the proxy rejected the credentials (HTTP 407) and asks for %q authentication; only Basic is supported", strings.Fields(scheme)[0])
	}
	return fail(ClassAuth, "the proxy rejected the username or password (HTTP 407)")
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func credentials(u *url.URL) (user, pass string, ok bool) {
	if u == nil || u.User == nil || u.User.Username() == "" {
		return "", "", false
	}
	pass, _ = u.User.Password()
	return u.User.Username(), pass, true
}

func portOf(u *url.URL) int {
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return p
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func statusExpected(code int, want []int) bool {
	for _, w := range want {
		if code == w {
			return true
		}
	}
	return false
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, " or ")
}

func tlsError(who string, err error) error {
	var ce *checkError
	if errors.As(err, &ce) {
		return err
	}
	if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, io.EOF) {
		return fail(ClassTLS, "TLS with %s failed: the connection closed during the handshake", who)
	}
	msg := err.Error()
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		msg = "certificate verification failed: " + certErr.Err.Error()
	}
	return fail(ClassTLS, "TLS with %s failed: %s", who, msg)
}

// classify turns any error into a class and a message that names the phase.
func classify(ctx context.Context, phase string, timeout time.Duration, err error) *checkError {
	var ce *checkError
	if errors.As(err, &ce) {
		return ce
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return fail(ClassCanceled, "canceled during %s", phase)
	}
	if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fail(ClassTimeout, "no answer within %s during %s", config.FormatDuration(timeout), phase)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		why := "lookup failed"
		switch {
		case dnsErr.IsNotFound:
			why = "no such host"
		case dnsErr.IsTemporary:
			why = "temporary DNS failure"
		}
		return fail(ClassDNS, "%s failed: %s", phase, why)
	}
	if isRefused(err) {
		return fail(ClassRefused, "the proxy refused the connection (nothing is listening on that port)")
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isReset(err) {
		return fail(ClassConnect, "the proxy closed the connection during %s", phase)
	}
	return fail(ClassConnect, "%s failed: %s", phase, shortErr(err))
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// Windows reports WSAECONNREFUSED (10061), which is not syscall.ECONNREFUSED.
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == 10061 {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

func isReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == 10054 || errno == 10053) { // WSAECONNRESET, WSAECONNABORTED
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "broken pipe")
}

func isMalformed(err error) bool {
	s := err.Error()
	return strings.Contains(s, "malformed HTTP") || strings.Contains(s, "malformed MIME")
}

// shortErr drops the Go-internal prefixes ("dial tcp 1.2.3.4:5: connectex: ")
// that make messages long without helping.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && strings.HasPrefix(s, "dial ") {
		s = s[i+2:]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// ErrorClassText describes a class for people, used by the CLI and dashboard.
func ErrorClassText(c Class) string {
	switch c {
	case ClassDNS:
		return "DNS lookup failed"
	case ClassRefused:
		return "connection refused"
	case ClassConnect:
		return "connection failed"
	case ClassTimeout:
		return "timeout"
	case ClassAuth:
		return "authentication failed"
	case ClassProtocol:
		return "protocol error"
	case ClassRejected:
		return "rejected by proxy"
	case ClassUpstream:
		return "proxy could not reach target"
	case ClassProxyError:
		return "proxy error"
	case ClassTLS:
		return "TLS error"
	case ClassStatus:
		return "unexpected HTTP status"
	case ClassBody:
		return "unexpected response body"
	case ClassCanceled:
		return "canceled"
	}
	return fmt.Sprint(c)
}
