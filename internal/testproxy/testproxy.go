// Package testproxy runs small local HTTP (forward and CONNECT) and SOCKS5
// proxies with fault injection. The test suite and `proxy-monitor demo` use
// them, so neither needs a real proxy or the internet.
//
// They are test tools: they listen on loopback by default and only connect to
// the targets the client asks for.
package testproxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Faults changes how a proxy behaves. The zero value is a healthy proxy.
type Faults struct {
	Latency  time.Duration // delay before answering the handshake
	Jitter   time.Duration // up to this much extra random delay
	FailRate float64       // share of requests (0..1) answered with an upstream failure
	Down     bool          // close every connection right after accepting it
	Hang     bool          // accept and never answer (timeouts)
}

// Server is one running test proxy.
type Server struct {
	kind       string
	ln         net.Listener
	user, pass string

	mu     sync.Mutex
	faults Faults
	rnd    *rand.Rand

	conns    sync.WaitGroup
	closed   chan struct{}
	once     sync.Once
	Requests atomic.Int64 // handshakes or forward requests handled
}

// StartHTTP starts an HTTP proxy that supports absolute-form forwarding and
// CONNECT. An empty user disables authentication.
func StartHTTP(addr, user, pass string) (*Server, error) { return start("http", addr, user, pass) }

// StartSOCKS5 starts a SOCKS5 proxy (TCP CONNECT only). An empty user means
// no authentication; otherwise RFC 1929 username/password is required.
func StartSOCKS5(addr, user, pass string) (*Server, error) { return start("socks5", addr, user, pass) }

// StartBlackhole accepts TCP connections and never sends a byte.
func StartBlackhole(addr string) (*Server, error) {
	s, err := start("blackhole", addr, "", "")
	if err != nil {
		return nil, err
	}
	s.SetFaults(Faults{Hang: true})
	return s, nil
}

func start(kind, addr, user, pass string) (*Server, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{kind: kind, ln: ln, user: user, pass: pass, closed: make(chan struct{}), rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}
	go s.serve()
	return s, nil
}

// Addr is host:port of the listener.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port is the listening port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// SetFaults replaces the fault settings.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	s.faults = f
	s.mu.Unlock()
}

// SetDown toggles the Down fault and keeps the others.
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	s.faults.Down = down
	s.mu.Unlock()
}

func (s *Server) snapshot() (Faults, time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.faults
	d := f.Latency
	if f.Jitter > 0 {
		d += time.Duration(s.rnd.Int63n(int64(f.Jitter)))
	}
	failNow := f.FailRate > 0 && s.rnd.Float64() < f.FailRate
	return f, d, failNow
}

// Close stops the listener and every open connection.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.closed)
		_ = s.ln.Close()
	})
	s.conns.Wait()
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			done := make(chan struct{})
			go func() {
				select {
				case <-s.closed:
				case <-done:
				}
				_ = c.Close()
			}()
			s.handle(c)
			close(done)
		}()
	}
}

func (s *Server) handle(c net.Conn) {
	f, delay, failNow := s.snapshot()
	if f.Down {
		return
	}
	if f.Hang {
		select {
		case <-s.closed:
		case <-time.After(5 * time.Minute):
		}
		return
	}
	switch s.kind {
	case "http":
		s.handleHTTP(c, delay, failNow)
	case "socks5":
		s.handleSOCKS5(c, delay, failNow)
	}
}

func (s *Server) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-s.closed:
		return false
	}
}

func (s *Server) handleHTTP(c net.Conn, delay time.Duration, failNow bool) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	s.Requests.Add(1)
	if !s.sleep(delay) {
		return
	}
	if s.user != "" && !s.checkBasic(req.Header.Get("Proxy-Authorization")) {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"testproxy\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if failNow {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Method == http.MethodConnect {
		up, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer up.Close()
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		pipe(&bufferedConn{Conn: c, r: br}, up)
		return
	}
	if !req.URL.IsAbs() {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	req.RequestURI = ""
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	resp, err := forwardTransport.RoundTrip(req)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Close = true
	_ = resp.Write(c)
}

var forwardTransport = &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second}

func (s *Server) checkBasic(h string) bool {
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	return ok && user == s.user && pass == s.pass
}

func (s *Server) handleSOCKS5(c net.Conn, delay time.Duration, failNow bool) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	s.Requests.Add(1)
	if !s.sleep(delay) {
		return
	}
	want := byte(0x00)
	if s.user != "" {
		want = 0x02
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		_, _ = c.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := c.Write([]byte{0x05, want}); err != nil {
		return
	}
	if want == 0x02 {
		var v [2]byte
		if _, err := io.ReadFull(br, v[:]); err != nil {
			return
		}
		user := make([]byte, v[1])
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(br, pl[:]); err != nil {
			return
		}
		pass := make([]byte, pl[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if string(user) != s.user || string(pass) != s.pass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	if req[1] != 0x01 {
		_ = socksReply(c, 0x07)
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	default:
		_ = socksReply(c, 0x08)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	if failNow {
		_ = socksReply(c, 0x04)
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		_ = socksReply(c, 0x05)
		return
	}
	defer up.Close()
	if err := socksReply(c, 0x00); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	pipe(&bufferedConn{Conn: c, r: br}, up)
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{0x05, code, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	return err
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
