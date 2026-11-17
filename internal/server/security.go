package server

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
)

// guard applies, in order: security headers, the Host check, the failed-auth
// throttle and authentication. /api/health stays public so load balancers
// and container health checks work without the token.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

		if !s.hostAllowed(r.Host) {
			writeJSON(w, http.StatusMisdirectedRequest, map[string]string{"error": "Host not allowed. Add it to server.allowed_hosts if you use a reverse proxy."})
			return
		}
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r)
		if s.throttle.blocked(ip) {
			h.Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed logins, try again in a minute"})
			return
		}
		if !s.authorized(r) {
			s.throttle.fail(ip)
			h.Set("WWW-Authenticate", `Basic realm="proxy-monitor", charset="UTF-8"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required: send Authorization: Bearer <token>, or log in with any username and the token as password"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	token := s.cfg.Server.AuthToken
	if token == "" {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return equal(strings.TrimPrefix(h, "Bearer "), token)
	}
	if _, pass, ok := r.BasicAuth(); ok {
		return equal(pass, token)
	}
	return false
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// hostAllowed protects a loopback-bound dashboard against DNS rebinding: a
// web page on another site cannot reach it through a name that points to
// 127.0.0.1, because that name is not in the allowed list.
func (s *Server) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if config.IsLoopbackHost(host) {
		return true
	}
	for _, a := range s.cfg.Server.AllowedHosts {
		if strings.EqualFold(a, host) {
			return true
		}
	}
	listenHost, _, _ := net.SplitHostPort(s.cfg.Server.Listen)
	if config.IsLoopbackHost(listenHost) {
		return false
	}
	// Bound to a reachable address: any Host unless allowed_hosts narrows it.
	return len(s.cfg.Server.AllowedHosts) == 0
}

// sameOrigin rejects cross-site browser requests to the management API.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // not a browser cross-origin request
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// throttle blocks an address for a minute after 10 failed logins.
type throttle struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newThrottle() *throttle { return &throttle{hits: map[string][]time.Time{}} }

const throttleMax = 10

func (t *throttle) prune(ip string, now time.Time) []time.Time {
	h := t.hits[ip]
	i := 0
	for i < len(h) && now.Sub(h[i]) > time.Minute {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(t.hits, ip)
	} else {
		t.hits[ip] = h
	}
	return h
}

func (t *throttle) blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.prune(ip, time.Now())) >= throttleMax
}

func (t *throttle) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	h := t.prune(ip, now)
	if len(t.hits) > 10000 { // bound memory under a flood of addresses
		t.hits = map[string][]time.Time{}
	}
	t.hits[ip] = append(h, now)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
