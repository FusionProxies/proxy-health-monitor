// Package redact masks credentials before text reaches a log, the API, the
// dashboard, an alert or a report.
//
// Two layers work together:
//
//   - Every secret the configuration knows about (proxy usernames and
//     passwords, API tokens, webhook URLs, bot tokens) is registered once at
//     startup and replaced wherever it appears in a string.
//   - Anything that still looks like credentials inside a URL
//     (scheme://user:pass@host) is masked by pattern, which also covers secrets
//     that were never registered.
package redact

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Mask is what a secret is replaced with.
const Mask = "***"

// minSecretLen keeps very short values (for example a one-letter username)
// from being registered, because replacing them would mangle ordinary text.
// Such values are still masked by Username and URL.
const minSecretLen = 4

var (
	mu      sync.RWMutex
	secrets []string // longest first, so a secret that contains another is replaced whole

	// userinfoRe matches the userinfo part of a URL: scheme://user[:pass]@
	userinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@:]+)(:[^/\s@]*)?@`)
	// bearerRe matches Authorization header values that slipped into a message.
	bearerRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`)
	// botTokenRe matches Telegram bot tokens inside API URLs.
	botTokenRe = regexp.MustCompile(`/bot[0-9]+:[A-Za-z0-9_-]+`)
)

// Register adds secrets that must never be printed. Empty and very short
// values are ignored.
func Register(values ...string) {
	mu.Lock()
	defer mu.Unlock()
	for _, v := range values {
		v = strings.TrimSpace(v)
		if len(v) < minSecretLen {
			continue
		}
		dup := false
		for _, s := range secrets {
			if s == v {
				dup = true
				break
			}
		}
		if !dup {
			secrets = append(secrets, v)
			// A password often reaches a URL percent-encoded.
			if esc := url.QueryEscape(v); esc != v {
				secrets = append(secrets, esc)
			}
			if esc := url.PathEscape(v); esc != v {
				secrets = append(secrets, esc)
			}
		}
	}
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
}

// Reset forgets every registered secret. Tests use it.
func Reset() {
	mu.Lock()
	secrets = nil
	mu.Unlock()
}

// String returns s with every registered secret and every URL credential
// masked.
func String(s string) string {
	if s == "" {
		return s
	}
	mu.RLock()
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, Mask)
		}
	}
	mu.RUnlock()
	s = userinfoRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := userinfoRe.FindStringSubmatch(m)
		out := sub[1] + Username(sub[2])
		if sub[3] != "" {
			out += ":" + Mask
		}
		return out + "@"
	})
	s = bearerRe.ReplaceAllString(s, "$1 "+Mask)
	s = botTokenRe.ReplaceAllString(s, "/bot"+Mask)
	return s
}

// Error returns the masked text of err, or "" for nil.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return String(err.Error())
}

// Username keeps the first two characters of a username so people can tell
// accounts apart, and masks the rest. Short names are masked completely.
func Username(u string) string {
	if u == "" || u == Mask {
		return u
	}
	if strings.HasSuffix(u, Mask) {
		return u // already masked
	}
	if len(u) <= 4 {
		return Mask
	}
	return u[:2] + Mask
}

// URL renders u without its password, with the username masked and every
// query value masked (tokens often travel in query strings).
func URL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	var userinfo string
	if c.User != nil {
		userinfo = Username(c.User.Username())
		if _, ok := c.User.Password(); ok {
			userinfo += ":" + Mask
		}
		userinfo += "@"
		c.User = nil
	}
	if c.RawQuery != "" {
		q := c.Query()
		for k := range q {
			q[k] = []string{"x"}
		}
		c.RawQuery = strings.ReplaceAll(q.Encode(), "=x", "="+Mask)
	}
	c.Fragment = ""
	s := c.String()
	if userinfo != "" {
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[:i+3] + userinfo + s[i+3:]
		}
	}
	return s
}
