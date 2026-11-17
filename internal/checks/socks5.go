package checks

import (
	"io"
	"net"
	"strconv"
)

// SOCKS5 reply codes (RFC 1928, section 6).
var socksReplies = map[byte]struct {
	class Class
	text  string
}{
	0x01: {ClassProxyError, "general SOCKS server failure"},
	0x02: {ClassRejected, "connection not allowed by the proxy's rules"},
	0x03: {ClassUpstream, "network unreachable from the proxy"},
	0x04: {ClassUpstream, "target host unreachable from the proxy"},
	0x05: {ClassUpstream, "target refused the connection from the proxy"},
	0x06: {ClassUpstream, "TTL expired on the way to the target"},
	0x07: {ClassProtocol, "command not supported (the proxy does not support CONNECT)"},
	0x08: {ClassProtocol, "address type not supported"},
}

// socks5Connect negotiates a SOCKS5 TCP CONNECT tunnel (RFC 1928) with
// optional username/password authentication (RFC 1929). host is a name when
// the proxy should resolve it (socks5h) and an IP literal otherwise.
//
// When credentials are configured only username/password is offered, so a
// proxy that also trusts the client IP cannot hide a broken password.
func socks5Connect(conn net.Conn, user, pass string, withAuth bool, host string, port int) error {
	method := byte(0x00)
	if withAuth {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fail(ClassProtocol, "not a SOCKS5 proxy: the first reply byte is 0x%02x%s", reply[0], protocolHint(reply[0]))
	}
	switch {
	case reply[1] == 0xFF && withAuth:
		return fail(ClassAuth, "the proxy accepts none of the offered authentication methods (username/password)")
	case reply[1] == 0xFF:
		return fail(ClassAuth, "the proxy requires authentication, but no username is configured")
	case reply[1] != method:
		return fail(ClassProtocol, "the proxy chose authentication method 0x%02x, which was not offered", reply[1])
	}

	if withAuth {
		if len(user) == 0 || len(user) > 255 || len(pass) > 255 {
			return fail(ClassAuth, "SOCKS5 usernames and passwords must be 1-255 bytes")
		}
		msg := make([]byte, 0, 3+len(user)+len(pass))
		msg = append(msg, 0x01, byte(len(user)))
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		// RFC 1929 says version 0x01; some servers answer 0x05. Both are fine.
		if reply[1] != 0x00 {
			return fail(ClassAuth, "the proxy rejected the username or password (status 0x%02x)", reply[1])
		}
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fail(ClassProtocol, "target host name is longer than 255 bytes")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fail(ClassProtocol, "malformed SOCKS5 reply (version 0x%02x)", head[0])
	}
	if head[1] != 0x00 {
		if r, ok := socksReplies[head[1]]; ok {
			return fail(r.class, "SOCKS5 reply 0x%02x: %s", head[1], r.text)
		}
		return fail(ClassProxyError, "SOCKS5 reply 0x%02x: unknown error", head[1])
	}
	// Skip the bound address and port.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return fail(ClassProtocol, "malformed SOCKS5 reply (address type 0x%02x)", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
		return err
	}
	return nil
}

// protocolHint explains a wrong first byte.
func protocolHint(b byte) string {
	switch {
	case b == 'H':
		return " ('H', the start of an HTTP response: this looks like an HTTP proxy)"
	case b == 0x15 || b == 0x16:
		return " (a TLS record: this port expects TLS)"
	case b == 0x05:
		return " (this looks like a SOCKS5 proxy)"
	case b >= 0x20 && b < 0x7f:
		return " (" + strconv.QuoteRune(rune(b)) + ")"
	}
	return ""
}
