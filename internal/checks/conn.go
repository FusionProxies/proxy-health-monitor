package checks

import (
	"bufio"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// meteredConn counts the bytes that cross the socket to the proxy, which is
// what a metered proxy plan bills.
type meteredConn struct {
	net.Conn
	in, out atomic.Int64
}

func (c *meteredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.in.Add(int64(n))
	return n, err
}

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out.Add(int64(n))
	return n, err
}

// firstByteReader remembers when the first byte of the response arrived. It
// sits above TLS, so TLS session tickets do not count as the response.
type firstByteReader struct {
	r     io.Reader
	first time.Time
}

func (f *firstByteReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if n > 0 && f.first.IsZero() {
		f.first = time.Now()
	}
	return n, err
}

// bufferedConn returns bytes a bufio.Reader already pulled from the socket
// before reading from the socket again.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
