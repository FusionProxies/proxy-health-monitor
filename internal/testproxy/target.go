package testproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Target is a local health endpoint over HTTP or HTTPS that answers "ok".
type Target struct {
	URL    string         // http://127.0.0.1:port/healthz or https://...
	Pool   *x509.CertPool // trusts the self-signed certificate (HTTPS only)
	srv    *http.Server
	ln     net.Listener
	status atomic.Int32
}

// StartTarget starts a health endpoint. With tlsOn it serves HTTPS with a
// fresh self-signed certificate for 127.0.0.1 and localhost.
func StartTarget(tlsOn bool) (*Target, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t := &Target{ln: ln}
	t.status.Store(http.StatusOK)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(int(t.status.Load()))
		_, _ = io.WriteString(w, "ok\n")
	})
	t.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	scheme := "http"
	if tlsOn {
		cert, pool, err := selfSigned()
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		t.Pool = pool
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		scheme = "https"
	}
	t.URL = scheme + "://" + t.ln.Addr().String() + "/healthz"
	go func() { _ = t.srv.Serve(ln) }()
	return t, nil
}

// SetStatus changes the status code the endpoint answers with.
func (t *Target) SetStatus(code int) { t.status.Store(int32(code)) }

// Close stops the endpoint.
func (t *Target) Close() { _ = t.srv.Close() }

func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "proxy-health-monitor test target"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, nil
}
