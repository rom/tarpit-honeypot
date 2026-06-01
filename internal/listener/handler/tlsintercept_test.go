package handler

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/egress"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

func newTestInterceptDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{Identity: identity.New("tlsi"), DataDir: t.TempDir(), TLSRotate: 0}
}

// TestTLSInterceptInnerHandler: mode A — decrypt and hand to an internal http
// handler. A TLS client should get an HTTP response back over the encrypted
// channel, and the result should carry the TLS fingerprints.
func TestTLSInterceptInnerHandler(t *testing.T) {
	deps := newTestInterceptDeps(t)
	h, err := newTLSIntercept(deps, config.TLSIntercept{InnerHandler: "http"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Listener{ID: "svc", ReadTimeout: 3 * time.Second, HTTPS: config.HTTPS{Hosts: []string{"localhost"}}}

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	resCh := make(chan Result, 1)
	go func() { res, _ := h.Handle(context.Background(), srv, cfg); resCh <- res }()

	client := tls.Client(cli, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, _ = client.Write([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := client.Read(buf)
	_ = cli.Close()
	res := <-resCh

	if n == 0 || !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		t.Errorf("expected an HTTP response over TLS, got %q", string(buf[:n]))
	}
	if res.Meta["tls_intercept"] != true || res.Meta["ja3"] == nil {
		t.Errorf("expected tls_intercept + ja3 in meta, got %v", res.Meta)
	}
}

// TestTLSInterceptForward: mode B — decrypt and forward to a real backend,
// capturing both directions. Requires an egress policy allowlisting the backend.
func TestTLSInterceptForward(t *testing.T) {
	// A plaintext backend that echoes a banner + reads one line.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("BACKEND-BANNER\r\n"))
		br := bufio.NewReader(c)
		_, _ = br.ReadString('\n') // read the client's line
	}()
	backendAddr := backend.Addr().String()

	// Install an egress policy that allowlists exactly the backend.
	prev := egress.Default()
	pol := egress.New()
	pol.Allow(backendAddr)
	egress.SetDefault(pol)
	defer egress.SetDefault(prev)

	deps := newTestInterceptDeps(t)
	h, err := newTLSIntercept(deps, config.TLSIntercept{ForwardTo: backendAddr})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Listener{ID: "svc", ReadTimeout: 3 * time.Second, HTTPS: config.HTTPS{Hosts: []string{"localhost"}}}

	srv, cli := net.Pipe()
	defer srv.Close()
	resCh := make(chan Result, 1)
	go func() { res, _ := h.Handle(context.Background(), srv, cfg); resCh <- res }()

	client := tls.Client(cli, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// The backend banner should arrive decrypted over the TLS channel.
	buf := make([]byte, 64)
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "BACKEND-BANNER") {
		t.Errorf("expected backend banner forwarded to client, got %q", string(buf[:n]))
	}
	// Send a line the backend will read, then close so the proxy copy ends.
	_, _ = client.Write([]byte("hello-backend\r\n"))
	_ = cli.Close()

	select {
	case res := <-resCh:
		if res.Meta["forward_to"] != backendAddr {
			t.Errorf("forward_to meta = %v, want %s", res.Meta["forward_to"], backendAddr)
		}
		if !strings.Contains(string(res.Payload), "hello-backend") {
			t.Errorf("client->backend bytes not captured: %q", string(res.Payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
}

// TestTLSInterceptForwardEgressDenied: a forward to a non-allowlisted backend
// must be refused (fail-closed), not dialed.
func TestTLSInterceptForwardEgressDenied(t *testing.T) {
	prev := egress.Default()
	pol := egress.New()
	pol.Allow("198.51.100.1:9") // a different host
	egress.SetDefault(pol)
	defer egress.SetDefault(prev)

	deps := newTestInterceptDeps(t)
	h, _ := newTLSIntercept(deps, config.TLSIntercept{ForwardTo: "203.0.113.50:443"})
	cfg := config.Listener{ID: "svc", ReadTimeout: 2 * time.Second, HTTPS: config.HTTPS{Hosts: []string{"localhost"}}}

	srv, cli := net.Pipe()
	defer srv.Close()
	resCh := make(chan Result, 1)
	go func() { res, _ := h.Handle(context.Background(), srv, cfg); resCh <- res }()
	client := tls.Client(cli, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = client.Handshake()
	_, _ = client.Write([]byte("x"))
	_, _ = io.ReadAll(client)
	_ = cli.Close()
	res := <-resCh
	if res.Meta["forward_err"] == nil {
		t.Errorf("forward to a non-allowlisted backend should report forward_err; meta=%v", res.Meta)
	}
}
