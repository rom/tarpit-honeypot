package handler

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// Drives the real https handler with a real TLS client over an in-memory
// pipe and asserts the handler captured the ServerHello and computed a
// well-formed JA3S (32 hex chars) for the response it sent.
func TestHTTPSEmitsJA3S(t *testing.T) {
	h := newTestHTTPS(t, identity.New("ja3s-dep"))
	cfg := config.Listener{
		ID:          "svc",
		ReadTimeout: 3 * time.Second,
		HTTPS:       config.HTTPS{Hosts: []string{"localhost"}},
	}

	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()
	resCh := make(chan Result, 1)
	go func() {
		res, _ := h.Handle(context.Background(), srvConn, cfg)
		resCh <- res
	}()

	client := tls.Client(cliConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// A minimal request so serveHTTP returns and the handler finishes.
	_, _ = client.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 512)
	_, _ = client.Read(buf)
	// Close the underlying pipe directly: a TLS close_notify would block,
	// since the server goroutine has already returned and stopped reading.
	_ = cliConn.Close()

	select {
	case res := <-resCh:
		ja3s, _ := res.Meta["ja3s"].(string)
		if ja3s == "" {
			t.Fatalf("handler did not emit ja3s; meta=%v", res.Meta)
		}
		if len(ja3s) != 32 {
			t.Fatalf("ja3s = %q; want 32-hex-char MD5", ja3s)
		}
		if _, err := hex.DecodeString(ja3s); err != nil {
			t.Fatalf("ja3s = %q is not hex: %v", ja3s, err)
		}
		if _, ok := res.Meta["ja3s_raw"].(string); !ok {
			t.Errorf("ja3s set but ja3s_raw missing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}
}
