package handler

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// serveHTTP took the header colon offset from a strings.ToLower copy and sliced
// the original line — a panic when a growing rune ('Ⱥ'→'ⱥ', 'ȿ'→'Ȿ') before the
// colon made the copy longer. The fuzzer found it; these header lines panicked
// before the fix.
func TestHTTPHeaderGrowingRuneNoPanic(t *testing.T) {
	hs, names := buildTCPHandlers(t.TempDir())
	var hh Handler
	for i, n := range names {
		if n == "http" {
			hh = hs[i]
		}
	}
	if hh == nil {
		t.Skip("http handler not built")
	}
	cfg := config.Listener{ReadTimeout: 300 * time.Millisecond, ReadBytes: 8192}
	for _, hdr := range []string{"Ⱥ:", "Ⱥ: v", "ȿ:x", "AⱥB: y", "Ⱥ"} {
		conn := &fuzzConn{data: []byte("GET / HTTP/1.1\r\n" + hdr + "\r\nHost: x\r\n\r\n")}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _ = hh.Handle(ctx, conn, cfg) // must not panic
		cancel()
	}
	// A normal header still parses and is captured.
	conn := &fuzzConn{data: []byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := hh.Handle(ctx, conn, cfg); err != nil {
		t.Errorf("well-formed request errored: %v", err)
	}
}
