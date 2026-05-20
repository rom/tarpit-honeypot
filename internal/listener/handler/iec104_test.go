package handler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Regression: a C_RD_NA_1 (type 102, COT=5) I-format frame with a body
// shorter than 13 bytes used to slice body[10:13] and panic. The handler
// must now skip it cleanly.
func TestIEC104ReadCommandShortBodyNoPanic(t *testing.T) {
	// APCI 0x68 + length(12) + 12 body bytes.
	body := make([]byte, 12)
	body[0] = 0x00 // I-format (low bit 0)
	body[4] = 102  // asdu_type C_RD_NA_1
	body[6] = 0x05 // cot = 5 (request), little-endian
	frame := append([]byte{0x68, 0x0c}, body...)

	srv, cli := net.Pipe()
	panicked := make(chan any, 1)
	done := make(chan struct{})
	go func() {
		defer func() { panicked <- recover(); close(done) }()
		h := &iec104{}
		_, _ = h.Handle(context.Background(), srv, config.Listener{ReadTimeout: time.Second})
	}()
	_ = cli.SetDeadline(time.Now().Add(time.Second))
	_, _ = cli.Write(frame)
	_ = cli.Close()

	select {
	case <-done:
		if p := <-panicked; p != nil {
			t.Fatalf("iec104 handler panicked on short C_RD_NA_1 frame: %v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return")
	}
}
