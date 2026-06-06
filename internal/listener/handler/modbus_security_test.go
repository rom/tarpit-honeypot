package handler

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// TestModbusSecurity drives a TLS client against the Modbus/TCP Security handler
// and confirms the session is flagged, the inner Modbus PDU is classified, and
// (with no client cert) the missing-cert anomaly fires.
func TestModbusSecurity(t *testing.T) {
	h, err := newModbusSecurity(Deps{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	client, server := pipePair(t)
	cfg := config.Listener{ID: "modbuss-1", ReadTimeout: 5 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	// Modbus MBAP + a Write Single Register (FC 0x06) PDU over the TLS channel.
	req := []byte{0, 1, 0, 0, 0, 6, 0x11, 0x06, 0x00, 0x0A, 0x12, 0x34}
	if _, err := tc.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp := make([]byte, 12)
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadFull(tc, resp)
	_ = tc.Close()

	r := <-resC
	if r.Meta["tls"] != true {
		t.Errorf("expected tls=true; meta=%v", r.Meta)
	}
	if !hasAnom(r, "modbus-secure-session") {
		t.Errorf("modbus-secure-session not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "modbus-secure-no-clientcert") {
		t.Errorf("missing-client-cert not flagged: %v", r.Meta["anomalies"])
	}
	// The inner Modbus handler must still have classified the write.
	if !hasAnom(r, "modbus-write-attempt") {
		t.Errorf("inner Modbus write not classified: %v", r.Meta["anomalies"])
	}
	if r.Meta["function_code"] != byte(0x06) {
		t.Errorf("function_code = %v, want 0x06", r.Meta["function_code"])
	}
}
