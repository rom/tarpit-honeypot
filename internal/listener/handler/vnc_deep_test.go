package handler

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// TestVNCAppleClientFingerprint: the Apple Remote Desktop minor (003.889) is
// recognized from the client RFB version.
func TestVNCAppleClientFingerprint(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&vnc{}).Handle(context.Background(), server, cfg) }()
	_, _ = io.ReadFull(client, make([]byte, 12)) // server version
	_, _ = client.Write([]byte("RFB 003.889\n"))
	// 3.7+ path: read security-type list, then close.
	_, _ = io.ReadFull(client, make([]byte, 2))
	_ = client.Close()
	<-done
	if res.Meta["vnc_client"] != "apple-remote-desktop" {
		t.Errorf("vnc_client = %v; want apple-remote-desktop", res.Meta["vnc_client"])
	}
}

// TestVNCNoneAuthProbe: a client selecting security type 1 (None) — which we
// never offer — is a scanner hunting for an unauthenticated server.
func TestVNCNoneAuthProbe(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&vnc{}).Handle(context.Background(), server, cfg) }()
	_, _ = io.ReadFull(client, make([]byte, 12))
	_, _ = client.Write([]byte("RFB 003.008\n"))
	_, _ = io.ReadFull(client, make([]byte, 2)) // [count][type]
	_, _ = client.Write([]byte{1})              // select None
	_ = client.Close()
	<-done
	if res.Meta["security_type_name"] != "None" {
		t.Errorf("security_type_name = %v; want None", res.Meta["security_type_name"])
	}
	if !hasAnom(res, "vnc-none-auth-probe") {
		t.Errorf("None-auth probe not flagged: %v", res.Meta["anomalies"])
	}
}

// TestVNCFailureReasonOn38: an RFB 3.8 auth failure carries a length-prefixed
// reason string after the 4-byte status.
func TestVNCFailureReasonOn38(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 2 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&vnc{}).Handle(context.Background(), server, cfg) }()
	_, _ = io.ReadFull(client, make([]byte, 12))
	_, _ = client.Write([]byte("RFB 003.008\n"))
	_, _ = io.ReadFull(client, make([]byte, 2))  // sec list
	_, _ = client.Write([]byte{2})               // VNC auth
	_, _ = io.ReadFull(client, make([]byte, 16)) // challenge
	_, _ = client.Write(make([]byte, 16))        // DES response
	status := make([]byte, 4)
	if _, err := io.ReadFull(client, status); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(status) != 1 {
		t.Fatalf("status = %d; want 1 (failed)", binary.BigEndian.Uint32(status))
	}
	rl := make([]byte, 4)
	if _, err := io.ReadFull(client, rl); err != nil {
		t.Fatalf("no reason length on 3.8 failure: %v", err)
	}
	n := binary.BigEndian.Uint32(rl)
	if n == 0 || n > 256 {
		t.Fatalf("implausible reason length %d", n)
	}
	reason := make([]byte, n)
	_, _ = io.ReadFull(client, reason)
	if string(reason) != "Authentication failed" {
		t.Errorf("reason = %q", reason)
	}
	_ = client.Close()
	<-done
}

// TestVNCEncodingsFingerprint: the client's SetEncodings list is decoded into
// named encodings during the accepted session.
func TestVNCEncodingsFingerprint(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: 3 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := (&vnc{acceptCreds: "any"}).Handle(context.Background(), server, cfg); resC <- r }()
	_ = vncHandshake(t, client)
	_, _ = client.Write([]byte{1}) // ClientInit
	head := make([]byte, 24)
	_, _ = io.ReadFull(client, head)
	nameLen := binary.BigEndian.Uint32(head[20:24])
	_, _ = io.ReadFull(client, make([]byte, nameLen))
	// SetEncodings: type=2, pad, count=2, Tight(7) + ZRLE(16).
	se := []byte{2, 0, 0, 2}
	se = append(se, 0, 0, 0, 7)  // Tight
	se = append(se, 0, 0, 0, 16) // ZRLE
	_, _ = client.Write(se)
	_ = client.Close()
	r := <-resC
	encs, _ := r.Meta["vnc_encodings"].([]string)
	if !containsStr(encs, "Tight") || !containsStr(encs, "ZRLE") {
		t.Errorf("vnc_encodings = %v; want Tight + ZRLE", encs)
	}
}
