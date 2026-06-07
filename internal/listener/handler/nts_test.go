package handler

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestNTSKEHandshake(t *testing.T) {
	h := &nts{mgr: maybeCertMgr(Deps{DataDir: t.TempDir()})}
	client, server := pipePair(t)
	cfg := config.Listener{ID: "nts-1", ReadTimeout: 2 * time.Second}
	resC := make(chan Result, 1)
	go func() { r, _ := h.Handle(context.Background(), server, cfg); resC <- r }()

	tc := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"ntske/1"},
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	// Client NTS-KE request: Next Protocol (NTPv4=0), AEAD (AES-SIV-CMAC-256=15),
	// End of Message — all critical.
	rec := func(typ, body uint16) []byte {
		out := make([]byte, 6)
		binary.BigEndian.PutUint16(out[0:2], typ|0x8000)
		binary.BigEndian.PutUint16(out[2:4], 2)
		binary.BigEndian.PutUint16(out[4:6], body)
		return out
	}
	var req []byte
	req = append(req, rec(1, 0)...)  // next-proto NTPv4
	req = append(req, rec(4, 15)...) // AEAD AES-SIV-CMAC-256
	eom := []byte{0x80, 0x00, 0x00, 0x00}
	req = append(req, eom...)
	if _, err := tc.Write(req); err != nil {
		t.Fatal(err)
	}

	// Read the response records; expect next-proto, AEAD, cookies, end-of-message.
	hdr := make([]byte, 4)
	sawNextProto, sawAEAD, sawCookie, sawEnd := false, false, false, false
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 40; i++ {
		if _, err := io.ReadFull(tc, hdr); err != nil {
			break
		}
		typ := binary.BigEndian.Uint16(hdr[0:2]) &^ 0x8000
		blen := int(binary.BigEndian.Uint16(hdr[2:4]))
		body := make([]byte, blen)
		if blen > 0 {
			if _, err := io.ReadFull(tc, body); err != nil {
				break
			}
		}
		switch typ {
		case 1:
			sawNextProto = true
		case 4:
			sawAEAD = true
		case 5:
			sawCookie = true
		case 0:
			sawEnd = true
		}
		if sawEnd {
			break
		}
	}
	// Close the raw pipe (not the TLS layer): a tls close_notify Write would
	// block on net.Pipe once the server has stopped reading.
	_ = client.Close()
	r := <-resC

	if !(sawNextProto && sawAEAD && sawCookie && sawEnd) {
		t.Errorf("NTS-KE response incomplete: nextproto=%v aead=%v cookie=%v end=%v",
			sawNextProto, sawAEAD, sawCookie, sawEnd)
	}
	if r.Meta["alpn"] != "ntske/1" {
		t.Errorf("alpn = %v; want ntske/1", r.Meta["alpn"])
	}
	if _, ok := r.Meta["ja3"]; !ok {
		t.Errorf("missing ja3 (ClientHello fingerprint): %v", r.Meta)
	}
	if !hasAnom(r, "nts-ke-probe") {
		t.Errorf("nts-ke-probe not flagged: %v", r.Meta["anomalies"])
	}
	if aeads, _ := r.Meta["nts_aead_algorithms"].([]uint16); len(aeads) == 0 || aeads[0] != 15 {
		t.Errorf("client AEAD not captured: %v", r.Meta["nts_aead_algorithms"])
	}
}
