package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// dtlsClientHello builds a DTLS 1.2 record wrapping a ClientHello handshake
// whose body carries the given cipher suites and a single extension, so the
// JA3/JA4 parser has real fields to fingerprint.
func dtlsClientHello() []byte {
	// ClientHello body: legacy_version(2) random(32) session_id(1=0)
	// cookie(1=0, DTLS-specific) cipher_suites(2-len + suites)
	// compression(1-len + 1) extensions(2-len + ext).
	body := []byte{0xfe, 0xfd} // legacy_version DTLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                               // session_id len
	body = append(body, 0x00)                               // cookie len (DTLS)
	body = append(body, 0x00, 0x04, 0xc0, 0x2f, 0xc0, 0x30) // 2 cipher suites
	body = append(body, 0x01, 0x00)                         // compression: 1 method (null)
	ext := []byte{0x00, 0x0d, 0x00, 0x00}                   // signature_algorithms, len 0
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	// DTLS handshake header (12 bytes), unfragmented.
	hs := make([]byte, 12+len(body))
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	hs[9] = byte(len(body) >> 16) // fragment_length == length
	hs[10] = byte(len(body) >> 8)
	hs[11] = byte(len(body))
	copy(hs[12:], body)

	// DTLS record header (13 bytes): type=22, version DTLS 1.2, epoch 0, seq 0.
	rec := make([]byte, 13+len(hs))
	rec[0] = 22
	rec[1], rec[2] = 0xfe, 0xfd
	binary.BigEndian.PutUint16(rec[11:13], uint16(len(hs)))
	copy(rec[13:], hs)
	return rec
}

func TestDTLSFingerprintsAndRepliesHVR(t *testing.T) {
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 50000}
	cfg := config.Listener{Handler: "dtls"}

	res, err := (&dtls{}).Handle(context.Background(), dtlsClientHello(), src, pc, cfg)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if res.Meta["ja3"] == nil || res.Meta["ja3"] == "" {
		t.Errorf("expected a JA3 from the DTLS ClientHello; meta=%v", res.Meta)
	}
	if res.Meta["ja4"] == nil || res.Meta["ja4"] == "" {
		t.Errorf("expected a JA4 from the DTLS ClientHello; meta=%v", res.Meta)
	}
	if res.Meta["dtls_version"] != "DTLS 1.2" {
		t.Errorf("dtls_version = %v, want DTLS 1.2", res.Meta["dtls_version"])
	}
	if !hasAnom(res, "dtls-probe") {
		t.Errorf("expected dtls-probe anomaly; meta=%v", res.Meta)
	}
	// A HelloVerifyRequest must have been written back.
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply datagram, got %d", len(pc.written))
	}
	reply := pc.written[0]
	if len(reply) < 14 || reply[0] != 22 || reply[13] != 0x03 {
		t.Errorf("reply is not a DTLS HelloVerifyRequest: % x", reply[:min2(16, len(reply))])
	}
}

func TestDTLSNonClientHelloStaysSilent(t *testing.T) {
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 50000}
	// A non-handshake datagram (e.g. random UDP) must not get a reply — no
	// reflection surface.
	res, _ := (&dtls{}).Handle(context.Background(), []byte("not dtls"), src, pc, config.Listener{})
	if len(pc.written) != 0 {
		t.Errorf("non-ClientHello must not be answered (reflection guard); got %d writes", len(pc.written))
	}
	if res.Meta["dtls"] != "non-clienthello" {
		t.Errorf("expected non-clienthello marker, got %v", res.Meta["dtls"])
	}
	if !hasAnom(res, "dtls-malformed") {
		t.Errorf("expected dtls-malformed anomaly; meta=%v", res.Meta)
	}
}
