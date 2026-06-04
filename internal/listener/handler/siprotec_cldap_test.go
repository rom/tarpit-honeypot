package handler

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func cveHit(res Result, id string) bool {
	for _, c := range res.CVEHits {
		if c == id {
			return true
		}
	}
	return false
}

// The published Siemens SIPROTEC EN100 DoS datagram (CVE-2015-5374) on UDP/50000
// must be detected and never answered.
func TestSIPROTECEN100DoS(t *testing.T) {
	h := &siprotecEN100{}
	src := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 50000}
	pc := &fakePacketConn{}
	res, _ := h.Handle(context.Background(), siprotecDoSPacket, src, pc, config.Listener{})
	if !hasAnom(res, "siprotec-en100-dos") || !cveHit(res, "CVE-2015-5374") {
		t.Errorf("DoS packet not detected: anoms=%v cves=%v", metaAnoms(res), res.CVEHits)
	}
	if len(pc.written) != 0 {
		t.Errorf("SIPROTEC handler must not reply (no amplification); wrote %d", len(pc.written))
	}
	// A benign datagram is captured but not flagged as the DoS.
	res2, _ := h.Handle(context.Background(), []byte{0x00, 0x01, 0x02, 0x03}, src, pc, config.Listener{})
	if hasAnom(res2, "siprotec-en100-dos") {
		t.Error("benign packet wrongly flagged as SIPROTEC DoS")
	}
}

func berLen(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// buildCLDAPSearch builds a CLDAP SearchRequest (op 0x63) whose body is fillerLen
// repeated 'A' bytes — the CVE-2026-41089 oversized-username overflow shape.
func buildCLDAPSearch(fillerLen int) []byte {
	filler := bytes.Repeat([]byte{0x41}, fillerLen)
	op := append([]byte{0x63}, berLen(len(filler))...)
	op = append(op, filler...)
	body := append([]byte{0x02, 0x01, 0x01}, op...) // messageID INTEGER 1 + op
	pkt := append([]byte{0x30}, berLen(len(body))...)
	return append(pkt, body...)
}

// A CLDAP Netlogon request with a 130+ char username must flag CVE-2026-41089.
func TestCLDAPNetlogonOverflow(t *testing.T) {
	h := &cldap{}
	src := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 389}

	res, _ := h.Handle(context.Background(), buildCLDAPSearch(200), src, &fakePacketConn{}, config.Listener{})
	if !hasAnom(res, "cldap-netlogon-overflow") || !cveHit(res, "CVE-2026-41089") {
		t.Errorf("overflow not detected: anoms=%v cves=%v", metaAnoms(res), res.CVEHits)
	}

	// A normal small CLDAP search must NOT trip the overflow detection.
	res2, _ := h.Handle(context.Background(), buildCLDAPSearch(8), src, &fakePacketConn{}, config.Listener{})
	if hasAnom(res2, "cldap-netlogon-overflow") {
		t.Error("normal CLDAP search wrongly flagged as overflow")
	}
	if !hasAnom(res2, "cldap-netlogon-probe") {
		t.Error("normal CLDAP search should still be a netlogon probe")
	}
}

func TestLongestByteRun(t *testing.T) {
	if got := longestByteRun([]byte("ABBBC")); got != 3 {
		t.Errorf("longestByteRun = %d; want 3", got)
	}
	if got := longestByteRun(bytes.Repeat([]byte{0x41}, 130)); got != 130 {
		t.Errorf("longestByteRun = %d; want 130", got)
	}
	if got := longestByteRun(nil); got != 0 {
		t.Errorf("longestByteRun(nil) = %d; want 0", got)
	}
}
