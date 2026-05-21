package handler

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// Regression tests for the security-audit findings batch. Each test
// reproduces a pre-fix exploitable behavior and verifies it's
// neutralized after the fix.

// Modbus length=1 used to drive `make([]byte, length-1) = empty slice`
// + `pdu[0]` panic, killing the handler goroutine on every connection.
// After the fix the handler returns cleanly with a "length" meta tag.
func TestSecModbusLengthOnePanic(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "modbus", ReadBytes: 32, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("modbus handler panicked: %v", r)
			}
		}()
		_, _ = (&modbus{}).Handle(context.Background(), server, cfg)
	}()
	// MBAP: txid=0, proto=0, length=1, unit=0 — 7 bytes total, no PDU.
	_, _ = client.Write([]byte{0, 0, 0, 0, 0, 1, 0})
	client.Close()
	<-done
}

// S7 with a 6-byte body used to slice `body[7:]` and panic. Reproduce
// with TPKT version=3, length=10 → body of 6 bytes (10-4) — and verify
// no panic.
func TestSecS7SixByteBodyPanic(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "s7", ReadBytes: 32, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("s7 handler panicked: %v", r)
			}
		}()
		_, _ = (&s7{}).Handle(context.Background(), server, cfg)
	}()
	// TPKT version=3 reserved=0 length=10. COTP CR (type 0xE0) with
	// only the mandatory fields and no parameter bytes.
	_, _ = client.Write([]byte{
		0x03, 0x00, 0x00, 0x0a, // TPKT
		0x05, 0xE0, // COTP length=5, type CR
		0x00, 0x00, // dst_ref
		0x00, 0x01, // src_ref
		// no class byte, no params — totaling 6 body bytes.
	})
	client.Close()
	<-done
}

// RADIUS with attacker-controlled length=5 (< 20) used to slice
// `payload[20:5]` and panic. Verify the bounds check catches it.
func TestSecRadiusShortLengthPanic(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1812}
	pkt := make([]byte, 20)
	pkt[0] = 1 // code=Access-Request
	pkt[1] = 1 // identifier
	pkt[2] = 0 // length high byte
	pkt[3] = 5 // length=5 (invalid; < 20)
	// authenticator: 16 bytes of 0
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("radius handler panicked: %v", r)
		}
	}()
	(&radius{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
}

// RADIUS with attacker-controlled length > payload size used to slice
// `payload[20:huge]` and panic.
func TestSecRadiusLengthOversizePanic(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1812}
	pkt := make([]byte, 25)
	pkt[0] = 1
	pkt[1] = 1
	pkt[2] = 0x10
	pkt[3] = 0x00 // length=4096; far larger than the 25-byte payload
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("radius handler panicked: %v", r)
		}
	}()
	(&radius{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
}

// SSDP ST header used to be reflected raw — CRLF in ST: gave a
// UDP reflection/amplification primitive for off-path attackers.
// After the fix, the response must contain neither raw CR nor LF
// from the attacker-controlled portion.
func TestSecSSDPHeaderInjection(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1900}
	pkt := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\nMX: 1\r\n" +
		// The hostile ST header: a real value followed by CRLF +
		// an injected response header + body.
		"ST: rootdevice\r\nX-Pwned: yes\r\nContent-Length: 99999\r\n\r\nST-Real: x\r\n\r\n")
	(&ssdp{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if len(pc.written) == 0 {
		t.Fatal("ssdp did not reply")
	}
	reply := string(pc.written[0])
	// Walk the response body after the ST: line — verify no injected
	// X-Pwned header survived inside the ST value position.
	idx := strings.Index(reply, "ST: ")
	if idx < 0 {
		t.Fatal("ST: header missing from reply")
	}
	nl := strings.Index(reply[idx:], "\r\n")
	if nl < 0 {
		t.Fatal("no CRLF after ST:")
	}
	stValue := reply[idx+4 : idx+nl]
	if strings.Contains(stValue, "X-Pwned") {
		t.Errorf("ST value contains injected header: %q", stValue)
	}
}

// UDP discovery/reflector handlers (coap/knx/ssdp/fins) used to answer
// every probe, making the sensor a spoofed-source reflection/amplification
// primitive. After the fix a global rate limiter caps believable replies;
// a flood is suppressed (rate_limited) instead of reflected at the victim.
func TestSecUDPReflectionRateLimited(t *testing.T) {
	h := &coap{lim: newUDPReflectLimiter()}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5683}
	req := []byte{0x40, 0x01, 0x00, 0x01} // valid minimal CoAP GET
	pc := &fakePacketConn{}
	suppressed := 0
	for i := 0; i < 200; i++ {
		res, _ := h.Handle(context.Background(), req, src, pc, config.Listener{})
		if res.Meta["rate_limited"] == true {
			suppressed++
		}
	}
	if suppressed == 0 {
		t.Error("rate limiter never engaged under a 200-packet flood")
	}
	if len(pc.written) >= 200 {
		t.Errorf("every probe was reflected (%d writes) — not rate limited", len(pc.written))
	}
}

// A nil limiter (handler constructed directly, e.g. unit tests) must not
// block the reply path.
func TestSecUDPReflectLimiterNilSafe(t *testing.T) {
	if !(*udpReflectLimiter)(nil).allow() {
		t.Error("nil udpReflectLimiter must allow")
	}
}

// The DCE/RPC endpoint-mapper interface set used to be a shared package
// var assigned straight into res.Meta; the listener sanitizes meta in
// place, so concurrent connections mutated the same maps and crashed with
// "concurrent map writes". epmInterfaces() must now hand out fresh maps.
func TestSecDCERPCEPMFreshMaps(t *testing.T) {
	a := epmInterfaces()
	b := epmInterfaces()
	if len(a) == 0 {
		t.Fatal("epmInterfaces returned nothing")
	}
	a[0]["name"] = "MUTATED"
	if b[0]["name"] == "MUTATED" {
		t.Error("epmInterfaces returned shared maps — concurrent sanitize would race/crash")
	}
}

// shouldRotate used to read the cert NotBefore, which is deliberately
// backdated — so any rotate window shorter than the backdate regenerated
// the cert on every TLS connection (CPU/disk DoS). Rotation now keys on
// real creation time.
func TestSecHTTPSRotationUsesCreationTime(t *testing.T) {
	h := &https{rotateDays: 30}
	if h.expired(time.Now()) {
		t.Error("a just-created cert must not be considered expired")
	}
	if !h.expired(time.Now().AddDate(0, 0, -40)) {
		t.Error("a 40-day-old cert must be expired at rotateDays=30")
	}
	if (&https{rotateDays: 0}).expired(time.Now().AddDate(-5, 0, 0)) {
		t.Error("rotateDays=0 disables rotation")
	}
}

// SIP Via header used to be reflected raw. Same threat shape as SSDP
// (UDP, spoofable, reflection amplification).
func TestSecSIPHeaderInjection(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5060}
	// Hostile Via header with CRLF injection attempt.
	pkt := []byte("OPTIONS sip:1000@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP scanner\r\nX-Pwned: yes\r\n" +
		"From: <sip:scanner@example>\r\n" +
		"To: <sip:1000@1.2.3.4>\r\n" +
		"Call-ID: cafe\r\nCSeq: 1 OPTIONS\r\n\r\n")
	(&sipUDP{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if len(pc.written) == 0 {
		t.Fatal("sip did not reply")
	}
	reply := string(pc.written[0])
	// X-Pwned must not appear at all in the reply.
	if strings.Contains(reply, "X-Pwned") {
		t.Errorf("injected header survived in SIP reply: %q", reply)
	}
}
