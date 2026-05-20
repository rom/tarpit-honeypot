package icmp

import "testing"

func hasAnom(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// A normal Linux-ping echo (timestamp + sequential filler) should not
// be flagged.
func TestNormalPingNoAnomaly(t *testing.T) {
	// 8-byte ICMP header + 16-byte ts + 32 sequential bytes.
	msg := make([]byte, 8+16+32)
	msg[0] = V4EchoRequest
	for i := 0; i < 32; i++ {
		msg[8+16+i] = byte(0x10 + i)
	}
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2} // DF set, no frag
	if a := Anomalies(ip, msg); len(a) != 0 {
		t.Errorf("normal ping flagged: %v", a)
	}
}

// An ICMP tunnel packs real data into the payload -> nonzero-entropy.
func TestTunnelPayloadFlagged(t *testing.T) {
	msg := make([]byte, 8)
	msg[0] = V4EchoRequest
	// Append "real" data that isn't sequential / alphabet / constant.
	data := []byte("POST /exfil HTTP/1.1\r\nHost: evil\r\nsecretsecret")
	msg = append(msg, data...)
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	if a := Anomalies(ip, msg); !hasAnom(a, "icmp-payload-nonzero-entropy") {
		t.Errorf("tunnel payload not flagged: %v", a)
	}
}

func TestOversizePayloadFlagged(t *testing.T) {
	msg := make([]byte, 8+2000)
	msg[0] = V4EchoRequest
	// Fill with sequential so only the size triggers.
	for i := 8; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	if a := Anomalies(ip, msg); !hasAnom(a, "icmp-oversize-payload") {
		t.Errorf("oversize payload not flagged: %v", a)
	}
}

func TestFragAbuseFlagged(t *testing.T) {
	msg := make([]byte, 8)
	msg[0] = V4EchoRequest
	// IP header with MF (0x2000) set.
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x20, 0x00, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	if a := Anomalies(ip, msg); !hasAnom(a, "icmp-frag-abuse") {
		t.Errorf("fragmented ICMP not flagged: %v", a)
	}

	// Tiny non-zero offset = overlapping-fragment evasion.
	ipTiny := []byte{0x45, 0, 0, 0, 0, 0, 0x00, 0x01, 64, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2} // offset 1*8=8
	a := Anomalies(ipTiny, msg)
	if !hasAnom(a, "icmp-frag-abuse") || !hasAnom(a, "icmp-frag-tiny") {
		t.Errorf("tiny-offset fragment not flagged: %v", a)
	}
}

func TestWindowsPingFiller(t *testing.T) {
	msg := make([]byte, 8)
	msg[0] = V4EchoRequest
	// Windows ping: "abcdefghijklmnopqrstuvwabcdefghi" (32 bytes, no ts).
	for i := 0; i < 32; i++ {
		msg = append(msg, byte('a'+(i%23)))
	}
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 128, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	if a := Anomalies(ip, msg); hasAnom(a, "icmp-payload-nonzero-entropy") {
		t.Errorf("Windows ping alphabet should be recognized as filler: %v", a)
	}
}
