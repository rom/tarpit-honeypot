package handler

import (
	"encoding/binary"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/identity"
)

// peerOpen builds a minimal BGP OPEN message from a peer (version 4, the given
// 2-byte AS, hold 180, router-id 10.0.0.1, no optional params).
func peerOpen(peerAS uint16) string {
	hdr := make([]byte, 19)
	for i := 0; i < 16; i++ {
		hdr[i] = 0xFF
	}
	hdr[16], hdr[17], hdr[18] = 0x00, 29, 1 // len 29, type OPEN
	body := []byte{4, byte(peerAS >> 8), byte(peerAS), 0x00, 0xB4, 10, 0, 0, 1, 0}
	return string(hdr) + string(body)
}

// firstBGPMsg returns the first BGP message in out: its type and the message
// bytes (header + body), or (0,nil) when out is too short / not BGP-framed.
func firstBGPMsg(out []byte) (msgType byte, msg []byte) {
	if len(out) < 19 {
		return 0, nil
	}
	n := int(binary.BigEndian.Uint16(out[16:18]))
	if n < 19 || n > len(out) {
		return 0, nil
	}
	return out[18], out[:n]
}

// TestBGPOpenAdvertisesAS: with sensor.bgp_as set, a peer OPEN is answered with
// our own OPEN carrying that AS (My Autonomous System), then a NOTIFICATION.
func TestBGPOpenAdvertisesAS(t *testing.T) {
	id := identity.New("bgp-as-test")
	id.SetBGPAS(64512)
	res, out := roundtrip(t, bgpH{id: id}, peerOpen(65000))

	if res.Meta["bgp_local_as"] != 64512 {
		t.Errorf("bgp_local_as = %v; want 64512", res.Meta["bgp_local_as"])
	}
	mt, open := firstBGPMsg(out)
	if mt != 1 {
		t.Fatalf("first reply type = %d; want 1 (OPEN). out=%x", mt, out)
	}
	if myAS := binary.BigEndian.Uint16(open[20:22]); myAS != 64512 {
		t.Errorf("My AS = %d; want 64512", myAS)
	}
	// The 4-octet-ASN capability carries the same AS, and a NOTIFICATION follows.
	if as4, _ := bgpOpenCaps(open[28:]); as4 != 64512 {
		t.Errorf("4-octet-ASN capability = %d; want 64512", as4)
	}
	if mt2, _ := firstBGPMsg(out[len(open):]); mt2 != 3 {
		t.Errorf("message after OPEN type = %d; want 3 (NOTIFICATION)", mt2)
	}
}

// TestBGPOpen4ByteASN: an ASN > 65535 is sent as AS_TRANS (23456) in the 2-byte
// field with the real value in the 4-octet-ASN capability (RFC 6793).
func TestBGPOpen4ByteASN(t *testing.T) {
	id := identity.New("bgp-as4")
	id.SetBGPAS(131072)
	_, out := roundtrip(t, bgpH{id: id}, peerOpen(65000))
	mt, open := firstBGPMsg(out)
	if mt != 1 {
		t.Fatalf("first reply type = %d; want OPEN", mt)
	}
	if myAS := binary.BigEndian.Uint16(open[20:22]); myAS != 23456 {
		t.Errorf("My AS = %d; want 23456 (AS_TRANS)", myAS)
	}
	if as4, _ := bgpOpenCaps(open[28:]); as4 != 131072 {
		t.Errorf("4-octet-ASN capability = %d; want 131072", as4)
	}
}

// TestBGPNoASNotificationOnly: with no AS configured, the responder replies
// NOTIFICATION only — it advertises no AS (the pre-existing behaviour).
func TestBGPNoASNotificationOnly(t *testing.T) {
	res, out := roundtrip(t, bgpH{}, peerOpen(65000))
	if res.Meta["bgp_local_as"] != nil {
		t.Errorf("bgp_local_as set without config: %v", res.Meta["bgp_local_as"])
	}
	if mt, _ := firstBGPMsg(out); mt != 3 {
		t.Errorf("first reply type = %d; want 3 (NOTIFICATION only)", mt)
	}
}
