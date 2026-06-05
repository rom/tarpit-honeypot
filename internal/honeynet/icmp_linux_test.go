//go:build linux

package honeynet

import (
	"encoding/binary"
	"net"
	"testing"

	icmppkg "github.com/rom/tarpit-honeypot/internal/icmp"
)

// verifyV6Checksum re-sums an ICMPv6 message against its pseudo-header; a
// correct checksum makes the one's-complement total 0xffff.
func verifyV6Checksum(t *testing.T, src, dst [16]byte, msg []byte) {
	t.Helper()
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src[:])
	add(dst[:])
	var ph [8]byte
	binary.BigEndian.PutUint32(ph[0:4], uint32(len(msg)))
	ph[7] = 58
	add(ph[:])
	add(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Errorf("ICMPv6 checksum invalid: folded sum = %#04x, want 0xffff", uint16(sum))
	}
}

func TestBuildICMP6FrameEchoReply(t *testing.T) {
	var ourMAC = [6]byte{0x02, 0, 0, 0, 0, 0x10}
	reqMAC := []byte{0x02, 0, 0, 0, 0, 0xaa}
	src := mustV6(t, "2001:db8::1")  // requester
	dst := mustV6(t, "2001:db8::10") // virtual host

	// An inbound echo request -> reply, framed from the host back to requester.
	req := icmppkg.EchoRequestV6(0x1234, 7, []byte("ping6-payload"))
	reply := icmppkg.EchoReplyV6(req)
	frame := buildICMP6Frame(ourMAC, dst, reqMAC, src, reply, 64)
	if frame == nil {
		t.Fatal("nil frame")
	}
	// Ethernet: dst = requester, src = host, ethertype 0x86DD.
	if !equalBytes(frame[0:6], reqMAC) || !equalBytes(frame[6:12], ourMAC[:]) {
		t.Errorf("ethernet MACs wrong: % x", frame[:12])
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPIPv6 {
		t.Errorf("ethertype = %#04x, want 0x86DD", binary.BigEndian.Uint16(frame[12:14]))
	}
	ip := frame[14:]
	if ip[0]>>4 != 6 {
		t.Errorf("IP version = %d, want 6", ip[0]>>4)
	}
	if ip[6] != 58 {
		t.Errorf("next header = %d, want 58 (ICMPv6)", ip[6])
	}
	if ip[7] != 64 {
		t.Errorf("hop limit = %d, want 64", ip[7])
	}
	if !equalBytes(ip[8:24], dst[:]) || !equalBytes(ip[24:40], src[:]) {
		t.Error("IPv6 src/dst addresses wrong")
	}
	icmp := ip[40:]
	if icmp[0] != icmppkg.V6EchoReply {
		t.Errorf("icmp type = %d, want %d (echo reply)", icmp[0], icmppkg.V6EchoReply)
	}
	verifyV6Checksum(t, dst, src, icmp)
}

func TestBuildICMP6FrameNeighborAdvert(t *testing.T) {
	var ourMAC = [6]byte{0x02, 0, 0, 0, 0, 0x10}
	reqMAC := []byte{0x02, 0, 0, 0, 0, 0xbb}
	target := mustV6(t, "2001:db8::10") // host being resolved
	solicitor := mustV6(t, "2001:db8::1")

	na := icmppkg.NeighborAdvertV6(target, ourMAC, 0x60)
	frame := buildICMP6Frame(ourMAC, target, reqMAC, solicitor, na, 255)
	if frame == nil {
		t.Fatal("nil frame")
	}
	ip := frame[14:]
	if ip[7] != 255 {
		t.Errorf("NDP hop limit = %d, want 255", ip[7])
	}
	icmp := ip[40:]
	if icmp[0] != icmppkg.V6NeighborAdv {
		t.Errorf("icmp type = %d, want %d (neighbor advert)", icmp[0], icmppkg.V6NeighborAdv)
	}
	verifyV6Checksum(t, target, solicitor, icmp)
}

func mustV6(t *testing.T, s string) [16]byte {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		t.Fatalf("not an IPv6 literal: %q", s)
	}
	var a [16]byte
	copy(a[:], ip.To16())
	return a
}

func equalBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
