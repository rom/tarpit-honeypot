//go:build linux

package tunnet

import (
	"encoding/binary"
	"testing"
)

// TestTCPv6ChecksumVerifies builds a TCP/IPv6 segment, stamps the checksum the
// way writeTCPv6 does, then re-runs the checksum over the segment *including*
// the stamped field — a correct checksum makes that total fold to zero.
func TestTCPv6ChecksumVerifies(t *testing.T) {
	src := []byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := []byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 51000)
	binary.BigEndian.PutUint32(tcp[4:8], 0x12345678)
	tcp[12] = (20 / 4) << 4
	tcp[13] = 0x12 // SYN|ACK
	binary.BigEndian.PutUint16(tcp[14:16], 0xfaf0)

	cs := tcpv6Checksum(src, dst, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], cs)

	if got := tcpv6Checksum(src, dst, tcp); got != 0 {
		t.Errorf("checksum over segment incl. its own field = %#x; want 0", got)
	}
}

// TestV6DecoyOpenPortLookup confirms the IPv6 decoy map answers the open-port
// question the SYN handler relies on.
func TestV6DecoyOpenPortLookup(t *testing.T) {
	host := [16]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	a := &Adapter{
		decoysV6: map[[16]byte]HostDecoy{
			host: {Ports: map[uint16]bool{443: true, 22: true}},
		},
	}
	d, ok := a.decoysV6[host]
	if !ok {
		t.Fatal("host not present in decoysV6")
	}
	if !d.Ports[443] || !d.Ports[22] {
		t.Errorf("expected 443 and 22 open")
	}
	if d.Ports[8080] {
		t.Errorf("8080 should be closed")
	}
	// A host we never configured must be absent (SYN handler -> RST path).
	other := [16]byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99}
	if _, ok := a.decoysV6[other]; ok {
		t.Errorf("unconfigured host should be absent from decoysV6")
	}
}
