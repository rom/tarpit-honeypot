//go:build linux

package honeynet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// buildLLDPFrame should produce a valid LLDP-ethertype frame whose
// PDU starts with Chassis-ID, Port-ID, and TTL TLVs (mandatory per
// IEEE 802.1AB) and terminates with End-of-LLDPDU (type=0 len=0).
func TestBuildLLDPFrameStructure(t *testing.T) {
	h := &Host{
		Hostname:  "scalance-test",
		MAC:       [6]byte{0x28, 0x63, 0x36, 0x01, 0x02, 0x03},
		Archetype: archetype.Lookup("Siemens SCALANCE XB-208"),
	}
	frame := buildLLDPFrame(h)

	// Ethernet header: dst MAC (6) + src MAC (6) + ethertype (2).
	if len(frame) < 14 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	if frame[0] != 0x01 || frame[1] != 0x80 || frame[2] != 0xc2 ||
		frame[3] != 0x00 || frame[4] != 0x00 || frame[5] != 0x0e {
		t.Errorf("LLDP dst MAC wrong: %x", frame[0:6])
	}
	if !bytes.Equal(frame[6:12], h.MAC[:]) {
		t.Errorf("src MAC wrong: got %x; want %x", frame[6:12], h.MAC[:])
	}
	if frame[12] != 0x88 || frame[13] != 0xcc {
		t.Errorf("ethertype not LLDP: %x", frame[12:14])
	}

	pdu := frame[14:]
	// Walk TLVs. First three must be type 1 (Chassis-ID), 2 (Port-ID),
	// 3 (TTL); last must be type 0 (End-of-LLDPDU).
	idx := 0
	tlvSeen := []int{}
	for idx < len(pdu)-1 {
		hdr := binary.BigEndian.Uint16(pdu[idx : idx+2])
		t := int(hdr >> 9)
		n := int(hdr & 0x1ff)
		tlvSeen = append(tlvSeen, t)
		idx += 2 + n
		if t == 0 {
			break
		}
	}
	if len(tlvSeen) < 4 {
		t.Fatalf("too few TLVs: %v", tlvSeen)
	}
	if tlvSeen[0] != 1 || tlvSeen[1] != 2 || tlvSeen[2] != 3 {
		t.Errorf("mandatory TLV order wrong: %v", tlvSeen)
	}
	if tlvSeen[len(tlvSeen)-1] != 0 {
		t.Errorf("frame doesn't end with End-of-LLDPDU: %v", tlvSeen)
	}
	// The hostname should appear in the System-Name TLV (type 5).
	if !bytes.Contains(pdu, []byte("scalance-test")) {
		t.Errorf("hostname missing from PDU")
	}
	// The archetype's sysDescr should appear in System-Description.
	if !bytes.Contains(pdu, []byte("SCALANCE")) {
		t.Errorf("sysDescr missing from PDU")
	}
}

// CDP frames use the SNAP/LLC encapsulation; verify the header bytes
// and that the device-id / platform TLVs land in the body.
func TestBuildCDPFrame(t *testing.T) {
	h := &Host{
		Hostname:  "moxa-test",
		MAC:       [6]byte{0x00, 0x90, 0xe8, 0xaa, 0xbb, 0xcc},
		Archetype: archetype.Lookup("Moxa EDS-208"),
	}
	frame := buildCDPFrame(h)
	if len(frame) < 22 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	if frame[0] != 0x01 || frame[1] != 0x00 || frame[2] != 0x0c ||
		frame[3] != 0xcc || frame[4] != 0xcc || frame[5] != 0xcc {
		t.Errorf("CDP dst MAC wrong: %x", frame[0:6])
	}
	// LLC + SNAP starts at offset 14: AA AA 03 00 00 0C 20 00.
	want := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}
	if !bytes.Equal(frame[14:22], want) {
		t.Errorf("LLC/SNAP header wrong: %x", frame[14:22])
	}
	if !bytes.Contains(frame, []byte("moxa-test")) {
		t.Errorf("hostname missing from CDP body")
	}
	if !bytes.Contains(frame, []byte("Moxa Industrial Switch")) {
		t.Errorf("platform string missing from CDP body")
	}
}

// LLDP capabilities should differ by archetype family.
func TestLLDPCapsByFamily(t *testing.T) {
	cases := map[string]uint16{
		"Debian 12":               0x0080, // station-only
		"Siemens SCALANCE XB-208": 0x0024, // bridge + router
		"Moxa EDS-208":            0x0024,
	}
	for name, want := range cases {
		h := &Host{Archetype: archetype.Lookup(name)}
		got := lldpCapsFor(h)
		if got != want {
			t.Errorf("%s: caps=%04x; want %04x", name, got, want)
		}
	}
}
