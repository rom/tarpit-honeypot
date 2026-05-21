package sniffer

import (
	"encoding/binary"
	"testing"
)

func TestParseGOOSE(t *testing.T) {
	gocb := "SIE/LLN0$GO$gcb01"
	goid := "GE_BAY1"
	tlv := func(tag byte, v []byte) []byte { return append([]byte{tag, byte(len(v))}, v...) }
	var apduBody []byte
	apduBody = append(apduBody, tlv(0x80, []byte(gocb))...)        // gocbRef
	apduBody = append(apduBody, tlv(0x81, []byte{0x07, 0xd0})...)  // timeAllowedToLive
	apduBody = append(apduBody, tlv(0x83, []byte(goid))...)        // goID
	apduBody = append(apduBody, tlv(0x85, []byte{0x05})...)        // stNum
	apduBody = append(apduBody, tlv(0x86, []byte{0x0a})...)        // sqNum
	apdu := append([]byte{0x61, byte(len(apduBody))}, apduBody...) // GOOSE PDU

	gooseHdr := make([]byte, 8) // APPID(2) length(2) reserved1(2) reserved2(2)
	binary.BigEndian.PutUint16(gooseHdr[0:2], 0x0001)
	binary.BigEndian.PutUint16(gooseHdr[2:4], uint16(8+len(apdu)))

	eth := []byte{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0xb8}
	frame := append(append(eth, gooseHdr...), apdu...)

	gi, ok := parseGOOSE(frame)
	if !ok {
		t.Fatal("frame not parsed as GOOSE")
	}
	if gi.appid != 1 {
		t.Errorf("appid = %d; want 1", gi.appid)
	}
	if gi.gocbRef != gocb {
		t.Errorf("gocbRef = %q; want %q", gi.gocbRef, gocb)
	}
	if gi.goID != goid {
		t.Errorf("goID = %q; want %q", gi.goID, goid)
	}
	if gi.stNum != 5 || gi.sqNum != 10 {
		t.Errorf("stNum/sqNum = %d/%d; want 5/10", gi.stNum, gi.sqNum)
	}
	if gi.srcMAC != "00:11:22:33:44:55" {
		t.Errorf("srcMAC = %q", gi.srcMAC)
	}

	// A non-GOOSE (IPv4) frame must not parse.
	ip := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00, 0x45}
	if _, ok := parseGOOSE(ip); ok {
		t.Error("IPv4 frame should not parse as GOOSE")
	}
}
