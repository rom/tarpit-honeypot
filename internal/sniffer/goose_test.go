package sniffer

import (
	"encoding/binary"
	"testing"
	"time"
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

// helper: does the marker slice contain s?
func hasGooseMarker(ms []string, s string) bool {
	for _, m := range ms {
		if m == s {
			return true
		}
	}
	return false
}

func TestGOOSETrackerSpoofAndReplay(t *testing.T) {
	tr := newGOOSETracker()
	now := time.Now()
	base := gooseInfo{srcMAC: "00:11:22:33:44:55", gocbRef: "SIE/LLN0$GO$gcb01", stNum: 5, sqNum: 1}

	// First observation: establishes the legitimate publisher, no markers.
	if m := tr.analyze(base, now); len(m) != 0 {
		t.Fatalf("first frame should be clean; got %v", m)
	}
	// Same publisher, sqNum advances, same state: clean.
	f := base
	f.sqNum = 2
	if m := tr.analyze(f, now.Add(time.Second)); len(m) != 0 {
		t.Errorf("steady stream should be clean; got %v", m)
	}
	// A DIFFERENT publisher for the same control block with a higher stNum = spoof.
	spoof := base
	spoof.srcMAC = "de:ad:be:ef:00:01"
	spoof.stNum = 9
	if m := tr.analyze(spoof, now.Add(2*time.Second)); !hasGooseMarker(m, "goose-spoofing") {
		t.Errorf("spoof not detected; got %v", m)
	}
	// stNum going backwards = replay.
	replay := base
	replay.stNum = 3
	if m := tr.analyze(replay, now.Add(3*time.Second)); !hasGooseMarker(m, "goose-replay") {
		t.Errorf("replay not detected; got %v", m)
	}
}

func TestGOOSETrackerSimulationAndStorm(t *testing.T) {
	tr := newGOOSETracker()
	now := time.Now()
	gi := gooseInfo{srcMAC: "00:11:22:33:44:55", gocbRef: "gcb-x", stNum: 1, simulated: true}
	if m := tr.analyze(gi, now); !hasGooseMarker(m, "goose-simulation") {
		t.Errorf("simulate bit not detected; got %v", m)
	}
	// Storm: rapid stNum (state) increments within the window.
	st := newGOOSETracker()
	g := gooseInfo{srcMAC: "aa:bb:cc:dd:ee:ff", gocbRef: "gcb-y", stNum: 1}
	st.analyze(g, now) // establish
	stormed := false
	for i := 2; i <= 7; i++ {
		g.stNum = uint32(i)
		if hasGooseMarker(st.analyze(g, now.Add(time.Duration(i)*10*time.Millisecond)), "goose-storm") {
			stormed = true
		}
	}
	if !stormed {
		t.Error("rapid state changes not detected as a storm")
	}
}
