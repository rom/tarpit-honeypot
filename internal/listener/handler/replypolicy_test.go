package handler

import (
	"net"
	"testing"
)

func TestReplyPolicyMuteDropsWrites(t *testing.T) {
	defer SetReplyPolicy("full", false) // restore
	SetReplyPolicy("mute", false)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	gated := GateConn(c1, "http")
	if _, ok := gated.(*discardConn); !ok {
		t.Fatalf("mute should wrap conn in discardConn, got %T", gated)
	}
	// Write returns success but emits nothing (no reader needed).
	if n, err := gated.Write([]byte("hello")); n != 5 || err != nil {
		t.Errorf("discard write = (%d,%v); want (5,nil)", n, err)
	}
}

func TestReplyPolicyNonOTMutesOTOnly(t *testing.T) {
	defer SetReplyPolicy("full", false)
	SetReplyPolicy("non-ot", false)
	c1, _ := net.Pipe()
	defer c1.Close()
	if _, ok := GateConn(c1, "modbus").(*discardConn); !ok {
		t.Error("non-ot policy must mute the OT handler modbus")
	}
	if _, ok := GateConn(c1, "http").(*discardConn); ok {
		t.Error("non-ot policy must NOT mute the non-OT handler http")
	}
}

func TestReplyPolicyFullDefault(t *testing.T) {
	SetReplyPolicy("full", false)
	c1, _ := net.Pipe()
	defer c1.Close()
	if _, ok := GateConn(c1, "modbus").(*discardConn); ok {
		t.Error("full policy must not mute any handler")
	}
	if !FullInteractionAllowed() {
		t.Error("full policy should allow full interaction")
	}
}

func TestReplyPolicyFingerprintBlocksInteraction(t *testing.T) {
	defer SetReplyPolicy("full", false)
	SetReplyPolicy("fingerprint", false)
	if FullInteractionAllowed() {
		t.Error("fingerprint policy must disable deep interaction")
	}
	c1, _ := net.Pipe()
	defer c1.Close()
	if _, ok := GateConn(c1, "http").(*discardConn); ok {
		t.Error("fingerprint policy still replies (must not mute)")
	}
}

func TestAmplifierReplyToggle(t *testing.T) {
	defer SetReplyPolicy("full", false)
	SetReplyPolicy("full", true) // amplifier replies suppressed
	if AmplifierReplyAllowed("ntp", "mode7-private", &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}) {
		t.Error("no_amplifier_replies should suppress amplifier replies")
	}
	SetReplyPolicy("full", false)
	if !AmplifierReplyAllowed("ntp", "mode7-private", nil) {
		t.Error("default should allow amplifier replies")
	}
}

func TestIsOTHandler(t *testing.T) {
	for _, ot := range []string{"modbus", "s7", "dnp3", "bacnet", "iccp_secure", "osisoft_pi"} {
		if !IsOTHandler(ot) {
			t.Errorf("%s should be OT-class", ot)
		}
	}
	for _, notOT := range []string{"http", "ssh", "ftp", "mysql"} {
		if IsOTHandler(notOT) {
			t.Errorf("%s should NOT be OT-class", notOT)
		}
	}
}
