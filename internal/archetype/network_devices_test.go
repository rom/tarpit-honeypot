package archetype

import "testing"

func TestMikroTikSignatures(t *testing.T) {
	p := Lookup("mikrotik router")
	if p == nil {
		t.Fatal("mikrotik router did not resolve")
	}
	if p.Family != "mikrotik" {
		t.Errorf("family = %q; want mikrotik", p.Family)
	}
	if p.SSHBanner() != "SSH-2.0-ROSSSH" {
		t.Errorf("RouterOS SSH banner = %q; want SSH-2.0-ROSSSH", p.SSHBanner())
	}
	if p.ICMPTTL() != 64 {
		t.Errorf("RouterOS TTL = %d; want 64 (Linux-based)", p.ICMPTTL())
	}
	if !p.HasMACOUI() || p.MACOUI() != [3]byte{0x4c, 0x5e, 0x0c} {
		t.Errorf("RouterOS MAC OUI wrong: %v", p.MACOUI())
	}
}

func TestTeltonikaSignatures(t *testing.T) {
	p := Lookup("teltonika RUT240")
	if p == nil {
		t.Fatal("teltonika RUT240 did not resolve")
	}
	if p.Family != "teltonika" {
		t.Errorf("family = %q; want teltonika", p.Family)
	}
	if p.SNMPSysObjectID() != ".1.3.6.1.4.1.48690" {
		t.Errorf("Teltonika sysObjectID = %q; want enterprise .48690", p.SNMPSysObjectID())
	}
	if p.MACOUI() != [3]byte{0x20, 0x97, 0x27} {
		t.Errorf("Teltonika MAC OUI wrong: %v", p.MACOUI())
	}
}

func TestCiscoCatalystSwitch(t *testing.T) {
	p := Lookup("cisco catalyst switch")
	if p == nil {
		t.Fatal("cisco catalyst switch did not resolve")
	}
	if p.Family != "cisco" {
		t.Errorf("family = %q; want cisco", p.Family)
	}
	if p.ICMPTTL() != 255 {
		t.Errorf("Cisco TTL = %d; want 255 (switch/router)", p.ICMPTTL())
	}
	if len(p.VLANs()) == 0 {
		t.Errorf("Catalyst switch should expose a VLAN table")
	}
	if len(p.DefaultServices()) == 0 {
		t.Errorf("Catalyst switch should expose default services")
	}
}
