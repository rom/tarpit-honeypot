package tcpstack

import "testing"

func TestProfileForFamilies(t *testing.T) {
	cases := map[string]struct {
		wantName string
		wantTTL  uint8
	}{
		"windows":      {"windows", 128},
		"ubuntu":       {"linux", 64},
		"debian":       {"linux", 64},
		"rhel":         {"linux", 64},
		"arch":         {"linux", 64}, // unknown family -> linux default
		"bsd":          {"bsd", 64},
		"freebsd":      {"bsd", 64},
		"pfsense":      {"bsd", 64},   // FreeBSD-based, not OT
		"mikrotik":     {"linux", 64}, // RouterOS is Linux-based, not OT
		"moxa":         {"ot", 255},
		"siemens":      {"ot", 255},
		"cisco":        {"ot", 255},
		"SIEMENS":      {"ot", 255}, // case-insensitive
		"unknown-junk": {"linux", 64},
	}
	for fam, want := range cases {
		p := ProfileFor(fam)
		if p.Name != want.wantName || p.TTL != want.wantTTL {
			t.Errorf("ProfileFor(%q) = {%s TTL %d}; want {%s TTL %d}",
				fam, p.Name, p.TTL, want.wantName, want.wantTTL)
		}
	}
}

func TestBuildOptionsLinuxLayout(t *testing.T) {
	p := profiles["linux"]
	b := p.buildOptions(0x11223344, 0x55667788)
	// MSS(4) SACK(2) TS(10) NOP(1) WScale(3) = 20 bytes, already aligned.
	want := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		4, 2, // SACK permitted
		8, 10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // timestamp
		1,       // NOP
		3, 3, 7, // window scale 7
	}
	if len(b) != len(want) {
		t.Fatalf("linux options len = %d; want %d (%v)", len(b), len(want), b)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("linux options[%d] = %d; want %d\n got %v\nwant %v", i, b[i], want[i], b, want)
		}
	}
	if len(b)%4 != 0 {
		t.Errorf("options not 4-byte aligned: %d", len(b))
	}
}

func TestBuildOptionsWindowsLayout(t *testing.T) {
	p := profiles["windows"]
	b := p.buildOptions(1, 2)
	// Windows: MSS NOP WScale NOP NOP SACK, no timestamp.
	want := []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2}
	if len(b) != len(want) {
		t.Fatalf("windows options = %v; want %v", b, want)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("windows options = %v; want %v", b, want)
		}
	}
}

func TestBuildOptionsOTMinimal(t *testing.T) {
	p := profiles["ot"]
	b := p.buildOptions(1, 2)
	want := []byte{2, 4, 0x05, 0xb4} // MSS only
	if len(b) != len(want) {
		t.Fatalf("ot options = %v; want %v", b, want)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("ot options = %v; want %v", b, want)
		}
	}
}
