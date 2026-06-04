package p0f

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinDBCompiles(t *testing.T) {
	if New().Count() < 10 {
		t.Fatalf("expected the curated DB to compile, got %d", New().Count())
	}
}

// buildSYN crafts a TCP SYN segment with the given window and option layout.
func buildSYN(window uint16, mss uint16, wscale byte, opts []byte) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[14:16], window)
	tcp := append(hdr, opts...)
	// pad options to a 4-byte boundary and set data offset.
	for len(tcp)%4 != 0 {
		tcp = append(tcp, 0)
	}
	tcp[12] = byte(len(tcp)/4) << 4
	tcp[13] = 0x02 // SYN
	return tcp
}

// mssOpt / wsOpt / sokOpt / tsOpt / nop build TCP option byte sequences.
func mssOpt(v uint16) []byte { b := []byte{2, 4, 0, 0}; binary.BigEndian.PutUint16(b[2:], v); return b }
func wsOpt(s byte) []byte    { return []byte{3, 3, s} }

var (
	sokOpt = []byte{4, 2}
	tsOpt  = []byte{8, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	nop    = []byte{1}
)

func TestFromSYNLinux(t *testing.T) {
	// Linux 3.11+: window = mss*20, wscale 7, layout mss,sok,ts,nop,ws, df,id+.
	mss := uint16(1460)
	opts := concat(mssOpt(mss), sokOpt, tsOpt, nop, wsOpt(7))
	tcp := buildSYN(mss*20, mss, 7, opts)

	s, ok := FromSYN(4, 64, true, 0x1234, 0, tcp, 0)
	if !ok {
		t.Fatal("FromSYN failed")
	}
	if s.ITTL != 64 || s.MSS != int(mss) || s.WScale != 7 {
		t.Errorf("parsed wrong: %+v", s)
	}
	wantLayout := []string{"mss", "sok", "ts", "nop", "ws"}
	if !eqStrings(s.Layout, wantLayout) {
		t.Errorf("layout = %v, want %v", s.Layout, wantLayout)
	}
	if label := New().Match(s); label != "Linux 3.11 and newer" {
		t.Errorf("match = %q, want Linux 3.11 and newer (sig %s)", label, s)
	}
}

func TestFromSYNWindows10(t *testing.T) {
	// Windows 10: window 64240, wscale 8, layout mss,nop,ws,nop,nop,sok.
	mss := uint16(1460)
	opts := concat(mssOpt(mss), nop, wsOpt(8), nop, nop, sokOpt)
	tcp := buildSYN(64240, mss, 8, opts)
	s, _ := FromSYN(4, 128, true, 0x4321, 0, tcp, 0)
	if label := New().Match(s); label != "Windows 10" {
		t.Errorf("match = %q, want Windows 10 (sig %s)", label, s)
	}
}

func TestNoMatchFallsThrough(t *testing.T) {
	// A SYN with a bizarre layout matches nothing.
	tcp := buildSYN(1234, 1460, 0, concat(mssOpt(1460), tsOpt))
	s, _ := FromSYN(4, 200, false, 0, 0, tcp, 0)
	if label := New().Match(s); label != "" {
		t.Errorf("unexpected match %q for unknown stack", label)
	}
}

func TestWsizeExpressions(t *testing.T) {
	cases := []struct {
		expr  string
		mss   int
		wsize int
		match bool
	}{
		{"mss*20", 1460, 1460 * 20, true},
		{"mss*20", 1460, 1460 * 19, false},
		{"mtu*2", 1460, (1460 + 40) * 2, true},
		{"65535", 0, 65535, true},
		{"%8192", 0, 16384, true},
		{"*", 0, 12345, true},
	}
	for _, c := range cases {
		w := parseWsize(c.expr)
		got := w.matches(Signature{MSS: c.mss, WSize: c.wsize})
		if got != c.match {
			t.Errorf("wsize %q (mss=%d wsize=%d) = %v, want %v", c.expr, c.mss, c.wsize, got, c.match)
		}
	}
}

func TestLoadFile(t *testing.T) {
	fp := `[mtu]
label = sneaky
sig = 1500

[tcp:request]
label = TestStack 1.0
sig   = *:64:0:*:mss*7,5:mss,sok,ts,nop,ws:df,id+:0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "p0f.fp")
	if err := os.WriteFile(path, []byte(fp), 0o644); err != nil {
		t.Fatal(err)
	}
	db := New()
	base := db.Count()
	n, err := db.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || db.Count() != base+1 {
		t.Fatalf("added %d (total %d, base %d)", n, db.Count(), base)
	}
	mss := uint16(1460)
	opts := concat(mssOpt(mss), sokOpt, tsOpt, nop, wsOpt(5))
	s, _ := FromSYN(4, 64, true, 0x1, 0, buildSYN(mss*7, mss, 5, opts), 0)
	if label := db.Match(s); label != "TestStack 1.0" {
		t.Errorf("loaded sig didn't match: %q (%s)", label, s)
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
