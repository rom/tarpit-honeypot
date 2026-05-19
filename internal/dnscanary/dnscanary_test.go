package dnscanary

import (
	"encoding/binary"
	"testing"
)

// buildQuery constructs a minimal DNS query for the given name + qtype.
func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234) // id
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qdcount
	pkt := append([]byte{}, hdr...)
	for _, label := range splitDot(name) {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], 1) // class IN
	return append(pkt, q...)
}

func splitDot(s string) []string {
	out := []string{}
	cur := ""
	for _, c := range s {
		if c == '.' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestParseQuery(t *testing.T) {
	pkt := buildQuery(t, "Foo.Example.Com", 1)
	name, qtype, ok := parseQuery(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	if name != "foo.example.com" {
		t.Errorf("name = %q; want foo.example.com", name)
	}
	if qtype != 1 {
		t.Errorf("qtype = %d; want 1", qtype)
	}
}

func TestParseQueryTooShort(t *testing.T) {
	if _, _, ok := parseQuery([]byte{0, 0, 0}); ok {
		t.Error("expected parse failure on short input")
	}
}

func TestBuildNXDOMAIN(t *testing.T) {
	q := buildQuery(t, "abc.example.com", 1)
	r := buildNXDOMAIN(q)
	if r == nil {
		t.Fatal("nil response")
	}
	if r[2]&0x80 == 0 {
		t.Error("QR bit not set")
	}
	if r[3]&0x0F != 3 {
		t.Errorf("RCODE = %d; want 3 (NXDOMAIN)", r[3]&0x0F)
	}
	if binary.BigEndian.Uint16(r[6:8]) != 0 {
		t.Error("answer count should be zero")
	}
}

func TestIsSubdomain(t *testing.T) {
	cases := []struct {
		name, suffix string
		want         bool
	}{
		{"foo.bar.example.com", "bar.example.com", true},
		{"bar.example.com", "bar.example.com", true},
		{"example.com", "bar.example.com", false},
		{"otherbar.example.com", "bar.example.com", false},
	}
	for _, c := range cases {
		if got := isSubdomain(c.name, c.suffix); got != c.want {
			t.Errorf("isSubdomain(%q, %q) = %v; want %v", c.name, c.suffix, got, c.want)
		}
	}
}
