package tcpstack

import "testing"

func classifyPkt(t *testing.T, pkt []byte) []string {
	t.Helper()
	s, ok := ParseV4(pkt)
	if !ok {
		t.Fatal("ParseV4 not-ok")
	}
	return Classify(s)
}

func TestClassifyCleanSegmentIsNil(t *testing.T) {
	pkt := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)
	if m := classifyPkt(t, pkt); m != nil {
		t.Errorf("clean SYN classified as %v", m)
	}
}

func TestClassifyStealthFlagCombos(t *testing.T) {
	host := [4]byte{10, 0, 0, 5}
	cl := [4]byte{1, 2, 3, 4}
	cases := []struct {
		name  string
		flags byte
		want  string
	}{
		{"null", 0, "tcp-null"},
		{"fin", FIN, "tcp-fin-scan"},
		{"xmas", FIN | PSH | URG, "tcp-xmas"},
		{"syn-fin", SYN | FIN, "tcp-syn-fin"},
		{"syn-rst", SYN | RST, "tcp-syn-rst"},
	}
	for _, c := range cases {
		pkt := clientPkt(cl, host, 40000, 80, 1, 0, c.flags, nil, nil)
		m := classifyPkt(t, pkt)
		if !has(m, c.want) {
			t.Errorf("%s: classified %v; want %q", c.name, m, c.want)
		}
	}
}

func TestClassifyDataInSyn(t *testing.T) {
	pkt := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, []byte("x"))
	if m := classifyPkt(t, pkt); !has(m, "tcp-data-in-syn") {
		t.Errorf("data-in-syn not flagged: %v", m)
	}
}

func TestClassifyBadChecksums(t *testing.T) {
	pkt := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)
	ipBad := append([]byte(nil), pkt...)
	ipBad[10] ^= 0xff
	if m := classifyPkt(t, ipBad); !has(m, "ip-bad-checksum") {
		t.Errorf("ip-bad-checksum not flagged: %v", m)
	}
	tcpBad := append([]byte(nil), pkt...)
	tcpBad[20+16] ^= 0xff
	if m := classifyPkt(t, tcpBad); !has(m, "tcp-bad-checksum") {
		t.Errorf("tcp-bad-checksum not flagged: %v", m)
	}
}

func TestClassifyTruncatedAndBadDataOffset(t *testing.T) {
	full := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)

	short := full[:20+10] // only 10 bytes of TCP header survive
	if m := classifyPkt(t, short); !has(m, "tcp-truncated") {
		t.Errorf("truncated TCP not flagged: %v", m)
	}

	badOff := append([]byte(nil), full...)
	badOff[20+12] = 0xF0 | (badOff[20+12] & 0x0f) // data offset 15 words = 60 bytes > header
	if m := classifyPkt(t, badOff); !has(m, "tcp-bad-dataoffset") {
		t.Errorf("bad data-offset not flagged: %v", m)
	}
}

func TestClassifyBadHeaderLen(t *testing.T) {
	full := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)
	bad := append([]byte(nil), full...)
	bad[0] = 0x4F // version 4, IHL 15 (60 bytes) > packet length
	m := classifyPkt(t, bad)
	if len(m) != 1 || m[0] != "ip-bad-header-len" {
		t.Errorf("bad IHL classified %v; want [ip-bad-header-len]", m)
	}
}

func TestClassifyFragment(t *testing.T) {
	full := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)
	frag := append([]byte(nil), full...)
	frag[6] = 0x20 // set MF bit; recompute IP checksum
	frag[10], frag[11] = 0, 0
	cs := ipChecksum(frag[:20])
	frag[10] = byte(cs >> 8)
	frag[11] = byte(cs)
	if m := classifyPkt(t, frag); !has(m, "ip-fragmented") {
		t.Errorf("fragment not flagged: %v", m)
	}
}

func TestIsMalformed(t *testing.T) {
	clean := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)
	s, _ := ParseV4(clean)
	if IsMalformed(s) {
		t.Error("clean SYN reported malformed")
	}
	nul := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, 0, nil, nil)
	s2, _ := ParseV4(nul)
	if !IsMalformed(s2) {
		t.Error("NULL scan not reported malformed")
	}
}
