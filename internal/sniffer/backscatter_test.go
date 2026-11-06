package sniffer

import (
	"testing"
	"time"
)

func TestBackscatterClassify(t *testing.T) {
	cases := []struct {
		flags byte
		want  backscatterKind
	}{
		{flagSYN | flagACK, bsSynAck},
		{flagRST, bsRst},
		{flagRST | flagACK, bsRst},
		{flagSYN, ""},           // bare SYN = ordinary connect/scan
		{flagACK, ""},           // bare ACK
		{flagSYN | flagRST, ""}, // SYN+RST is not a clean reply
		{flagFIN | flagACK, ""}, // teardown
	}
	for _, c := range cases {
		if got := backscatterTCP(c.flags); got != c.want {
			t.Errorf("backscatterTCP(0x%02x)=%q want %q", c.flags, got, c.want)
		}
	}
	if backscatterICMP(3, false) != bsICMPUnreach {
		t.Error("ICMPv4 type 3 should be unreachable backscatter")
	}
	if backscatterICMP(11, false) != bsICMPTimeEx {
		t.Error("ICMPv4 type 11 should be time-exceeded backscatter")
	}
	if backscatterICMP(1, true) != bsICMPUnreach {
		t.Error("ICMPv6 type 1 should be unreachable backscatter")
	}
	if backscatterICMP(8, false) != "" {
		t.Error("ICMPv4 echo (type 8) is not backscatter")
	}
}

func TestBackscatterTrackerDistinctSources(t *testing.T) {
	now := time.Now()
	tr := newBackscatterTracker(30*time.Second, 16)

	// The same single source repeating never fires (our own replies look like
	// this — one source).
	for i := 0; i < 50; i++ {
		if _, fire := tr.observe(bsSynAck, "198.51.100.9", now); fire {
			t.Fatal("a single repeating source must not trip backscatter")
		}
	}
	// 16 distinct sources in the window → fire exactly once.
	fires := 0
	for i := 0; i < 16; i++ {
		src := "203.0.113." + itoaTest(i)
		if _, fire := tr.observe(bsSynAck, src, now); fire {
			fires++
		}
	}
	if fires != 1 {
		t.Errorf("distinct-source backscatter fired %d times, want 1", fires)
	}
	// A different reply kind is tracked independently.
	if _, fire := tr.observe(bsRst, "192.0.2.1", now); fire {
		t.Error("one RST source should not fire")
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
