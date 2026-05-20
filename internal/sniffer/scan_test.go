package sniffer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestClassifyTCP(t *testing.T) {
	cases := []struct {
		flags byte
		want  scanKind
	}{
		{0x00, scanNull},
		{flagFIN, scanFIN},
		{flagFIN | flagPSH | flagURG, scanXmas},
		{flagSYN, scanSYN},
		{flagACK, scanACK},
		{flagSYN | flagACK, scanNone}, // normal handshake reply
		{flagPSH | flagACK, scanNone}, // normal data
		{flagRST | flagACK, scanNone},
		{0x40 | flagSYN, scanSYN}, // ECE bit ignored -> still SYN
	}
	for _, c := range cases {
		if got := classifyTCP(c.flags); got != c.want {
			t.Errorf("classifyTCP(%#02x) = %v; want %v", c.flags, got, c.want)
		}
	}
}

func buildFrame(src net.IP, proto byte, fragField uint16, l4 []byte) []byte {
	frame := make([]byte, 14)                        // Ethernet header (zeroed MACs)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // EtherType IPv4
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(ip[6:8], fragField)
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src.To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 1).To4())
	frame = append(frame, ip...)
	frame = append(frame, l4...)
	return frame
}

func tcpSeg(dstPort uint16, flags byte) []byte {
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	seg[12] = 0x50 // data offset 5
	seg[13] = flags
	return seg
}

func TestParseIPv4AndTCP(t *testing.T) {
	frame := buildFrame(net.IPv4(1, 2, 3, 4), 6, 0, tcpSeg(443, flagSYN))
	info, ok := parseIPv4(frame)
	if !ok {
		t.Fatal("parseIPv4 failed on a valid TCP frame")
	}
	if info.srcIP != "1.2.3.4" {
		t.Errorf("srcIP = %q; want 1.2.3.4", info.srcIP)
	}
	if info.proto != 6 {
		t.Errorf("proto = %d; want 6", info.proto)
	}
	if info.fragmented {
		t.Errorf("non-fragmented frame reported fragmented")
	}
	port, flags, ok := parseTCP(info.payload)
	if !ok || port != 443 || flags != flagSYN {
		t.Errorf("parseTCP = (%d,%#02x,%v); want (443,SYN,true)", port, flags, ok)
	}
}

func TestParseIPv4Fragmented(t *testing.T) {
	// MF bit (0x2000) set.
	frame := buildFrame(net.IPv4(1, 2, 3, 4), 6, 0x2000, tcpSeg(80, flagSYN))
	info, ok := parseIPv4(frame)
	if !ok || !info.fragmented {
		t.Errorf("MF-set frame not reported fragmented (ok=%v frag=%v)", ok, info.fragmented)
	}
	// Non-zero fragment offset.
	frame2 := buildFrame(net.IPv4(1, 2, 3, 4), 6, 0x0001, tcpSeg(80, flagSYN))
	info2, _ := parseIPv4(frame2)
	if !info2.fragmented {
		t.Errorf("offset-set frame not reported fragmented")
	}
}

func TestParseIPv4Rejects(t *testing.T) {
	if _, ok := parseIPv4([]byte{0x00}); ok {
		t.Error("parseIPv4 accepted a runt frame")
	}
	// EtherType ARP, not IPv4.
	bad := make([]byte, 40)
	binary.BigEndian.PutUint16(bad[12:14], 0x0806)
	if _, ok := parseIPv4(bad); ok {
		t.Error("parseIPv4 accepted a non-IPv4 EtherType")
	}
}

func TestScanTrackerStealthFiresAtThreshold(t *testing.T) {
	tr := newScanTracker(time.Minute, 16, 3)
	now := time.Now()
	src := "9.9.9.9"
	if _, fire := tr.observe(src, 1, scanXmas, now); fire {
		t.Fatal("fired at 1 port (stealth threshold is 3)")
	}
	if _, fire := tr.observe(src, 2, scanXmas, now); fire {
		t.Fatal("fired at 2 ports")
	}
	count, fire := tr.observe(src, 3, scanXmas, now)
	if !fire || count != 3 {
		t.Fatalf("expected fire at 3 ports; got fire=%v count=%d", fire, count)
	}
	if _, fire := tr.observe(src, 4, scanXmas, now); fire {
		t.Fatal("fired again within the same window (should dedup)")
	}
}

func TestScanTrackerVolumeThreshold(t *testing.T) {
	tr := newScanTracker(time.Minute, 4, 3)
	now := time.Now()
	src := "8.8.8.8"
	for p := uint16(1); p <= 3; p++ {
		if _, fire := tr.observe(src, p, scanSYN, now); fire {
			t.Fatalf("SYN fired early at port %d", p)
		}
	}
	if _, fire := tr.observe(src, 4, scanSYN, now); !fire {
		t.Fatal("SYN did not fire at volume threshold 4")
	}
}

func TestScanTrackerWindowResets(t *testing.T) {
	tr := newScanTracker(time.Second, 16, 3)
	now := time.Now()
	src := "7.7.7.7"
	tr.observe(src, 1, scanXmas, now)
	tr.observe(src, 2, scanXmas, now)
	// Past the window: state resets, so the next two ports start fresh.
	later := now.Add(2 * time.Second)
	if _, fire := tr.observe(src, 3, scanXmas, later); fire {
		t.Fatal("fired right after window reset (count should be 1)")
	}
}

func TestScanTrackerNoneIgnored(t *testing.T) {
	tr := newScanTracker(time.Minute, 1, 1)
	if _, fire := tr.observe("1.1.1.1", 1, scanNone, time.Now()); fire {
		t.Fatal("scanNone produced a fire")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(time.Minute)
	now := time.Now()
	if !rl.allow("k", now) {
		t.Fatal("first allow denied")
	}
	if rl.allow("k", now.Add(time.Second)) {
		t.Fatal("second allow within window not denied")
	}
	if !rl.allow("k", now.Add(2*time.Minute)) {
		t.Fatal("allow after window denied")
	}
}

func TestFmtTCPFlags(t *testing.T) {
	if got := fmtTCPFlags(flagACK | flagSYN); got != "ACK,SYN" {
		t.Errorf("fmtTCPFlags(ACK|SYN) = %q; want ACK,SYN", got)
	}
	if got := fmtTCPFlags(0); got != "none" {
		t.Errorf("fmtTCPFlags(0) = %q; want none", got)
	}
}
