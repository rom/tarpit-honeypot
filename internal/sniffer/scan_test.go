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
		{flagFIN | flagACK, scanMaimon}, // nmap -sM
		{flagSYN | flagACK, scanNone},   // normal handshake reply
		{flagPSH | flagACK, scanNone},   // normal data
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
	if info.ttl != 64 {
		t.Errorf("ttl = %d; want 64", info.ttl)
	}
	port, flags, ok := parseTCP(info.payload)
	if !ok || port != 443 || flags != flagSYN {
		t.Errorf("parseTCP = (%d,%#02x,%v); want (443,SYN,true)", port, flags, ok)
	}
}

func TestParseUDPAndScanKind(t *testing.T) {
	// UDP header: src(2) dst(2) len(2) csum(2).
	seg := make([]byte, 8)
	binary.BigEndian.PutUint16(seg[2:4], 53)
	port, ok := parseUDP(seg)
	if !ok || port != 53 {
		t.Errorf("parseUDP = (%d,%v); want (53,true)", port, ok)
	}
	if _, ok := parseUDP(seg[:7]); ok {
		t.Error("parseUDP accepted a runt header")
	}
	// UDP scans are volume-gated (not stealth) and carry their own rule id.
	if scanUDP.stealth() {
		t.Error("scanUDP must not be treated as a stealth probe")
	}
	if scanUDP.ruleID() != "sniffer:udp_scan" {
		t.Errorf("scanUDP.ruleID() = %q; want sniffer:udp_scan", scanUDP.ruleID())
	}
}

func TestEncapClassifiers(t *testing.T) {
	protos := map[byte]string{4: "ipip", 41: "6in4", 47: "gre", 97: "etherip", 115: "l2tp", 6: "", 17: "", 1: ""}
	for p, want := range protos {
		if got := encapByProto(p); got != want {
			t.Errorf("encapByProto(%d) = %q; want %q", p, got, want)
		}
	}
	ports := map[uint16]string{4789: "vxlan", 8472: "vxlan", 6081: "geneve", 1701: "l2tp", 3544: "teredo", 4754: "gre-in-udp", 53: "", 443: ""}
	for p, want := range ports {
		if got := encapByUDPPort(p); got != want {
			t.Errorf("encapByUDPPort(%d) = %q; want %q", p, got, want)
		}
	}
}

// stpFrame builds an 802.3/LLC spanning-tree BPDU frame with the given BPDU
// version byte (0=STP, 2=RSTP, 3=MSTP).
func stpFrame(version byte) []byte {
	frame := make([]byte, 14)
	copy(frame[0:6], []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}) // bridge group
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 38) // 802.3 length (<= 1500)
	llc := []byte{0x42, 0x42, 0x03}              // LLC: STP
	bpdu := []byte{0x00, 0x00, version, 0x00}    // protocol id, version, type
	return append(append(frame, llc...), bpdu...)
}

func TestParseSTP(t *testing.T) {
	cases := map[byte]string{0: "stp", 2: "rstp", 3: "mstp"}
	for ver, want := range cases {
		variant, mac, ok := parseSTP(stpFrame(ver))
		if !ok || variant != want {
			t.Errorf("parseSTP(version=%d) = (%q,%v); want (%q,true)", ver, variant, ok, want)
		}
		if mac != "02:00:00:00:00:01" {
			t.Errorf("parseSTP src MAC = %q; want 02:00:00:00:00:01", mac)
		}
	}
	// A normal IPv4 frame is not a BPDU.
	if _, _, ok := parseSTP(buildFrame(net.IPv4(1, 2, 3, 4), 6, 0, tcpSeg(443, flagSYN))); ok {
		t.Error("parseSTP matched a non-BPDU IPv4 frame")
	}
	// Right dest MAC but an EtherType (>1500) instead of an 802.3 length.
	bad := stpFrame(0)
	binary.BigEndian.PutUint16(bad[12:14], 0x0800)
	if _, _, ok := parseSTP(bad); ok {
		t.Error("parseSTP matched a frame with an EtherType, not a length")
	}
}

func TestEncap41Subtype(t *testing.T) {
	mk := func(srcHi, srcLo []byte) []byte {
		p := make([]byte, 40)
		p[0] = 0x60 // IPv6 version
		copy(p[8:24], srcHi)
		copy(p[24:40], srcLo)
		return p
	}
	// 6to4: 2002::/16 in the source address.
	v6to4 := mk([]byte{0x20, 0x02, 0, 0}, make([]byte, 16))
	if got := encap41Subtype(v6to4); got != "6to4" {
		t.Errorf("6to4 = %q", got)
	}
	// ISATAP: ...:0000:5efe interface id in the destination.
	iid := make([]byte, 16)
	iid[8], iid[9], iid[10], iid[11] = 0x00, 0x00, 0x5e, 0xfe
	if got := encap41Subtype(mk(make([]byte, 16), iid)); got != "isatap" {
		t.Errorf("isatap = %q", got)
	}
	// Plain 6in4.
	if got := encap41Subtype(mk(make([]byte, 16), make([]byte, 16))); got != "6in4" {
		t.Errorf("6in4 = %q", got)
	}
}

func TestICMPEchoTunnel(t *testing.T) {
	// Small standard ping → not a tunnel.
	small := append([]byte{8, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 56)...)
	if _, tun := icmpEchoTunnel(small); tun {
		t.Errorf("standard ping flagged as tunnel")
	}
	// Large, high-entropy echo payload → tunnel.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i * 7) // spreads across many distinct values
	}
	big := append([]byte{0, 0, 0, 0, 0, 0, 0, 0}, data...) // echo reply
	if n, tun := icmpEchoTunnel(big); !tun || n != 256 {
		t.Errorf("large high-entropy echo not flagged: n=%d tun=%v", n, tun)
	}
	// A non-echo ICMP type is ignored.
	if _, tun := icmpEchoTunnel(append([]byte{3, 0, 0, 0, 0, 0, 0, 0}, data...)); tun {
		t.Errorf("non-echo ICMP type flagged")
	}
}

func TestOSGuessFromTTL(t *testing.T) {
	cases := []struct {
		ttl   byte
		guess string
		hops  int
	}{
		{64, "linux/unix", 0},
		{57, "linux/unix", 7},
		{128, "windows", 0},
		{120, "windows", 8},
		{255, "network/embedded", 0},
		{250, "network/embedded", 5},
		{0, "", 0},
	}
	for _, c := range cases {
		g, h := osGuessFromTTL(c.ttl)
		if g != c.guess || h != c.hops {
			t.Errorf("osGuessFromTTL(%d) = (%q,%d); want (%q,%d)", c.ttl, g, h, c.guess, c.hops)
		}
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
