package tcpstack

import "testing"

func TestParseV4RoundTrip(t *testing.T) {
	src := [4]byte{1, 2, 3, 4}
	dst := [4]byte{10, 0, 0, 5}
	payload := []byte("hello")
	pkt := clientPkt(src, dst, 40000, 80, 1000, 2000, PSH|ACK, tsOpt(7, 9), payload)

	s, ok := ParseV4(pkt)
	if !ok {
		t.Fatal("ParseV4 returned not-ok for a valid packet")
	}
	if s.SrcIP != src || s.DstIP != dst {
		t.Errorf("addresses = %v/%v; want %v/%v", s.SrcIP, s.DstIP, src, dst)
	}
	if !s.IsTCP || s.TCPShort || s.BadDataOff {
		t.Fatalf("flags: IsTCP=%v Short=%v BadOff=%v", s.IsTCP, s.TCPShort, s.BadDataOff)
	}
	if s.SrcPort != 40000 || s.DstPort != 80 {
		t.Errorf("ports = %d/%d", s.SrcPort, s.DstPort)
	}
	if s.Seq != 1000 || s.Ack != 2000 {
		t.Errorf("seq/ack = %d/%d", s.Seq, s.Ack)
	}
	if s.Flags != PSH|ACK {
		t.Errorf("flags = %#x", s.Flags)
	}
	if string(s.Payload) != "hello" {
		t.Errorf("payload = %q", s.Payload)
	}
	if !s.IPChecksumOK || !s.TCPChecksumOK {
		t.Errorf("checksums: ip=%v tcp=%v", s.IPChecksumOK, s.TCPChecksumOK)
	}
	if !s.HasTS || s.TSVal != 7 || s.TSEcr != 9 {
		t.Errorf("timestamp parse: has=%v val=%d ecr=%d", s.HasTS, s.TSVal, s.TSEcr)
	}
	if s.PayloadLen() != 5 {
		t.Errorf("PayloadLen = %d; want 5", s.PayloadLen())
	}
}

func TestParseV4RejectsNonIPv4(t *testing.T) {
	if _, ok := ParseV4([]byte{0x60, 0, 0, 0}); ok {
		t.Error("IPv6 nibble accepted as IPv4")
	}
	if _, ok := ParseV4([]byte{0x45, 0, 0}); ok {
		t.Error("runt accepted")
	}
}

func TestBuildV4ChecksumsVerify(t *testing.T) {
	// A packet built by buildV4 must parse back with both checksums valid.
	pkt := buildV4(out{
		src: [4]byte{10, 0, 0, 5}, dst: [4]byte{1, 2, 3, 4},
		srcPort: 80, dstPort: 40000,
		seq: 0x1000, ack: 0x2000,
		flags: SYN | ACK, window: 64240, ttl: 64, df: true,
		options: profiles["linux"].buildOptions(11, 22),
	})
	s, ok := ParseV4(pkt)
	if !ok || !s.IPChecksumOK || !s.TCPChecksumOK {
		t.Fatalf("built packet failed verification: ok=%v ip=%v tcp=%v", ok, s.IPChecksumOK, s.TCPChecksumOK)
	}
	if s.DataOff != 20+20 { // 20 base + 20 option bytes
		t.Errorf("data offset = %d; want 40", s.DataOff)
	}
	if s.Window != 64240 || s.TTL != 64 || !s.DF {
		t.Errorf("ip/tcp shape: win=%d ttl=%d df=%v", s.Window, s.TTL, s.DF)
	}
}

func TestParseV4DetectsBadChecksums(t *testing.T) {
	pkt := clientPkt([4]byte{1, 2, 3, 4}, [4]byte{10, 0, 0, 5}, 1, 80, 1, 0, SYN, nil, nil)
	bad := append([]byte(nil), pkt...)
	bad[10] ^= 0xff // corrupt the IP header checksum
	if s, _ := ParseV4(bad); s.IPChecksumOK {
		t.Error("corrupt IP checksum reported OK")
	}
	bad2 := append([]byte(nil), pkt...)
	bad2[20+16] ^= 0xff // corrupt the TCP checksum field
	if s, _ := ParseV4(bad2); s.TCPChecksumOK {
		t.Error("corrupt TCP checksum reported OK")
	}
}
