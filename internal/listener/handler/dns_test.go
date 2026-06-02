package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// buildDNSQuery assembles a minimal single-question DNS query message.
func buildDNSQuery(name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // ID
	msg[2] = 0x01                                // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	for _, label := range bytes.Split([]byte(name), []byte(".")) {
		if len(label) == 0 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // root
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1) // QCLASS IN
	return msg
}

// dnsAnswerCount reads ANCOUNT out of a response header.
func dnsAnswerCount(resp []byte) uint16 {
	if len(resp) < 8 {
		return 0
	}
	return binary.BigEndian.Uint16(resp[6:8])
}

func TestDNSAnswerARecord(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
	q := buildDNSQuery("example.com", 1)
	res, err := (&dnsHandler{}).Handle(context.Background(), q, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["qname"] != "example.com" {
		t.Errorf("qname = %v; want example.com", res.Meta["qname"])
	}
	if res.Meta["qtype_name"] != "A" {
		t.Errorf("qtype_name = %v; want A", res.Meta["qtype_name"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 DNS reply; got %d", len(pc.written))
	}
	resp := pc.written[0]
	if resp[2]&0x80 == 0 {
		t.Error("QR bit not set on response")
	}
	if dnsAnswerCount(resp) != 1 {
		t.Fatalf("ANCOUNT = %d; want 1", dnsAnswerCount(resp))
	}
	// The A rdata is the final 4 bytes; must not be RFC1918 / loopback.
	ip := resp[len(resp)-4:]
	switch {
	case ip[0] == 10, ip[0] == 127, ip[0] == 0:
		t.Errorf("fake A record in reserved range: %v", net.IP(ip))
	case ip[0] == 192 && ip[1] == 168:
		t.Errorf("fake A record in RFC1918: %v", net.IP(ip))
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		t.Errorf("fake A record in RFC1918: %v", net.IP(ip))
	}
}

func TestDNSFakeIPv4AvoidsReserved(t *testing.T) {
	d := &dnsHandler{}
	for i := 0; i < 2000; i++ {
		ip := d.fakeIPv4("host-" + itoa(i) + ".example.com")
		switch {
		case ip[0] == 0 || ip[0] == 10 || ip[0] == 127 || ip[0] == 169 || ip[0] == 100 || ip[0] >= 224:
			t.Fatalf("reserved first octet %v", net.IP(ip[:]))
		case ip[0] == 192 && ip[1] == 168:
			t.Fatalf("RFC1918 192.168 %v", net.IP(ip[:]))
		case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
			t.Fatalf("RFC1918 172.16/12 %v", net.IP(ip[:]))
		}
	}
}

func TestDNSDeterministicPerName(t *testing.T) {
	d := &dnsHandler{}
	a := d.fakeIPv4("host.example.org")
	b := d.fakeIPv4("host.example.org")
	c := d.fakeIPv4("other.example.org")
	if a != b {
		t.Errorf("same name resolved differently: %v vs %v", a, b)
	}
	if a == c {
		t.Errorf("different names collided: %v", a)
	}
}

func TestDNSAnswerAAAARecord(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
	q := buildDNSQuery("ipv6.example.com", 28)
	if _, err := (&dnsHandler{}).Handle(context.Background(), q, src, pc, config.Listener{}); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	resp := pc.written[0]
	if dnsAnswerCount(resp) != 1 {
		t.Fatalf("ANCOUNT = %d; want 1", dnsAnswerCount(resp))
	}
	rdlen := binary.BigEndian.Uint16(resp[len(resp)-18 : len(resp)-16])
	if rdlen != 16 {
		t.Errorf("AAAA rdlength = %d; want 16", rdlen)
	}
}

func TestDNSAnswerMXAndTXT(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		label string
	}{
		{"mail.example.com", 15, "MX"},
		{"example.com", 16, "TXT"},
		{"example.com", 2, "NS"},
		{"www.example.com", 5, "CNAME"},
	} {
		pc := &fakePacketConn{}
		src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
		q := buildDNSQuery(tc.name, tc.qtype)
		if _, err := (&dnsHandler{}).Handle(context.Background(), q, src, pc, config.Listener{}); err != nil {
			t.Fatalf("%s: %v", tc.label, err)
		}
		if len(pc.written) != 1 {
			t.Fatalf("%s: expected 1 reply; got %d", tc.label, len(pc.written))
		}
		if dnsAnswerCount(pc.written[0]) != 1 {
			t.Errorf("%s: ANCOUNT = %d; want 1", tc.label, dnsAnswerCount(pc.written[0]))
		}
	}
}

func TestDNSUnsupportedTypeNoAnswer(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
	q := buildDNSQuery("example.com", 99) // SPF (legacy/unsupported) -> NOERROR/0
	if _, err := (&dnsHandler{}).Handle(context.Background(), q, src, pc, config.Listener{}); err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply (NOERROR/0 answers); got %d", len(pc.written))
	}
	if got := dnsAnswerCount(pc.written[0]); got != 0 {
		t.Errorf("ANCOUNT = %d; want 0 for unsupported type", got)
	}
}

func TestDNSTunnelingAnomaly(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
	// A long high-entropy label is the classic DNS-exfil shape.
	q := buildDNSQuery("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5.example.com", 1)
	res, err := (&dnsHandler{}).Handle(context.Background(), q, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	found := false
	for _, a := range anoms {
		if a == "dns-high-entropy-label" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dns-high-entropy-label anomaly; got %v", anoms)
	}
}

func TestDNSZoneTransferFlagged(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 2), Port: 5301}
	// qtype 252 = AXFR (full zone transfer).
	q := buildDNSQuery("internal.example.com", 252)
	res, err := (&dnsHandler{}).Handle(context.Background(), q, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if anoms, _ := res.Meta["anomalies"].([]string); !containsStr(anoms, "dns-zone-transfer") {
		t.Errorf("AXFR not flagged: %v", res.Meta["anomalies"])
	}
}

func TestDNSMalformedShort(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 5300}
	res, err := (&dnsHandler{}).Handle(context.Background(), []byte{0, 1, 2}, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["malformed_dns"] != true {
		t.Errorf("short message not flagged malformed: %v", res.Meta)
	}
	if len(pc.written) != 0 {
		t.Errorf("malformed query must not be answered; got %d", len(pc.written))
	}
}

// scriptConn is a net.Conn that replays a fixed read buffer (then EOF) and
// captures everything written. Synchronous and single-goroutine — unlike
// net.Pipe it never blocks, so a client-first request/response protocol like
// DNS-over-TCP can be driven inline without deadlocking.
type scriptConn struct {
	rd *bytes.Reader
	wr bytes.Buffer
}

func (c *scriptConn) Read(p []byte) (int, error)       { return c.rd.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error)      { return c.wr.Write(p) }
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return fuzzAddr{} }
func (c *scriptConn) RemoteAddr() net.Addr             { return fuzzAddr{} }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// frameDNS prepends the 2-byte big-endian length prefix DNS-over-TCP uses.
func frameDNS(msg []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	return append(out, msg...)
}

func TestDNSOverTCP(t *testing.T) {
	// Two pipelined length-framed queries (A, then AXFR). The handler should
	// answer both with length-framed responses, capture the first query's
	// name, and flag the zone-transfer attempt.
	var in bytes.Buffer
	in.Write(frameDNS(buildDNSQuery("example.com", 1)))
	in.Write(frameDNS(buildDNSQuery("corp.example.local", 252))) // AXFR
	conn := &scriptConn{rd: bytes.NewReader(in.Bytes())}

	res, err := (&dnsTCP{inner: &dnsHandler{}}).Handle(context.Background(), conn, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["transport"] != "tcp" {
		t.Errorf("transport meta = %v; want tcp", res.Meta["transport"])
	}
	if res.Meta["qname"] != "example.com" {
		t.Errorf("qname = %v; want example.com (first query)", res.Meta["qname"])
	}
	if res.Meta["dns_queries"] != 2 {
		t.Errorf("dns_queries = %v; want 2", res.Meta["dns_queries"])
	}
	if !hasAnomaly(res, "dns-zone-transfer") {
		t.Errorf("AXFR over TCP should flag dns-zone-transfer; anomalies=%v", res.Meta["anomalies"])
	}

	// Decode the captured length-framed responses and check the first one.
	out := res2frames(t, conn.wr.Bytes())
	if len(out) != 2 {
		t.Fatalf("expected 2 framed responses; got %d", len(out))
	}
	first := out[0]
	if len(first) < 4 || first[2]&0x80 == 0 {
		t.Error("QR bit not set on first TCP response")
	}
	if dnsAnswerCount(first) != 1 {
		t.Errorf("first ANCOUNT = %d; want 1 (A record)", dnsAnswerCount(first))
	}
}

// res2frames splits a stream of 2-byte-length-prefixed DNS messages.
func res2frames(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	for len(b) >= 2 {
		n := int(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
		if len(b) < n {
			t.Fatalf("truncated framed response: want %d, have %d", n, len(b))
		}
		frames = append(frames, b[:n])
		b = b[n:]
	}
	return frames
}
