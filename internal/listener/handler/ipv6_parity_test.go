package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestLocalIPOfHandlesV4AndV6(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 53}, "10.0.0.1"},
		{&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}, "2001:db8::1"},
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 21}, "fe80::1"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := localIPOf(c.addr); got != c.want {
			t.Errorf("localIPOf(%v) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// llmnrQuery builds an LLMNR query for `wpad` of the given qtype.
func llmnrQuery(qtype uint16) []byte {
	q := []byte{0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, 4, 'w', 'p', 'a', 'd', 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1) // class IN
	return q
}

func TestLLMNRAnswersAAAAOverIPv6(t *testing.T) {
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::99"), Port: 5355}}
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 50000}
	res, _ := (&llmnr{}).Handle(context.Background(), llmnrQuery(28), src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected an AAAA poison reply over IPv6, got %d writes", len(pc.written))
	}
	reply := pc.written[0]
	// Answer record type must be AAAA (28) and rdata 16 bytes = our v6 addr.
	if !containsBytes(reply, net.ParseIP("2001:db8::99").To16()) {
		t.Errorf("AAAA reply does not embed our IPv6 address: % x", reply)
	}
	_ = res
}

func TestLLMNRAnswersAOverIPv4(t *testing.T) {
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 50), Port: 5355}}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 50000}
	_, _ = (&llmnr{}).Handle(context.Background(), llmnrQuery(1), src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected an A poison reply over IPv4, got %d", len(pc.written))
	}
	if !containsBytes(pc.written[0], net.IPv4(192, 0, 2, 50).To4()) {
		t.Errorf("A reply does not embed our IPv4 address: % x", pc.written[0])
	}
}

func TestLLMNRNoWrongFamilyAnswer(t *testing.T) {
	// AAAA query but our local address is IPv4 → no reply (don't fabricate a
	// wrong-family record).
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 50), Port: 5355}}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 50000}
	_, _ = (&llmnr{}).Handle(context.Background(), llmnrQuery(28), src, pc, config.Listener{})
	if len(pc.written) != 0 {
		t.Errorf("AAAA query on a v4-only responder should not be answered; got %d writes", len(pc.written))
	}
}

func TestStunIPv6XORMappedAddress(t *testing.T) {
	req := []byte{0x00, 0x01, 0x00, 0x00}
	req = binary.BigEndian.AppendUint32(req, 0x2112A442)
	req = append(req, make([]byte, 12)...) // txid
	pc := &capPC{}
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::1234"), Port: 50000}
	_, _ = (&stun{lim: newUDPReflectLimiter()}).Handle(context.Background(), req, src, pc, config.Listener{})
	if len(pc.wrote) < 8 {
		t.Fatalf("no STUN response for IPv6 client; got %d bytes", len(pc.wrote))
	}
	// Binding Success + the XOR-MAPPED-ADDRESS attribute with IPv6 family 0x02.
	if pc.wrote[0] != 0x01 || pc.wrote[1] != 0x01 {
		t.Errorf("not a Binding Success: % x", pc.wrote[:2])
	}
	// Attribute starts at byte 20 (after 20-byte STUN header): type 0x0020,
	// len 0x0014, then family byte at offset 25 must be 0x02 (IPv6).
	if len(pc.wrote) >= 26 && pc.wrote[25] != 0x02 {
		t.Errorf("XOR-MAPPED-ADDRESS family = %#x, want 0x02 (IPv6)", pc.wrote[25])
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// fakeAddrConn is a net.Conn whose LocalAddr returns a chosen TCPAddr, for
// exercising ftpPasvListen's address-family branch.
type fakeAddrConn struct {
	net.Conn
	local net.Addr
}

func (f fakeAddrConn) LocalAddr() net.Addr { return f.local }

func TestFTPPasvListenIPv4VsIPv6(t *testing.T) {
	// IPv4 control conn → PASV host string is the h1,h2,h3,h4,p1,p2 form.
	v4 := fakeAddrConn{local: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21}}
	ln4, hp4, err := ftpPasvListen(v4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln4.Close()
	if hp4 == "" || hp4[:3] != "127" {
		t.Errorf("IPv4 PASV host string = %q, want a 127.x octet form", hp4)
	}

	// IPv6 control conn → empty host string (caller must use EPSV); the
	// listener still binds successfully on the v6 stack.
	v6 := fakeAddrConn{local: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 21}}
	ln6, hp6, err := ftpPasvListen(v6)
	if err != nil {
		t.Fatal(err)
	}
	defer ln6.Close()
	if hp6 != "" {
		t.Errorf("IPv6 PASV host string = %q, want empty (forces EPSV)", hp6)
	}
}
