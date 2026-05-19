package handler

import (
	"context"
	"net"
	"testing"
	"time"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// fakePacketConn captures writes so tests can inspect server replies.
// laddr is optional — when set, LocalAddr() returns it (used by the
// LLMNR / NBNS responder tests which need a non-nil local IP).
type fakePacketConn struct {
	net.PacketConn
	written [][]byte
	to      []net.Addr
	laddr   net.Addr
}

func (f *fakePacketConn) WriteTo(p []byte, a net.Addr) (int, error) {
	f.written = append(f.written, append([]byte(nil), p...))
	f.to = append(f.to, a)
	return len(p), nil
}
func (f *fakePacketConn) Close() error               { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr {
	if f.laddr != nil {
		return f.laddr
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5355}
}
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func TestNTPClientResponse(t *testing.T) {
	// Build a client-mode (mode=3) NTPv4 packet: 0b00_100_011 = 0x23
	req := make([]byte, 48)
	req[0] = 0x23
	// Stamp something in transmit_timestamp for echo verification.
	copy(req[40:48], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	res, err := (&ntp{}).Handle(context.Background(), req, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	resp := pc.written[0]
	if len(resp) != 48 {
		t.Fatalf("ntp reply size = %d; want 48", len(resp))
	}
	if resp[0]&0x07 != 4 {
		t.Errorf("reply mode = %d; want 4 (server)", resp[0]&0x07)
	}
	// Origin timestamp (bytes 24..32) must echo client transmit timestamp.
	for i := 0; i < 8; i++ {
		if resp[24+i] != req[40+i] {
			t.Errorf("origin timestamp byte %d not echoed: got %x want %x", i, resp[24+i], req[40+i])
		}
	}
	if res.Meta["mode"] != "client" {
		t.Errorf("meta.mode = %v; want client", res.Meta["mode"])
	}
}

func TestNTPNonClientNoReply(t *testing.T) {
	// mode=7 (private / monlist amplifier) — must NOT be answered.
	req := make([]byte, 48)
	req[0] = 0x27 // ver=4, mode=7
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	_, _ = (&ntp{}).Handle(context.Background(), req, src, pc, config.Listener{})
	if len(pc.written) != 0 {
		t.Fatalf("mode 7 must not be answered; got %d writes", len(pc.written))
	}
}

func TestSNMPv2cGetRequest(t *testing.T) {
	// Build a v2c GetRequest for sysDescr.
	client := &g.GoSNMP{
		Target:    "127.0.0.1",
		Port:      161,
		Version:   g.Version2c,
		Community: "public-honey",
	}
	pkt := &g.SnmpPacket{
		Version:    g.Version2c,
		Community:  "public-honey",
		PDUType:    g.GetRequest,
		RequestID:  42,
		Error:      0,
		ErrorIndex: 0,
		Variables: []g.SnmpPDU{
			{Name: "1.3.6.1.2.1.1.1.0", Type: g.Null},
		},
	}
	encoded, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	_ = client

	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	res, err := (&snmp{}).Handle(context.Background(), encoded, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["community"] != "public-honey" {
		t.Errorf("community: %v", res.Meta["community"])
	}
	if res.Meta["pdu_type"] != "GetRequest" {
		t.Errorf("pdu_type: %v", res.Meta["pdu_type"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
}
