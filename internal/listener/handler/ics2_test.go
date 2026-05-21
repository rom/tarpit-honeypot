package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestOPCUAHelloAck(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "opcua", ReadBytes: 4096, ReadTimeout: time.Second}

	endpoint := "opc.tcp://target.example/UA/MyServer"
	body := make([]byte, 24+len(endpoint))
	binary.LittleEndian.PutUint32(body[0:4], 0)                       // version
	binary.LittleEndian.PutUint32(body[4:8], 65536)                   // rx buf
	binary.LittleEndian.PutUint32(body[8:12], 65536)                  // tx buf
	binary.LittleEndian.PutUint32(body[12:16], 16777216)              // max msg
	binary.LittleEndian.PutUint32(body[16:20], 0)                     // max chunk
	binary.LittleEndian.PutUint32(body[20:24], uint32(len(endpoint))) // endpoint len
	copy(body[24:], endpoint)

	hdr := make([]byte, 8)
	copy(hdr[0:4], []byte("HELF"))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(8+len(body)))

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&opcua{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(append(hdr, body...)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 28)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatal(err)
	}
	if string(ack[0:3]) != "ACK" {
		t.Errorf("expected ACK; got %q", ack[0:4])
	}
	client.Close()
	<-done
	if res.Meta["endpoint_url"] != endpoint {
		t.Errorf("endpoint not captured; meta=%v", res.Meta)
	}
}

func TestEthernetIPListIdentity(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ethernetip", ReadBytes: 1024, ReadTimeout: time.Second}

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint16(hdr[0:2], 0x0063) // ListIdentity
	binary.LittleEndian.PutUint16(hdr[2:4], 0)      // data length

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&ethernetip{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(hdr); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 24)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(resp[0:2]) != 0x0063 {
		t.Errorf("response command mismatch: %x", resp[0:2])
	}
	// Read the rest of the body (length is in resp[2:4])
	bodyLen := binary.LittleEndian.Uint16(resp[2:4])
	body := make([]byte, bodyLen)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	if res.Meta["command"] != "ListIdentity" {
		t.Errorf("command meta: %v", res.Meta["command"])
	}
}

func TestEthernetIPRegisterSession(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ethernetip", ReadBytes: 1024, ReadTimeout: time.Second}

	body := []byte{0x01, 0x00, 0x00, 0x00} // protocol version=1, options=0
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint16(hdr[0:2], 0x0065) // RegisterSession
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(body)))

	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&ethernetip{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(append(hdr, body...)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 28)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	// Session handle must be non-zero (the trap honors the session).
	if binary.LittleEndian.Uint32(resp[4:8]) == 0 {
		t.Errorf("session handle is zero")
	}
}

func TestBACnetWhoIsIAmReply(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	// Build Who-Is: BVLC (0x81 0x0B len) + NPDU (0x01 0x00) + APDU (0x10 0x08)
	pkt := []byte{0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	res, _ := (&bacnet{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 I-Am reply; got %d", len(pc.written))
	}
	reply := pc.written[0]
	if reply[0] != 0x81 {
		t.Errorf("reply not BVLC; first byte %x", reply[0])
	}
	if res.Meta["apdu_service"] != "Who-Is" {
		t.Errorf("apdu_service meta: %v", res.Meta["apdu_service"])
	}
}

func TestBACnetIgnoresNonWhoIs(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	// Same packet but APDU service = 0x07 (Who-Has)
	pkt := []byte{0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x07}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	_, _ = (&bacnet{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if len(pc.written) != 0 {
		t.Errorf("expected no reply to Who-Has; got %d writes", len(pc.written))
	}
}

func TestTFTPRRQReturnsError(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	pkt := []byte{0x00, 0x01}                         // opcode RRQ
	pkt = append(pkt, []byte("config/router.cfg")...) // filename
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte("octet")...)
	pkt = append(pkt, 0)

	res, _ := (&tftp{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 error reply; got %d", len(pc.written))
	}
	reply := pc.written[0]
	if binary.BigEndian.Uint16(reply[0:2]) != 5 {
		t.Errorf("not ERROR opcode: %x", reply[0:2])
	}
	if binary.BigEndian.Uint16(reply[2:4]) != 2 {
		t.Errorf("not Access Violation code: %x", reply[2:4])
	}
	if res.Meta["filename"] != "config/router.cfg" {
		t.Errorf("filename: %v", res.Meta["filename"])
	}
	if res.Meta["mode"] != "octet" {
		t.Errorf("mode: %v", res.Meta["mode"])
	}
	// .cfg read over TFTP is config exfil.
	if anoms, _ := res.Meta["anomalies"].([]string); !containsStr(anoms, "tftp-config-read") {
		t.Errorf("config-file RRQ not flagged: %v", res.Meta["anomalies"])
	}
}

func TestTFTPWRQFlagged(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12346}
	pkt := []byte{0x00, 0x02} // opcode WRQ (upload)
	pkt = append(pkt, []byte("firmware.bin")...)
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte("octet")...)
	pkt = append(pkt, 0)

	res, _ := (&tftp{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["opcode"] != "WRQ" {
		t.Errorf("opcode: %v", res.Meta["opcode"])
	}
	if anoms, _ := res.Meta["anomalies"].([]string); !containsStr(anoms, "tftp-write-attempt") {
		t.Errorf("WRQ upload not flagged: %v", res.Meta["anomalies"])
	}
}
