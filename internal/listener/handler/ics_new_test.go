package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestDNP3LinkStatus(t *testing.T) {
	client, server := loopbackPair(t)
	// REQUEST_LINK_STATUS: start 05 64, len 05, ctrl 0x49 (PRM=1 fn=9),
	// dest=4 src=1, crc (handler doesn't validate request crc).
	req := []byte{0x05, 0x64, 0x05, 0x49, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00}
	go func() { _, _ = client.Write(req) }()
	res, err := (&dnp3{}).Handle(context.Background(), server, config.Listener{ReadTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["dnp3_function"] != "REQUEST_LINK_STATUS" {
		t.Errorf("function = %v; want REQUEST_LINK_STATUS", res.Meta["dnp3_function"])
	}
	buf := make([]byte, 16)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := client.Read(buf)
	if err != nil || n < 8 {
		t.Fatalf("read reply: n=%d err=%v", n, err)
	}
	if buf[0] != 0x05 || buf[1] != 0x64 || buf[3] != 0x8B {
		t.Errorf("not a DNP3 link-status reply: % x", buf[:n])
	}
	// dest/src swapped: reply dest = original src (1), reply src = orig dest (4).
	if binary.LittleEndian.Uint16(buf[4:6]) != 1 || binary.LittleEndian.Uint16(buf[6:8]) != 4 {
		t.Errorf("addresses not swapped: % x", buf[:8])
	}
}

func TestGESRTPResponds(t *testing.T) {
	client, server := loopbackPair(t)
	go func() { _, _ = client.Write(make([]byte, 56)) }()
	res, err := (&geSRTP{}).Handle(context.Background(), server, config.Listener{ReadTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	if n != 56 || buf[0] != 0x03 {
		t.Errorf("ge-srtp reply: n=%d first=%#x", n, buf[0])
	}
	if !hasAnom(res, "ics-ge-srtp-probe") {
		t.Errorf("ge-srtp probe not flagged: %v", res.Meta["anomalies"])
	}
}

func TestCodesysResponds(t *testing.T) {
	client, server := loopbackPair(t)
	go func() { _, _ = client.Write([]byte{0xC5, 0x01, 0x02, 0x03}) }()
	res, err := (&codesys{}).Handle(context.Background(), server, config.Listener{ReadTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	if n == 0 || buf[0] != 0xC5 {
		t.Errorf("codesys reply: n=%d first=%#x", n, buf[0])
	}
	if !hasAnom(res, "ics-codesys-probe") {
		t.Errorf("codesys probe not flagged")
	}
}

func TestS7commPlusClassifies(t *testing.T) {
	client, server := loopbackPair(t)
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	dt := []byte{0x03, 0x00, 0x00, 0x0A, 0x02, 0xF0, 0x80, 0x72, 0x01, 0x00}
	go func() {
		_, _ = client.Write(cr)
		buf := make([]byte, 64)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = client.Read(buf) // consume the CC
		_, _ = client.Write(dt)
	}()
	res, err := (&s7commPlus{}).Handle(context.Background(), server, config.Listener{ReadTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["s7_protocol"] != "S7comm-Plus" {
		t.Errorf("s7_protocol = %v; want S7comm-Plus", res.Meta["s7_protocol"])
	}
	if !hasAnom(res, "ics-s7commplus-probe") {
		t.Errorf("s7comm-plus probe not flagged")
	}
}

func TestBACnetWriteProperty(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 47808}
	// BVLC 81 0A len | NPDU 01 04 | APDU confirmed: 00 05 01 0F (WriteProperty)
	frame := []byte{0x81, 0x0A, 0x00, 0x0A, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0F}
	res, err := (&bacnet{}).Handle(context.Background(), frame, src, pc, config.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Meta["apdu_service"] != "WriteProperty" {
		t.Errorf("apdu_service = %v; want WriteProperty", res.Meta["apdu_service"])
	}
	if !hasAnom(res, "bacnet-write-attempt") {
		t.Errorf("write attempt not flagged: %v", res.Meta["anomalies"])
	}
	if len(pc.written) != 1 || pc.written[0][1] != 0x0A {
		t.Errorf("expected a unicast SimpleACK; got %d writes", len(pc.written))
	}
}

func hasAnom(res Result, want string) bool {
	a, _ := res.Meta["anomalies"].([]string)
	for _, m := range a {
		if m == want {
			return true
		}
	}
	return false
}
