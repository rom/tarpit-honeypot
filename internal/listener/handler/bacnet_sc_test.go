package handler

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// maskedWSBinary builds a client→server masked WebSocket binary frame.
func maskedWSBinary(payload []byte) []byte {
	mask := []byte{0x12, 0x34, 0x56, 0x78}
	out := []byte{0x82, byte(0x80 | len(payload))}
	out = append(out, mask...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	return out
}

func TestBACnetSCConnect(t *testing.T) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		h := &bacnetSC{}
		r, _ := h.Handle(context.Background(), srv, config.Listener{ID: "bms1", ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))

	// WebSocket upgrade offering the BACnet/SC hub subprotocol.
	upgrade := "GET /bsc HTTP/1.1\r\n" +
		"Host: bms.local\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Protocol: hub.bsc.bacnet.org\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := cli.Write([]byte(upgrade)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(cli)
	// Read the 101 response head.
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read handshake: %v", err)
		}
		sb.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	hs := sb.String()
	if !strings.Contains(hs, "101 Switching Protocols") {
		t.Fatalf("no 101 upgrade: %q", hs)
	}
	if !strings.Contains(hs, "Sec-WebSocket-Protocol: hub.bsc.bacnet.org") {
		t.Errorf("hub subprotocol not echoed: %q", hs)
	}

	// BVLC-SC Connect-Request: func 0x06, control 0x00, msg id, VMAC(6),
	// device UUID(16), max BVLC(2), max NPDU(2).
	vmac := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}
	uuid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	req := []byte{0x06, 0x00, 0x00, 0x2a}
	req = append(req, vmac...)
	req = append(req, uuid...)
	req = append(req, 0x05, 0xf2, 0x05, 0xf2)
	if _, err := cli.Write(maskedWSBinary(req)); err != nil {
		t.Fatalf("write connect-request: %v", err)
	}

	// Read the server's Connect-Accept WebSocket binary frame.
	h0, _ := br.ReadByte()
	l0, _ := br.ReadByte()
	if h0 != 0x82 {
		t.Fatalf("server reply not a binary frame: 0x%02x", h0)
	}
	body := make([]byte, int(l0))
	if _, err := br.Read(body); err != nil {
		t.Fatalf("read connect-accept: %v", err)
	}
	if len(body) < 4 || body[0] != 0x07 {
		t.Fatalf("expected Connect-Accept (0x07), got % x", body)
	}
	if body[2] != 0x00 || body[3] != 0x2a {
		t.Errorf("Connect-Accept did not echo message id: % x", body[:4])
	}

	_ = cli.Close()
	res := <-resCh

	if res.Meta["bacnet_sc"] != true {
		t.Errorf("bacnet_sc not recognized: %v", res.Meta)
	}
	if res.Meta["bacnet_sc_role"] != "hub" {
		t.Errorf("role = %v want hub", res.Meta["bacnet_sc_role"])
	}
	if res.Meta["node_vmac"] != "aabbcc001122" {
		t.Errorf("node_vmac = %v", res.Meta["node_vmac"])
	}
	if res.Meta["device_uuid"] != "01020304-0506-0708-090a-0b0c0d0e0f10" {
		t.Errorf("device_uuid = %v", res.Meta["device_uuid"])
	}
	for _, a := range []string{"bacnet-sc", "ics-bacnet-sc-connect", "ics-field-device-probe"} {
		if !metaHasAnomaly(res.Meta, a) {
			t.Errorf("missing anomaly %q in %v", a, res.Meta["anomalies"])
		}
	}
	if fns, _ := res.Meta["bvlc_sc_functions"].([]string); len(fns) == 0 || fns[0] != "Connect-Request" {
		t.Errorf("bvlc_sc_functions = %v", res.Meta["bvlc_sc_functions"])
	}
}

func TestBACnetSCNonUpgrade(t *testing.T) {
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		h := &bacnetSC{}
		r, _ := h.Handle(context.Background(), srv, config.Listener{ID: "bms1", ReadTimeout: time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = cli.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := cli.Read(buf)
	if !strings.Contains(string(buf[:n]), "426 Upgrade Required") {
		t.Errorf("non-upgrade reply = %q", string(buf[:n]))
	}
	_ = cli.Close()
	res := <-resCh
	if res.Meta["ws_upgrade"] != false {
		t.Errorf("ws_upgrade = %v want false", res.Meta["ws_upgrade"])
	}
}

func TestBVLCSCNPDUWriteDetect(t *testing.T) {
	// A confirmed-request (0x00) WriteProperty (0x0F) APDU should be flagged.
	write := []byte{0x01, 0x04, 0x00, 0x05, 0x0f} // npdu + confirmed-req + WriteProperty
	if !bscNPDUHasWrite(write) {
		t.Error("WriteProperty APDU not detected")
	}
	// A ReadProperty (0x0C) must not look like a write.
	read := []byte{0x01, 0x04, 0x00, 0x05, 0x0c}
	if bscNPDUHasWrite(read) {
		t.Error("ReadProperty wrongly flagged as a write")
	}
}
