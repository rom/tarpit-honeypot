package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// CoAP GET /.well-known/core — the discovery query Shodan-style scanners
// use to enumerate IoT devices. The handler should reply with a 2.05
// ACK carrying a link-format body.
func TestCoAPGetWellKnownCore(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 50001}
	// ver=1, type=CON, tkl=2, code=GET(0x01), mid=0xbeef, token=ab cd,
	// Uri-Path option(11) ".well-known", delta=0 ".well-known"=11 bytes,
	// then option(11+0=11) "core" delta=0 len=4.
	pkt := []byte{
		(1 << 6) | (0 << 4) | 2, // VER=1 TYPE=CON TKL=2
		0x01,                    // GET
		0xbe, 0xef,              // mid
		0xab, 0xcd, // token
	}
	// Option Uri-Path = ".well-known". option num 11 -> delta = 11, value len = 11
	pkt = append(pkt, (11<<4)|11)
	pkt = append(pkt, []byte(".well-known")...)
	// Next option delta = 0 (same), value = "core"
	pkt = append(pkt, (0<<4)|4)
	pkt = append(pkt, []byte("core")...)

	res, _ := (&coap{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["code"] != byte(0x01) {
		t.Errorf("code = %v; want 0x01", res.Meta["code"])
	}
	if got, ok := res.Meta["uri_path"]; !ok || got != ".well-known/core" {
		t.Errorf("uri_path = %v; want .well-known/core", got)
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	reply := pc.written[0]
	// Reply header: VER=1, TYPE=ACK(2), TKL=2, code=2.05 (0x45), mid=0xbeef.
	if reply[0] != (1<<6)|(2<<4)|2 {
		t.Errorf("reply byte 0 = %x; want VER=1 ACK TKL=2", reply[0])
	}
	if reply[1] != 0x45 {
		t.Errorf("reply code = %x; want 0x45 (2.05 Content)", reply[1])
	}
	if binary.BigEndian.Uint16(reply[2:4]) != 0xbeef {
		t.Errorf("mid not echoed: %x", reply[2:4])
	}
	if !bytes.Contains(reply, []byte("well-known/core")) {
		t.Errorf("link-format body missing: % x", reply)
	}
}

// KNXnet/IP SEARCH_REQUEST is the standard discovery probe. The handler
// should reply with a SEARCH_RESPONSE whose body advertises a "MDT KNX
// IP Router" friendly-name.
func TestKNXSearchRequest(t *testing.T) {
	pc := &fakePacketConn{laddr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 7), Port: 3671}}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 50001}
	pkt := []byte{
		0x06, 0x10, // header len + version
		0x02, 0x01, // SEARCH_REQUEST
		0x00, 0x0e, // total length 14
		// HPAI
		0x08, 0x01, // len + proto
		192, 168, 1, 200, // ip
		0xc3, 0x50, // port 50000
	}
	res, _ := (&knx{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if res.Meta["op"] != "SEARCH_REQUEST" {
		t.Errorf("op = %v; want SEARCH_REQUEST", res.Meta["op"])
	}
	if len(pc.written) != 1 {
		t.Fatalf("expected 1 reply; got %d", len(pc.written))
	}
	reply := pc.written[0]
	if reply[0] != 0x06 || reply[1] != 0x10 {
		t.Errorf("bad reply header: % x", reply[:2])
	}
	if binary.BigEndian.Uint16(reply[2:4]) != 0x0202 {
		t.Errorf("svc = %x; want SEARCH_RESPONSE 0x0202", reply[2:4])
	}
	if !bytes.Contains(reply, []byte("MDT KNX IP Router")) {
		t.Errorf("friendly-name not in reply: % x", reply)
	}
}

// XMPP client opens with <stream:stream> announcing the @to host. The
// handler should reply with its own stream:stream + a STARTTLS feature
// advertising PLAIN/SCRAM-SHA-1.
func TestXMPPClientStreamStart(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "xmpp", ReadBytes: 4096, ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&xmpp{}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte(`<?xml version='1.0'?><stream:stream to='im.example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`))
	buf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(buf)
	// Send a close stanza so the handler exits promptly.
	_, _ = client.Write([]byte(`</stream:stream>`))
	client.Close()
	<-done
	resp := string(buf[:n])
	if !strings.Contains(resp, "<stream:features>") {
		t.Errorf("response missing stream:features: %q", resp)
	}
	if !strings.Contains(resp, "<mechanism>PLAIN</mechanism>") {
		t.Errorf("PLAIN mechanism missing: %q", resp)
	}
	if res.Meta["to"] != "im.example.com" {
		t.Errorf("to = %v; want im.example.com", res.Meta["to"])
	}
}

// AMQP scanner sends the 8-byte protocol header. The handler should
// respond with a Connection.Start method frame announcing PLAIN.
func TestAMQPConnectionStart(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "amqp", ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&amqp{}).Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1})

	// Read the Connection.Start frame: 1 byte type, 2 channel, 4 len, body, 1 0xCE.
	hdr := make([]byte, 7)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != amqpFrameMethod {
		t.Errorf("frame type = %d; want %d", hdr[0], amqpFrameMethod)
	}
	plen := binary.BigEndian.Uint32(hdr[3:7])
	body := make([]byte, int(plen)+1)
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}
	if body[len(body)-1] != amqpFrameEnd {
		t.Errorf("missing frame-end")
	}
	if !bytes.Contains(body, []byte("RabbitMQ")) {
		t.Errorf("RabbitMQ product missing: % x", body)
	}
	if !bytes.Contains(body, []byte("PLAIN")) {
		t.Errorf("PLAIN mechanism missing")
	}

	// Send a fake Connection.StartOk with PLAIN \0root\0secret.
	startOk := buildStartOkForTest(t)
	_, _ = client.Write(startOk)
	// Read Connection.Close frame.
	closeHdr := make([]byte, 7)
	_, _ = io.ReadFull(client, closeHdr)
	if closeHdr[0] == amqpFrameMethod {
		closeLen := binary.BigEndian.Uint32(closeHdr[3:7])
		closeBody := make([]byte, int(closeLen)+1)
		_, _ = io.ReadFull(client, closeBody)
		if !bytes.Contains(closeBody, []byte("NOT_ALLOWED")) {
			t.Errorf("Connection.Close text missing: % x", closeBody)
		}
	}
	client.Close()
	<-done
	if got := res.Meta["auth_user"]; got != "root" {
		t.Errorf("auth_user = %v; want root", got)
	}
	if got := res.Meta["auth_pass"]; got != "secret" {
		t.Errorf("auth_pass = %v; want secret", got)
	}
}

// buildStartOkForTest crafts a minimal Connection.StartOk frame whose
// PLAIN response is \0root\0secret — verifies the handler decodes
// SASL PLAIN credentials correctly.
func buildStartOkForTest(t *testing.T) []byte {
	t.Helper()
	// class=10 method=11.
	args := []byte{}
	// client-properties: empty table (long string with len=0).
	args = binary.BigEndian.AppendUint32(args, 0)
	// mechanism: short str "PLAIN".
	args = append(args, byte(len("PLAIN")))
	args = append(args, []byte("PLAIN")...)
	// response: long str "\0root\0secret".
	resp := []byte{0, 'r', 'o', 'o', 't', 0, 's', 'e', 'c', 'r', 'e', 't'}
	args = binary.BigEndian.AppendUint32(args, uint32(len(resp)))
	args = append(args, resp...)
	// locale: short str "en_US".
	args = append(args, byte(len("en_US")))
	args = append(args, []byte("en_US")...)

	body := []byte{}
	body = binary.BigEndian.AppendUint16(body, amqpClassConnection)
	body = binary.BigEndian.AppendUint16(body, amqpMethodStartOk)
	body = append(body, args...)

	out := []byte{amqpFrameMethod}
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	out = append(out, amqpFrameEnd)
	return out
}

// IPP POST with a minimal Get-Printer-Attributes body. The handler
// should reply HTTP 200 with Content-Type: application/ipp and a
// printer-attributes payload mentioning the fake Brother printer.
func TestIPPGetPrinterAttributes(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "ipp", ReadBytes: 8192, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&ipp{}).Handle(context.Background(), server, cfg)
	}()
	// Build minimal IPP body: version 2.0, op Get-Printer-Attributes
	// (0x000B), request-id 1, end-of-attributes-tag.
	body := []byte{
		0x02, 0x00, // ver
		0x00, 0x0B, // op
		0x00, 0x00, 0x00, 0x01, // request id
		0x03, // end-of-attributes
	}
	req := "POST /ipp/print HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Content-Type: application/ipp\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n"
	_, _ = client.Write(append([]byte(req), body...))

	br := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200") {
		t.Errorf("status = %q; want 200", statusLine)
	}
	// Drain headers.
	headers := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		headers += line
		if line == "\r\n" {
			break
		}
	}
	if !strings.Contains(headers, "Server: CUPS/") {
		t.Errorf("CUPS server header missing: %q", headers)
	}
	if !strings.Contains(headers, "application/ipp") {
		t.Errorf("application/ipp content-type missing: %q", headers)
	}
	bodyBuf := make([]byte, 4096)
	n, _ := br.Read(bodyBuf)
	if !bytes.Contains(bodyBuf[:n], []byte("Brother")) {
		t.Errorf("Brother printer name missing in body")
	}
	client.Close()
	<-done
}
