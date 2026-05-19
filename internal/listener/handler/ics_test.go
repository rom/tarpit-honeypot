package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func pipePair(t *testing.T) (clientSide net.Conn, serverSide net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestModbusReadHoldingRegisters(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "modbus", ReadBytes: 260, ReadTimeout: time.Second}

	// Send: txid=0x0001, proto=0, len=6, unit=0x11, fc=0x03 (read holding regs), addr=0, count=1
	req := []byte{0, 1, 0, 0, 0, 6, 0x11, 0x03, 0, 0, 0, 1}
	done := make(chan struct{})
	var handlerErr error
	go func() {
		defer close(done)
		_, handlerErr = (&modbus{}).Handle(context.Background(), server, cfg)
	}()
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	// Read response.
	resp := make([]byte, 12) // header 7 + pdu 3 fc+bytecount+1reg = 4? actually fc + bytecount(0x02) + 2 bytes
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := io.ReadFull(client, resp[:11])
	if err != nil {
		t.Fatalf("read response: %v (n=%d)", err, n)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0001 {
		t.Errorf("tx id mismatch: %x", resp[0:2])
	}
	if resp[7] != 0x03 {
		t.Errorf("response fc = %x; want 0x03", resp[7])
	}
	if resp[8] != 0x02 {
		t.Errorf("response byte_count = %x; want 0x02", resp[8])
	}
	client.Close()
	<-done
	if handlerErr != nil {
		t.Errorf("handler err: %v", handlerErr)
	}
}

func TestModbusException(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "modbus", ReadBytes: 260, ReadTimeout: time.Second}
	// fc=0x42 is not standard — should get exception.
	req := []byte{0, 2, 0, 0, 0, 2, 0x01, 0x42}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&modbus{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 9)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	if resp[7] != 0x42|0x80 {
		t.Errorf("expected exception fc 0xc2; got %x", resp[7])
	}
	if resp[8] != 0x01 {
		t.Errorf("expected exception code 0x01; got %x", resp[8])
	}
	client.Close()
	<-done
}

// Read Device Identification (FC 0x2B / MEI 0x0E) — what nmap's
// modbus-discover uses to fingerprint the PLC. The honeypot should
// answer with the vendor + product code so the scan records a real-
// looking PLC.
func TestModbusReadDeviceID(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "modbus", ReadBytes: 260, ReadTimeout: time.Second}
	// MBAP: txid=3, proto=0, len=5, unit=1; PDU: 2B 0E 01 00.
	req := []byte{0, 3, 0, 0, 0, 5, 0x01, 0x2B, 0x0E, 0x01, 0x00}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&modbus{}).Handle(context.Background(), server, cfg)
	}()
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	// Read MBAP header first to size the body read.
	hdr := make([]byte, 7)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[4:6])) - 1
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	// Body starts with: 2B 0E <device_id> 83 00 00 <num_objs> <objects...>
	if body[0] != 0x2B {
		t.Errorf("expected fc 0x2B; got %x", body[0])
	}
	if body[1] != 0x0E {
		t.Errorf("expected MEI 0x0E; got %x", body[1])
	}
	if !bytes.Contains(body, []byte("Schneider Electric")) {
		t.Errorf("vendor not advertised: % x", body)
	}
	if !bytes.Contains(body, []byte("BMX P34 2020")) {
		t.Errorf("product code not advertised: % x", body)
	}
	// And the PDU metadata should record the MEI subfunction.
	pdus, _ := res.Meta["pdus"].([]map[string]any)
	if len(pdus) != 1 || pdus[0]["mei_subfunction"] != byte(0x0E) {
		t.Errorf("meta did not record MEI subfunction: %v", res.Meta)
	}
}

// Write Multiple Registers (FC 0x10) — the honeypot must capture the
// values the attacker tried to write. A scanner pivoting from a
// "Modbus-open" finding to "tamper with setpoints" lands here.
func TestModbusWriteMultipleRegistersCapture(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "modbus", ReadBytes: 260, ReadTimeout: time.Second}
	// MBAP: txid=4, proto=0, len=11 (unit+pdu=11), unit=1.
	// PDU: 10 (FC) 00 64 (addr=100) 00 02 (qty=2) 04 (byte count)
	//      DE AD BE EF (the two registers attacker wants written).
	req := []byte{0, 4, 0, 0, 0, 11, 0x01,
		0x10, 0x00, 0x64, 0x00, 0x02, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = (&modbus{}).Handle(context.Background(), server, cfg)
	}()
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 7)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[4:6])) - 1
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	// Server should echo back fc + addr + qty.
	if body[0] != 0x10 || body[1] != 0x00 || body[2] != 0x64 ||
		body[3] != 0x00 || body[4] != 0x02 {
		t.Errorf("write-multiple ack wrong: % x", body)
	}
	pdus, _ := res.Meta["pdus"].([]map[string]any)
	if len(pdus) != 1 {
		t.Fatalf("expected 1 captured PDU; got %d", len(pdus))
	}
	values, _ := pdus[0]["written_values"].([]uint16)
	if len(values) != 2 || values[0] != 0xDEAD || values[1] != 0xBEEF {
		t.Errorf("written values not captured: %v", values)
	}
}

func TestMQTTConnectParse(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "mqtt", ReadBytes: 1024, ReadTimeout: time.Second}
	// CONNECT: type=0x10, remlen calculated, MQTT v3.1.1 with user+pass.
	body := []byte{
		0, 4, 'M', 'Q', 'T', 'T', // protocol name
		0x04,                // level 4
		0xc0,                // flags: user+pass
		0, 60,               // keepalive
		0, 5, 'h', 'e', 'l', 'l', 'o',     // ClientID
		0, 5, 'a', 'd', 'm', 'i', 'n',     // username
		0, 6, 's', 'e', 'c', 'r', 'e', 't', // password
	}
	pkt := []byte{0x10, byte(len(body))}
	pkt = append(pkt, body...)

	done := make(chan struct{})
	var res Result
	go func() { defer close(done); res, _ = (&mqtt{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}
	connack := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, connack); err != nil {
		t.Fatal(err)
	}
	if connack[0] != 0x20 || connack[1] != 0x02 || connack[3] != 0x00 {
		t.Errorf("connack mismatch: %v", connack)
	}
	client.Close()
	<-done
	if res.Meta["client_id"] != "hello" {
		t.Errorf("client_id: %v", res.Meta["client_id"])
	}
	if res.Meta["username"] != "admin" {
		t.Errorf("username: %v", res.Meta["username"])
	}
	if res.Meta["password"] != "secret" {
		t.Errorf("password: %v", res.Meta["password"])
	}
}

func TestS7ConnectionConfirm(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "s7", ReadBytes: 256, ReadTimeout: time.Second}
	// COTP CR: TPKT(03 00 00 16) + COTP len=0x11 type=0xE0 dst=0 src=0x100 class=0 + 11 param bytes
	tpkt := []byte{0x03, 0x00, 0x00, 0x16}
	cotp := []byte{0x11, 0xE0, 0x00, 0x00, 0x01, 0x00, 0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x09}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&s7{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(append(tpkt, cotp...)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 22)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x03 {
		t.Errorf("response not TPKT: %v", resp[:4])
	}
	if resp[5] != 0xD0 {
		t.Errorf("response COTP type = %x; want 0xD0 (Connection Confirm)", resp[5])
	}
	client.Close()
	<-done
}

func TestIEC104StartDTCon(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "iec104", ReadBytes: 256, ReadTimeout: time.Second}
	// STARTDT_ACT: 0x68 0x04 0x07 0x00 0x00 0x00
	req := []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&iec104{}).Handle(context.Background(), server, cfg) }()
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 6)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x68 || resp[2] != 0x0b {
		t.Errorf("expected STARTDT_CON 68 04 0b 00 00 00; got %v", resp)
	}
	client.Close()
	<-done
}

// After STARTDT, a scanner sends General Interrogation (ASDU type 100,
// COT=6). The handler should reply with act-con, stream measurements,
// then act-term.
func TestIEC104GeneralInterrogation(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{Handler: "iec104", ReadBytes: 512, ReadTimeout: time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = (&iec104{}).Handle(context.Background(), server, cfg) }()

	// Frame 1: STARTDT_ACT.
	_, _ = client.Write([]byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00})
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 6)
	_, _ = io.ReadFull(client, resp)
	if resp[2] != 0x0b {
		t.Fatalf("STARTDT_CON missing: %v", resp)
	}

	// Frame 2: General Interrogation request. APCI(6) + ASDU(10):
	// type=100, vsq=1, cot=6, ca=1, ioa=0, qoi=0x14.
	gi := []byte{
		0x68, 0x0e, // start + length
		0x00, 0x00, 0x00, 0x00, // I-format ctrl (seqs 0)
		100, 0x01, 0x06, 0x00, 0x01, 0x00, // type, vsq, cot, ca
		0x00, 0x00, 0x00, // IOA = 0
		0x14, // QOI = 20 (interrogated by general interrogation)
	}
	_, _ = client.Write(gi)

	// Read 5 reply frames: act-con + 3 measurements + act-term.
	gotIFrames := 0
	gotMeasurements := 0
	gotActTerm := false
	for r := 0; r < 5; r++ {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(client, hdr); err != nil {
			break
		}
		if hdr[0] != 0x68 {
			break
		}
		body := make([]byte, hdr[1])
		if _, err := io.ReadFull(client, body); err != nil {
			break
		}
		if body[0]&0x01 != 0 {
			// not an I-frame
			continue
		}
		gotIFrames++
		if len(body) < 8 {
			continue
		}
		asduType := body[4]
		cot := body[6] & 0x3F
		switch {
		case asduType == 100 && cot == 7:
			// act-con; expected first
		case asduType == 11:
			gotMeasurements++
		case asduType == 100 && cot == 10:
			gotActTerm = true
		}
	}
	client.Close()
	<-done
	if gotMeasurements < 3 {
		t.Errorf("expected 3 measurement frames; got %d", gotMeasurements)
	}
	if !gotActTerm {
		t.Errorf("expected activation-termination frame")
	}
}
