package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestNDRWStrRoundTrip(t *testing.T) {
	e := &ndrEnc{}
	e.uniquePtr(0x20000)
	e.wstr("Random.Real4")
	// Decode: skip the referent, then read the wstring.
	d := &ndrDec{buf: e.buf}
	if _, ok := d.u32(); !ok {
		t.Fatal("read referent")
	}
	got, ok := d.wstr()
	if !ok {
		t.Fatal("wstr decode failed")
	}
	if got != "Random.Real4" {
		t.Errorf("wstr round-trip = %q", got)
	}
}

func TestNDRAlignment(t *testing.T) {
	e := &ndrEnc{}
	e.buf = append(e.buf, 0xaa) // 1 byte, now misaligned
	e.u32(0x11223344)           // must align to 4 first
	if len(e.buf) != 8 {
		t.Fatalf("expected padding to offset 4 then u32: len=%d (%x)", len(e.buf), e.buf)
	}
	if binary.LittleEndian.Uint32(e.buf[4:]) != 0x11223344 {
		t.Errorf("u32 not at aligned offset: %x", e.buf)
	}
}

func TestScavengeWStrings(t *testing.T) {
	// Build a fake stub: 8 bytes of ORPCTHIS-ish padding, then a conformant-
	// varying wstring for an OPC item ID.
	e := &ndrEnc{}
	e.u64(0) // stand-in header
	e.wstr("Channel1.Device1.Tag42")
	got := scavengeWStrings(e.buf)
	found := false
	for _, s := range got {
		if s == "Channel1.Device1.Tag42" {
			found = true
		}
	}
	if !found {
		t.Errorf("item ID not scavenged: %v", got)
	}
}

func TestOPCServerStatusStubWellFormed(t *testing.T) {
	stub := opcServerStatusStub("") // empty -> default Matrikon vendor
	// The vendor string must be embedded as UTF-16LE.
	want := utf16.Encode([]rune("Matrikon OPC Server for Simulation"))
	wantBytes := make([]byte, len(want)*2)
	for i, u := range want {
		binary.LittleEndian.PutUint16(wantBytes[i*2:], u)
	}
	if !containsBytes(stub, wantBytes) {
		t.Error("vendor info string not present in GetStatus stub")
	}
	// dwServerState (running=1) appears after ORPCTHAT(8) + referent(4) + 3
	// FILETIMEs(24) = offset 36.
	if got := binary.LittleEndian.Uint32(stub[36:]); got != 1 {
		t.Errorf("dwServerState = %d, want 1 (running)", got)
	}
	// A custom (archetype-driven) vendor string must be honored.
	kep := opcServerStatusStub("Kepware Technologies KEPServerEX")
	kw := utf16.Encode([]rune("Kepware Technologies KEPServerEX"))
	kb := make([]byte, len(kw)*2)
	for i, u := range kw {
		binary.LittleEndian.PutUint16(kb[i*2:], u)
	}
	if !containsBytes(kep, kb) {
		t.Error("custom OPC vendor string not present in GetStatus stub")
	}
}

func TestBuildResponsePDUFraming(t *testing.T) {
	stub := []byte{1, 2, 3, 4, 5}
	pdu := buildResponsePDU(0xdeadbeef, 7, stub)
	if pdu[2] != dcerpcResponse {
		t.Errorf("ptype = %d, want response", pdu[2])
	}
	if int(binary.LittleEndian.Uint16(pdu[8:10])) != len(pdu) {
		t.Errorf("frag_length %d != actual %d", binary.LittleEndian.Uint16(pdu[8:10]), len(pdu))
	}
	if binary.LittleEndian.Uint32(pdu[12:16]) != 0xdeadbeef {
		t.Error("call_id not echoed")
	}
}

func TestBuildFaultPDUFraming(t *testing.T) {
	pdu := buildFaultPDU(42, 0, 0x1c010002)
	if pdu[2] != dcerpcFault {
		t.Errorf("ptype = %d, want fault", pdu[2])
	}
	if int(binary.LittleEndian.Uint16(pdu[8:10])) != len(pdu) {
		t.Error("fault frag_length mismatch")
	}
}

// buildRequestPDU builds a DCE/RPC Request PDU for opnum with the given stub.
func buildRequestPDU(callID uint32, contID, opnum uint16, stub []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], uint32(len(stub))) // alloc_hint
	binary.LittleEndian.PutUint16(body[4:6], contID)
	binary.LittleEndian.PutUint16(body[6:8], opnum)
	body = append(body, stub...)
	hdr := make([]byte, 16)
	hdr[0] = 5
	hdr[2] = dcerpcRequest
	hdr[3] = pfcFirstLast
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(16+len(body)))
	binary.LittleEndian.PutUint32(hdr[12:16], callID)
	return append(hdr, body...)
}

// TestDCERPCOPCCallSequence drives a full bind -> GetStatus -> Read sequence
// against IOPCServer and asserts the handler decodes the item ID and replies
// with NDR responses.
func TestDCERPCOPCCallSequence(t *testing.T) {
	// IOPCServer (39c13a4d-011e-11d0-9675-0020afd8adb3) on the wire.
	iopcServer := []byte{
		0x4d, 0x3a, 0xc1, 0x39, // field1 LE
		0x1e, 0x01, // field2 LE
		0xd0, 0x11, // field3 LE
		0x96, 0x75, // field4 BE
		0x00, 0x20, 0xaf, 0xd8, 0xad, 0xb3, // field5 BE
	}
	srv, cli := net.Pipe()
	resCh := make(chan Result, 1)
	go func() {
		d := &dcerpc{}
		r, _ := d.Handle(context.Background(), srv, config.Listener{ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))

	// 1) bind
	if _, err := cli.Write(buildBindPDU(iopcServer)); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	readPDU(t, cli) // bind_ack

	// 2) GetStatus (opnum 6) with an ORPCTHIS-ish header + no args.
	getStatus := &ndrEnc{}
	getStatus.u64(0) // stand-in ORPCTHIS
	if _, err := cli.Write(buildRequestPDU(1, 0, 6, getStatus.buf)); err != nil {
		t.Fatalf("write getstatus: %v", err)
	}
	resp := readPDU(t, cli)
	if resp[2] != dcerpcResponse {
		t.Fatalf("GetStatus reply ptype = %d, want response", resp[2])
	}

	// 3) Read (opnum 3) carrying an OPC item ID.
	readReq := &ndrEnc{}
	readReq.u64(0) // ORPCTHIS stand-in
	readReq.uniquePtr(0x30000)
	readReq.wstr("PLC1.Boiler.Pressure")
	if _, err := cli.Write(buildRequestPDU(2, 0, 3, readReq.buf)); err != nil {
		t.Fatalf("write read: %v", err)
	}
	readPDU(t, cli) // response

	_ = cli.Close()
	r := <-resCh

	calls, ok := r.Meta["dcerpc_calls"].([]map[string]any)
	if !ok || len(calls) != 2 {
		t.Fatalf("dcerpc_calls = %v", r.Meta["dcerpc_calls"])
	}
	items, _ := r.Meta["opc_strings"].([]string)
	found := false
	for _, s := range items {
		if s == "PLC1.Boiler.Pressure" {
			found = true
		}
	}
	if !found {
		t.Errorf("OPC item ID not captured: %v", items)
	}
	if !hasAnom(r, "ics-opc-da-call") || !hasAnom(r, "ics-opc-da-item-access") {
		t.Errorf("OPC call anomalies not flagged: %v", r.Meta["anomalies"])
	}
}

// readPDU reads one full DCE/RPC PDU (header + frag body) from c.
func readPDU(t *testing.T, c net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, 16)
	if _, err := pipeReadFull(c, hdr); err != nil {
		t.Fatalf("read pdu header: %v", err)
	}
	fragLen := int(binary.LittleEndian.Uint16(hdr[8:10]))
	if fragLen < 16 || fragLen > 70000 {
		t.Fatalf("implausible frag_length %d", fragLen)
	}
	rest := make([]byte, fragLen-16)
	if _, err := pipeReadFull(c, rest); err != nil {
		t.Fatalf("read pdu body: %v", err)
	}
	return append(hdr, rest...)
}

func pipeReadFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
