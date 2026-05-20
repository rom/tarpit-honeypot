package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// buildBindPDU builds a DCE/RPC bind PDU whose first abstract-syntax UUID
// is wireUUID (the 16-byte mixed-endian on-wire form).
func buildBindPDU(wireUUID []byte) []byte {
	body := make([]byte, 32)
	// body[0:8] = max_xmit/max_recv/assoc_group (skipped by handler)
	binary.LittleEndian.PutUint16(body[8:10], 0)  // ctx_id
	body[10] = 1                                  // n_xfer
	copy(body[12:28], wireUUID)                   // abstract_uuid
	binary.LittleEndian.PutUint32(body[28:32], 0) // abstract_ver

	hdr := make([]byte, 16)
	hdr[0] = 5    // rpc_vers
	hdr[2] = 0x0B // ptype = bind
	hdr[3] = 0x03 // flags first|last
	hdr[4] = 0x10 // drep little-endian
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(16+len(body)))
	binary.LittleEndian.PutUint32(hdr[12:16], 0x11223344) // call_id
	return append(hdr, body...)
}

// opcEnumWireUUID is OPCEnum (13486d44-4821-11d2-a494-3cb306c10000) in the
// DCE/RPC on-wire mixed-endian encoding.
var opcEnumWireUUID = []byte{
	0x44, 0x6d, 0x48, 0x13, // field1 LE
	0x21, 0x48, // field2 LE
	0xd2, 0x11, // field3 LE
	0xa4, 0x94, // field4 BE
	0x3c, 0xb3, 0x06, 0xc1, 0x00, 0x00, // field5 BE
}

func runDCERPC(t *testing.T, pdu []byte) Result {
	t.Helper()
	srv, cli := net.Pipe()
	defer cli.Close()
	resCh := make(chan Result, 1)
	go func() {
		d := &dcerpc{}
		r, _ := d.Handle(context.Background(), srv, config.Listener{ReadTimeout: 2 * time.Second})
		resCh <- r
	}()
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli.Write(pdu); err != nil {
		t.Fatalf("write pdu: %v", err)
	}
	_, _ = cli.Read(make([]byte, 512)) // drain bind_ack so Handle returns
	select {
	case r := <-resCh:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not return")
		return Result{}
	}
}

func TestDCERPCRecognizesOPCEnum(t *testing.T) {
	res := runDCERPC(t, buildBindPDU(opcEnumWireUUID))
	if res.Meta["bind_abstract_uuid"] != "13486d44-4821-11d2-a494-3cb306c10000" {
		t.Fatalf("bind UUID = %v; want OPCEnum canonical", res.Meta["bind_abstract_uuid"])
	}
	if res.Meta["dcerpc_interface"] != "OPCEnum" {
		t.Errorf("dcerpc_interface = %v; want OPCEnum", res.Meta["dcerpc_interface"])
	}
	if !hasAnom(res, "ics-opc-da-probe") {
		t.Errorf("ics-opc-da-probe not flagged; meta=%v", res.Meta)
	}
	if _, ok := res.Meta["opc_servers"].([]string); !ok {
		t.Errorf("opc_servers not advertised")
	}
}

func TestDCERPCAdvertisesOPCEnumInEPM(t *testing.T) {
	// Any bind triggers the EPM interface advertisement.
	res := runDCERPC(t, buildBindPDU(make([]byte, 16)))
	ifaces, ok := res.Meta["epm_interfaces"].([]map[string]any)
	if !ok || len(ifaces) == 0 {
		t.Fatalf("epm_interfaces missing: %v", res.Meta["epm_interfaces"])
	}
	found := false
	for _, m := range ifaces {
		if m["name"] == "OPCEnum" {
			found = true
		}
	}
	if !found {
		t.Errorf("EPM did not advertise OPCEnum: %v", ifaces)
	}
}
