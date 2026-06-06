package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// driveDrain runs a TCP handler against a pipe, draining the handler's writes
// concurrently so multi-PDU sessions (which write replies the test ignores)
// don't deadlock, then returns the handler's Result.
func driveDrain(t *testing.T, h func(net.Conn) Result, send []byte) Result {
	t.Helper()
	client, server := pipePair(t)
	out := make(chan Result, 1)
	go func() { out <- h(server) }()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	if _, err := client.Write(send); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.Close()
	select {
	case r := <-out:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("handler timed out")
		return Result{}
	}
}

// A full S7comm session: COTP CR, Setup Communication, Write Var (control
// manipulation), and an SZL read (CPU fingerprinting).
func TestS7CommSession(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	setup := []byte{0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80,
		0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
		0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0}
	writeVar := []byte{0x03, 0x00, 0x00, 0x13, 0x02, 0xF0, 0x80,
		0x32, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x05, 0x01}
	szl := []byte{0x03, 0x00, 0x00, 0x21, 0x02, 0xF0, 0x80,
		0x32, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x08,
		0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00,
		0xFF, 0x09, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00}
	msg := append(append(append(append([]byte{}, cr...), setup...), writeVar...), szl...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&s7{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, msg)

	if r.Meta["cotp_type"] != "CR" {
		t.Errorf("cotp_type = %v, want CR", r.Meta["cotp_type"])
	}
	if !hasAnom(r, "ics-plc-write") {
		t.Errorf("Write Var not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "ics-field-device-probe") {
		t.Errorf("SZL read not flagged: %v", r.Meta["anomalies"])
	}
	if r.Meta["s7_szl_id"] != uint16(0x0011) {
		t.Errorf("s7_szl_id = %v, want 0x0011", r.Meta["s7_szl_id"])
	}
}

// A DNP3 OPERATE frame actuates control points.
func TestDNP3Operate(t *testing.T) {
	frame := []byte{0x05, 0x64, 0x08, 0xC4, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xC0, 0xC0, 0x04, 0x00, 0x00}
	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&dnp3{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, frame)
	if r.Meta["dnp3_app_function"] != "OPERATE" {
		t.Errorf("dnp3_app_function = %v, want OPERATE", r.Meta["dnp3_app_function"])
	}
	if !hasAnom(r, "ics-dnp3-control") {
		t.Errorf("OPERATE not flagged: %v", r.Meta["anomalies"])
	}
}

// A DNP3 COLD_RESTART reboots the outstation.
func TestDNP3ColdRestart(t *testing.T) {
	frame := []byte{0x05, 0x64, 0x08, 0xC4, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xC0, 0xC0, 0x0D, 0x00, 0x00}
	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&dnp3{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, frame)
	if r.Meta["dnp3_app_function"] != "COLD_RESTART" {
		t.Errorf("dnp3_app_function = %v, want COLD_RESTART", r.Meta["dnp3_app_function"])
	}
	if !hasAnom(r, "ics-device-restart") {
		t.Errorf("COLD_RESTART not flagged: %v", r.Meta["anomalies"])
	}
}

// A Modbus Diagnostics (FC 0x08) Restart-Communications sub-function is a
// control/DoS action, not benign register sampling.
func TestModbusDiagnosticRestart(t *testing.T) {
	frame := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x08, 0x00, 0x01, 0xFF, 0x00}
	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&modbus{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, frame)
	if r.Meta["function_code"] != byte(0x08) {
		t.Errorf("function_code = %v, want 0x08 (Diagnostics)", r.Meta["function_code"])
	}
	if !hasAnom(r, "ics-modbus-diagnostic") {
		t.Errorf("diagnostic restart not flagged: %v", r.Meta["anomalies"])
	}
}

// BACnet ReadProperty (confirmed request) is control-point enumeration.
func TestBACnetReadProperty(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 47808}
	pkt := []byte{0x81, 0x0A, 0x00, 0x0A, 0x01, 0x00, 0x00, 0x05, 0x01, 0x0C}
	r, _ := (&bacnet{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if r.Meta["apdu_service"] != "ReadProperty" {
		t.Errorf("apdu_service = %v, want ReadProperty", r.Meta["apdu_service"])
	}
	if !hasAnom(r, "bacnet-property-read") {
		t.Errorf("ReadProperty not flagged: %v", r.Meta["anomalies"])
	}
}

// BACnet ReinitializeDevice reboots the controller.
func TestBACnetReinitialize(t *testing.T) {
	pc := &fakePacketConn{}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 47808}
	pkt := []byte{0x81, 0x0A, 0x00, 0x0A, 0x01, 0x00, 0x00, 0x05, 0x01, 0x14}
	r, _ := (&bacnet{}).Handle(context.Background(), pkt, src, pc, config.Listener{})
	if !hasAnom(r, "bacnet-reinitialize-device") {
		t.Errorf("ReinitializeDevice not flagged: %v", r.Meta["anomalies"])
	}
}

// IEC-104: STARTDT, a General Interrogation (process-image enum) and a single
// command (control-point actuation).
func TestIEC104InterrogationAndCommand(t *testing.T) {
	startdt := []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}
	gi := []byte{0x68, 0x0E, 0x00, 0x00, 0x00, 0x00,
		0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14}
	cmd := []byte{0x68, 0x0E, 0x00, 0x00, 0x00, 0x00,
		0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
	msg := append(append(append([]byte{}, startdt...), gi...), cmd...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&iec104{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, msg)
	if !hasAnom(r, "ics-process-data-access") {
		t.Errorf("General Interrogation not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "ics-iec104-command") {
		t.Errorf("single command not flagged: %v", r.Meta["anomalies"])
	}
}

// EtherNet/IP: a SendRRData carrying a CIP Write_Tag is control manipulation.
func TestEtherNetIPCIPWrite(t *testing.T) {
	mr := []byte{0x4D, 0x02, 0x20, 0x04, 0x24, 0x01} // Write_Tag, path to obj
	var data []byte
	data = binary.LittleEndian.AppendUint32(data, 0)      // interface handle
	data = binary.LittleEndian.AppendUint16(data, 0)      // timeout
	data = binary.LittleEndian.AppendUint16(data, 2)      // CPF item count
	data = binary.LittleEndian.AppendUint16(data, 0x0000) // null address item
	data = binary.LittleEndian.AppendUint16(data, 0)      // ...len 0
	data = binary.LittleEndian.AppendUint16(data, 0x00B2) // unconnected data item
	data = binary.LittleEndian.AppendUint16(data, uint16(len(mr)))
	data = append(data, mr...)

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint16(hdr[0:2], 0x006F) // SendRRData
	binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(data)))
	binary.LittleEndian.PutUint32(hdr[4:8], 0xdeadbeef) // session
	frame := append(hdr, data...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&ethernetip{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, frame)
	if r.Meta["cip_service"] != "Write_Tag" {
		t.Errorf("cip_service = %v, want Write_Tag", r.Meta["cip_service"])
	}
	if !hasAnom(r, "ics-plc-write") {
		t.Errorf("CIP write not flagged: %v", r.Meta["anomalies"])
	}
}

// OPC-UA: an OpenSecureChannel for SecurityPolicy#None is an unauthenticated
// endpoint attempt.
func TestOPCUAInsecurePolicy(t *testing.T) {
	endpoint := "opc.tcp://target/UA"
	hb := make([]byte, 24+len(endpoint))
	binary.LittleEndian.PutUint32(hb[20:24], uint32(len(endpoint)))
	copy(hb[24:], endpoint)
	hel := append([]byte("HELF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(hel[4:8], uint32(8+len(hb)))
	hel = append(hel, hb...)

	uri := "http://opcfoundation.org/UA/SecurityPolicy#None"
	ob := make([]byte, 8+len(uri)+8)
	binary.LittleEndian.PutUint32(ob[4:8], uint32(len(uri)))
	copy(ob[8:], uri)
	opn := append([]byte("OPNF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(opn[4:8], uint32(8+len(ob)))
	opn = append(opn, ob...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&opcua{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, append(hel, opn...))
	if p, _ := r.Meta["opcua_security_policy"].(string); !strings.HasSuffix(p, "#None") {
		t.Errorf("opcua_security_policy = %v, want ...#None", r.Meta["opcua_security_policy"])
	}
	if !hasAnom(r, "ics-opcua-insecure-policy") {
		t.Errorf("insecure policy not flagged: %v", r.Meta["anomalies"])
	}
}

// MMS: after the association completes, an MMS Read request reads IED values.
func TestMMSReadService(t *testing.T) {
	cr := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	aarq := []byte{0x03, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0x00}
	read := []byte{0x03, 0x00, 0x00, 0x0E, 0x02, 0xF0, 0x80,
		0xA0, 0x06, 0x02, 0x01, 0x01, 0xA4, 0x00}
	msg := append(append(append([]byte{}, cr...), aarq...), read...)

	r := driveDrain(t, func(c net.Conn) Result {
		res, _ := (&mms{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, msg)
	if r.Meta["mms_service"] != "read" {
		t.Errorf("mms_service = %v, want read", r.Meta["mms_service"])
	}
	if !hasAnom(r, "ics-process-data-access") {
		t.Errorf("MMS read not flagged: %v", r.Meta["anomalies"])
	}
}
