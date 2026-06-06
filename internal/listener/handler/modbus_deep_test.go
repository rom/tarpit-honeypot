package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// mbap wraps a Modbus PDU in an MBAP header with the given unit id.
func mbap(txID uint16, unit byte, pdu []byte) []byte {
	h := make([]byte, 7)
	binary.BigEndian.PutUint16(h[0:2], txID)
	binary.BigEndian.PutUint16(h[2:4], 0)                  // protocol id
	binary.BigEndian.PutUint16(h[4:6], uint16(len(pdu)+1)) // length = unit + pdu
	h[6] = unit
	return append(h, pdu...)
}

func driveModbus(t *testing.T, frames []byte) Result {
	t.Helper()
	return driveDrain(t, func(c net.Conn) Result {
		res, _ := (&modbus{}).Handle(context.Background(), c, config.Listener{ReadTimeout: time.Second})
		return res
	}, frames)
}

// Schneider UMAS (FC 0x5A) is the unauthenticated engineering channel.
func TestModbusUMAS(t *testing.T) {
	// FC 0x5A, session 0x00, UMAS func 0x41 = STOP_PLC.
	r := driveModbus(t, mbap(1, 0x00, []byte{0x5A, 0x00, 0x41}))
	if !hasAnom(r, "modbus-umas") {
		t.Errorf("UMAS not flagged: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "ics-plc-mode-change") {
		t.Errorf("UMAS STOP_PLC not classified as mode change: %v", r.Meta["anomalies"])
	}
	if !hasAnom(r, "cve:CVE-2018-7842") {
		t.Errorf("UMAS CVE not attributed: %v", r.Meta["anomalies"])
	}
}

// A vendor/reserved function code is a proprietary/backdoor channel.
func TestModbusVendorFunction(t *testing.T) {
	r := driveModbus(t, mbap(1, 1, []byte{0x66, 0x01, 0x02}))
	if !hasAnom(r, "modbus-vendor-function") {
		t.Errorf("vendor FC not flagged: %v", r.Meta["anomalies"])
	}
}

// A program/firmware-transfer function is a logic download.
func TestModbusProgramDownload(t *testing.T) {
	r := driveModbus(t, mbap(1, 1, []byte{0x28, 0x01}))
	if !hasAnom(r, "modbus-program-download") || !hasAnom(r, "ics-plc-program-access") {
		t.Errorf("program transfer not flagged: %v", r.Meta["anomalies"])
	}
}

// Register-reference + vendor-tag enrichment for a holding-register read.
func TestModbusRegisterEnrichment(t *testing.T) {
	// FC 0x03 read holding regs, start 100, qty 1.
	r := driveModbus(t, mbap(1, 1, []byte{0x03, 0x00, 0x64, 0x00, 0x01}))
	pdus, _ := r.Meta["pdus"].([]map[string]any)
	if len(pdus) == 0 {
		t.Fatal("no pdus captured")
	}
	if pdus[0]["register_class"] != "holding-register" {
		t.Errorf("register_class = %v", pdus[0]["register_class"])
	}
	if pdus[0]["register_ref"] != "400101" {
		t.Errorf("register_ref = %v, want 400101", pdus[0]["register_ref"])
	}
	if pdus[0]["tag_hint"] != "%MW100" {
		t.Errorf("tag_hint = %v, want %%MW100", pdus[0]["tag_hint"])
	}
}

// Many distinct unit ids in one session = a unit/slave sweep.
func TestModbusUnitEnumeration(t *testing.T) {
	var frames []byte
	for u := byte(1); u <= 5; u++ {
		frames = append(frames, mbap(uint16(u), u, []byte{0x03, 0x00, 0x00, 0x00, 0x01})...)
	}
	r := driveModbus(t, frames)
	if !hasAnom(r, "modbus-uid-enumeration") {
		t.Errorf("unit-id enumeration not flagged: %v", r.Meta["anomalies"])
	}
}

// A broadcast (unit 0) write hits every slave at once.
func TestModbusBroadcastWrite(t *testing.T) {
	r := driveModbus(t, mbap(1, 0x00, []byte{0x06, 0x00, 0x0A, 0x12, 0x34}))
	if !hasAnom(r, "modbus-broadcast-write") {
		t.Errorf("broadcast write not flagged: %v", r.Meta["anomalies"])
	}
}
