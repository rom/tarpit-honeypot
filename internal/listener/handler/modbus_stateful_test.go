package handler

import (
	"encoding/binary"
	"testing"
)

// modbusSession drives the handler over net.Pipe with the given MBAP frames
// (roundtrip drains responses concurrently, so multi-PDU sessions don't
// deadlock the synchronous pipe), ending with a non-Modbus frame so the
// handler breaks its read loop and returns. It returns the concatenated
// response bytes.
func modbusSession(t *testing.T, frames ...[]byte) []byte {
	t.Helper()
	var in []byte
	for _, f := range frames {
		in = append(in, f...)
	}
	in = append(in, 0, 9, 0xFF, 0xFF, 0, 2, 0) // protoID!=0 -> handler returns
	_, out := roundtrip(t, &modbus{}, string(in))
	return out
}

// A holding register written earlier in the session must read back the written
// value (0xBEEF differs from the synthetic default for register 10, so this
// genuinely exercises the per-session overlay rather than the formula).
func TestModbusWriteThenReadRegisterCoherent(t *testing.T) {
	out := modbusSession(t,
		mbap(1, 0x11, []byte{0x06, 0x00, 0x0A, 0xBE, 0xEF}), // write reg 10 = 0xBEEF
		mbap(2, 0x11, []byte{0x03, 0x00, 0x0A, 0x00, 0x01}), // read reg 10
	)
	// write echo (7+5=12) + read response (7+4=11); register value at [21:23].
	if len(out) < 23 {
		t.Fatalf("short response (%d bytes): % x", len(out), out)
	}
	if got := binary.BigEndian.Uint16(out[21:23]); got != 0xBEEF {
		t.Errorf("register read-back = 0x%04X; want 0xBEEF (write not reflected)", got)
	}
}

// Same for a coil: write coil 0 ON (synthetic default OFF) and read it back.
func TestModbusWriteThenReadCoilCoherent(t *testing.T) {
	if modbusSynthCoil(0) {
		t.Skip("coil 0 synthetic default is ON; pick another address")
	}
	out := modbusSession(t,
		mbap(1, 0x11, []byte{0x05, 0x00, 0x00, 0xFF, 0x00}), // write coil 0 = ON
		mbap(2, 0x11, []byte{0x01, 0x00, 0x00, 0x00, 0x01}), // read coil 0
	)
	// write echo (12) + read response (7+3=10); coil bits in the last byte.
	if len(out) < 22 {
		t.Fatalf("short response (%d bytes): % x", len(out), out)
	}
	if out[21]&0x01 == 0 {
		t.Errorf("coil read-back byte = 0x%02X; want bit0 set (write not reflected)", out[21])
	}
}

// Read/Write Multiple Registers (FC 0x17) applies its write half before the
// read half, so a value written to an address it also reads comes back.
func TestModbusReadWriteMultipleCoherent(t *testing.T) {
	// read 1 reg @ addr 20; write 1 reg @ addr 20 = 0x1234.
	pdu := []byte{0x17, 0x00, 0x14, 0x00, 0x01, 0x00, 0x14, 0x00, 0x01, 0x02, 0x12, 0x34}
	out := modbusSession(t, mbap(1, 0x11, pdu))
	// response: MBAP(7) + fc + bytecount + 2 data = 11 bytes; data at [9:11].
	if len(out) < 11 {
		t.Fatalf("short response (%d bytes): % x", len(out), out)
	}
	if got := binary.BigEndian.Uint16(out[9:11]); got != 0x1234 {
		t.Errorf("FC 0x17 read-back = 0x%04X; want 0x1234", got)
	}
}
