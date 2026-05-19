package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type modbus struct{}

func (m *modbus) Name() string { return "modbus" }

// Modbus TCP (port 502). Per Modbus Messaging on TCP/IP (MBAP):
//
//   transaction_id (2) | protocol_id (2) | length (2) | unit_id (1) | data...
//
// We read one PDU, log function_code + unit_id, then respond with a plausible
// success for the few common function codes that scanners try. For everything
// else we send a Modbus exception (illegal function), which is what a real
// PLC does and what a scanner expects.
func (m *modbus) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	// Read MBAP header (7 bytes through unit_id).
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	txID := binary.BigEndian.Uint16(hdr[0:2])
	protoID := binary.BigEndian.Uint16(hdr[2:4])
	length := binary.BigEndian.Uint16(hdr[4:6])
	unitID := hdr[6]

	if protoID != 0 || length < 1 || int(length) > 254 {
		// Not Modbus; record what we got and bail.
		res.Meta = map[string]any{"non_modbus_proto_id": protoID, "length": length}
		return res, nil
	}

	// Read the PDU.
	pdu := make([]byte, int(length)-1)
	if _, err := io.ReadFull(conn, pdu); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(hdr, pdu...)
	fc := pdu[0]
	res.Meta = map[string]any{
		"function_code":  fc,
		"unit_id":        unitID,
		"transaction_id": txID,
	}

	// Build response.
	var rpdu []byte
	switch fc {
	case 0x01, 0x02: // Read Coils / Discrete Inputs — return 1 byte of zeros
		rpdu = []byte{fc, 0x01, 0x00}
	case 0x03, 0x04: // Read Holding / Input Registers — return 1 register = 2 bytes
		rpdu = []byte{fc, 0x02, 0x00, 0x00}
	case 0x11: // Report Server ID
		// vendor-shaped: "MX3" + " " + run-status
		rpdu = []byte{0x11, 0x05, 0x4d, 0x58, 0x33, 0x20, 0xff}
	default:
		// Exception response: fc | 0x80, error code 0x01 (illegal function)
		rpdu = []byte{fc | 0x80, 0x01}
	}

	// Send response with the same transaction_id + unit_id.
	rlen := uint16(len(rpdu) + 1)
	resp := make([]byte, 0, 7+len(rpdu))
	resp = binary.BigEndian.AppendUint16(resp, txID)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = binary.BigEndian.AppendUint16(resp, rlen)
	resp = append(resp, unitID)
	resp = append(resp, rpdu...)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "modbus mbap response"
	return res, nil
}
