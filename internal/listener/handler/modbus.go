package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

type modbus struct{}

func (m *modbus) Name() string { return "modbus" }

// Modbus TCP (port 502). Per Modbus Messaging on TCP/IP (MBAP):
//
//	transaction_id (2) | protocol_id (2) | length (2) | unit_id (1) | data...
//
// Handles a multi-PDU session (real scanners send a sequence like
// 0x2B → 0x03 → 0x06 — vendor probe, register read, register write).
// We answer believable success for the read commands and capture
// any write attempts in res.Meta. The "Read Device Identification"
// vendor probe (FC 0x2B / subfunction 0x0E) is the big deception
// hook — that's what nmap's modbus-discover script uses.
func (m *modbus) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	var pdus []map[string]any
	var totalPayload []byte
	const maxPDUs = 16

	for p := 0; p < maxPDUs; p++ {
		// Read MBAP header (7 bytes through unit_id).
		hdr := make([]byte, 7)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if p == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		txID := binary.BigEndian.Uint16(hdr[0:2])
		protoID := binary.BigEndian.Uint16(hdr[2:4])
		length := binary.BigEndian.Uint16(hdr[4:6])
		unitID := hdr[6]

		// length is the MBAP "length" field — covers unit_id + PDU.
		// A PDU must carry at least the function-code byte, so the
		// shortest legal length is 2. Without this guard, length==1
		// produces a 0-byte PDU and the function-code dereference
		// panics — an attacker would otherwise crash the handler
		// goroutine on every connection.
		if protoID != 0 || length < 2 || length > 254 {
			res.Meta["non_modbus_proto_id"] = protoID
			res.Meta["length"] = length
			break
		}

		pduBuf, ok := safe.AllocBytes(int(length) - 1)
		if !ok {
			res.Meta["alloc_err"] = length
			break
		}
		if _, err := io.ReadFull(conn, pduBuf); err != nil {
			res.Meta["read_err"] = err.Error()
			break
		}
		totalPayload = append(totalPayload, hdr...)
		totalPayload = append(totalPayload, pduBuf...)

		entry := map[string]any{
			"transaction_id": txID,
			"unit_id":        unitID,
		}
		rpdu := m.respondPDU(pduBuf, entry)
		pdus = append(pdus, entry)

		// Writing to a "PLC" (coils/registers/file records) is an attacker
		// manipulating the control process, not a benign scan — flag it
		// (maps to ATT&CK for ICS T0836 Modify Parameter / T0831
		// Manipulation of Control).
		if fcv, ok := entry["function_code"].(byte); ok {
			switch {
			case modbusIsWrite(fcv):
				flagAnomaly(&res, "modbus-write-attempt")
				res.Meta["intent"] = "Modbus " + modbusFCName(fcv) + " — writing to a PLC (control manipulation)"
			case fcv == 0x08: // Diagnostics — restart/listen-only are control/DoS.
				if sub, ok := entry["diag_subfunction"].(uint16); ok && (sub == 0x0001 || sub == 0x0004) {
					flagAnomaly(&res, "ics-modbus-diagnostic")
					res.Meta["intent"] = "Modbus Diagnostics — " + modbusDiagName(sub) + " (control/DoS)"
				}
			case fcv == 0x2B: // Read Device Identification = PLC fingerprinting.
				setIfEmpty(res.Meta, "intent", "Modbus Read Device Identification — PLC vendor/model fingerprinting")
			case fcv == 0x11: // Report Server ID = device fingerprinting.
				setIfEmpty(res.Meta, "intent", "Modbus Report Server ID — device fingerprinting")
			default:
				setIfEmpty(res.Meta, "intent", "Modbus "+modbusFCName(fcv)+" — sampling registers/coils (recon)")
			}
		}

		if rpdu != nil {
			rlen := uint16(len(rpdu) + 1)
			resp := make([]byte, 0, 7+len(rpdu))
			resp = binary.BigEndian.AppendUint16(resp, txID)
			resp = binary.BigEndian.AppendUint16(resp, 0)
			resp = binary.BigEndian.AppendUint16(resp, rlen)
			resp = append(resp, unitID)
			resp = append(resp, rpdu...)
			if _, err := conn.Write(resp); err != nil {
				res.Meta["write_err"] = err.Error()
				break
			}
		}
	}

	if len(pdus) > 0 {
		res.Meta["pdus"] = pdus
		// Convenience: keep flat top-level fields for SIEM rules that
		// matched on these in v1.x.
		if first, ok := pdus[0]["function_code"].(byte); ok {
			res.Meta["function_code"] = first
		}
		if first, ok := pdus[0]["unit_id"].(byte); ok {
			res.Meta["unit_id"] = first
		}
		if first, ok := pdus[0]["transaction_id"].(uint16); ok {
			res.Meta["transaction_id"] = first
		}
	}
	res.Payload = totalPayload
	res.BannerSent = "modbus mbap multi-pdu"
	return res, nil
}

// respondPDU dispatches by function code, fills meta, and returns the
// reply PDU body. Returns nil if the request was so malformed we
// don't want to reply at all.
func (m *modbus) respondPDU(pdu []byte, meta map[string]any) []byte {
	if len(pdu) < 1 {
		return nil
	}
	fc := pdu[0]
	meta["function_code"] = fc
	meta["function_name"] = modbusFCName(fc)

	switch fc {
	case 0x01, 0x02: // Read Coils / Discrete Inputs
		// Request: starting_addr(2) + quantity(2).
		quantity := uint16(1)
		if len(pdu) >= 5 {
			meta["start_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			quantity = binary.BigEndian.Uint16(pdu[3:5])
			meta["quantity"] = quantity
		}
		if quantity == 0 || quantity > 2000 {
			return []byte{fc | 0x80, 0x03} // illegal data value
		}
		nBytes := int((quantity + 7) / 8)
		out := append([]byte{fc, byte(nBytes)}, make([]byte, nBytes)...)
		// Make a few bits non-zero so the read result looks alive.
		for i := 0; i < nBytes; i++ {
			out[2+i] = byte((i + 1) * 17)
		}
		return out
	case 0x03, 0x04: // Read Holding / Input Registers
		quantity := uint16(1)
		if len(pdu) >= 5 {
			meta["start_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			quantity = binary.BigEndian.Uint16(pdu[3:5])
			meta["quantity"] = quantity
		}
		if quantity == 0 || quantity > 125 {
			return []byte{fc | 0x80, 0x03}
		}
		// Generate a 2-byte * quantity register block with believable
		// process values (1000 .. 1500 + small sine-ish drift).
		out := append([]byte{fc, byte(quantity * 2)}, make([]byte, quantity*2)...)
		for i := uint16(0); i < quantity; i++ {
			val := 1000 + (i*173)%500
			binary.BigEndian.PutUint16(out[2+2*i:4+2*i], val)
		}
		return out
	case 0x05: // Write Single Coil
		if len(pdu) >= 5 {
			meta["coil_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			meta["coil_value"] = binary.BigEndian.Uint16(pdu[3:5])
		}
		// Echo: function + addr + value (5 bytes total).
		out := make([]byte, len(pdu))
		copy(out, pdu)
		return out
	case 0x06: // Write Single Register
		if len(pdu) >= 5 {
			meta["reg_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			meta["reg_value"] = binary.BigEndian.Uint16(pdu[3:5])
		}
		out := make([]byte, len(pdu))
		copy(out, pdu)
		return out
	case 0x0F: // Write Multiple Coils
		if len(pdu) >= 6 {
			meta["start_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			meta["quantity"] = binary.BigEndian.Uint16(pdu[3:5])
			meta["byte_count"] = pdu[5]
		}
		if len(pdu) >= 5 {
			return append([]byte{fc}, pdu[1:5]...) // echo addr + quantity
		}
		return []byte{fc | 0x80, 0x03}
	case 0x10: // Write Multiple Registers
		if len(pdu) >= 6 {
			meta["start_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			meta["quantity"] = binary.BigEndian.Uint16(pdu[3:5])
			meta["byte_count"] = pdu[5]
			// Capture the values the attacker tried to write (capped
			// at 16 registers for log size). Anything outside
			// "control-loop tuning" range is worth a closer look.
			values := []uint16{}
			for off := 6; off+1 < len(pdu) && len(values) < 16; off += 2 {
				values = append(values, binary.BigEndian.Uint16(pdu[off:off+2]))
			}
			meta["written_values"] = values
		}
		if len(pdu) >= 5 {
			return append([]byte{fc}, pdu[1:5]...) // echo addr + quantity
		}
		return []byte{fc | 0x80, 0x03}
	case 0x16: // Mask Write Register
		if len(pdu) >= 7 {
			meta["reg_addr"] = binary.BigEndian.Uint16(pdu[1:3])
			meta["and_mask"] = binary.BigEndian.Uint16(pdu[3:5])
			meta["or_mask"] = binary.BigEndian.Uint16(pdu[5:7])
			out := make([]byte, len(pdu))
			copy(out, pdu) // echo request
			return out
		}
		return []byte{fc | 0x80, 0x03}
	case 0x17: // Read/Write Multiple Registers
		if len(pdu) >= 10 {
			readQty := binary.BigEndian.Uint16(pdu[3:5])
			meta["read_qty"] = readQty
			meta["write_addr"] = binary.BigEndian.Uint16(pdu[5:7])
			meta["write_qty"] = binary.BigEndian.Uint16(pdu[7:9])
			if readQty == 0 || readQty > 125 {
				return []byte{fc | 0x80, 0x03}
			}
			out := append([]byte{fc, byte(readQty * 2)}, make([]byte, readQty*2)...)
			for i := uint16(0); i < readQty; i++ {
				binary.BigEndian.PutUint16(out[2+2*i:4+2*i], 1000+(i*173)%500)
			}
			return out
		}
		return []byte{fc | 0x80, 0x03}
	case 0x08: // Diagnostics
		// sub-function(2) + data(2). Echo the request like a real device
		// (FC 0x08 is a request/echo loopback for most sub-functions).
		if len(pdu) >= 3 {
			meta["diag_subfunction"] = binary.BigEndian.Uint16(pdu[1:3])
		}
		out := make([]byte, len(pdu))
		copy(out, pdu)
		return out
	case 0x11: // Report Server ID
		// vendor: "MX3 " + run-status 0xff (running).
		return []byte{0x11, 0x05, 0x4d, 0x58, 0x33, 0x20, 0xff}
	case 0x14: // Read File Record
		// Capture the record numbers requested, then deny.
		if len(pdu) >= 2 {
			meta["byte_count"] = pdu[1]
		}
		return []byte{fc | 0x80, 0x02} // illegal data address
	case 0x2B: // Encapsulated Interface Transport
		// Subfunction 0x0E = Read Device Identification (MEI 14).
		// This is the nmap modbus-discover probe.
		if len(pdu) >= 4 && pdu[1] == 0x0E {
			deviceID := pdu[2] // 0x01=basic, 0x02=regular, 0x03=extended, 0x04=specific
			objID := pdu[3]
			meta["mei_subfunction"] = pdu[1]
			meta["device_id_code"] = deviceID
			meta["object_id"] = objID
			return modbusReadDeviceID(deviceID, objID)
		}
		return []byte{fc | 0x80, 0x01}
	}
	// Exception: illegal function.
	return []byte{fc | 0x80, 0x01}
}

// modbusReadDeviceID builds the response for FC 0x2B / MEI 0x0E
// (Read Device Identification). The exact format per Modbus
// Application Protocol §6.21:
//
//	MEI subfunction(1) read_dev_id_code(1) conformity(1)
//	more_follows(1) next_id(1) num_objects(1)
//	{ object_id(1) object_len(1) object_data(*) } * num_objects
//
// We advertise as a plausible commercial PLC — vendor "Schneider
// Electric", product "BMX P34 2020" — which is what an attacker
// scanning industrial networks expects to find.
func modbusReadDeviceID(deviceID, objID byte) []byte {
	type obj struct {
		id   byte
		data string
	}
	// Basic identification = mandatory objects 0..2.
	// Regular adds 3..6.
	// Extended adds 7..0x7F (vendor-specific).
	objects := []obj{
		{0x00, "Schneider Electric"}, // VendorName
		{0x01, "BMX P34 2020"},       // ProductCode
		{0x02, "V2.70"},              // MajorMinorRevision
	}
	if deviceID >= 0x02 {
		objects = append(objects,
			obj{0x03, "https://www.schneider-electric.com/"},
			obj{0x04, "Modicon M340"},
			obj{0x05, "BMX P34 2020"},
			obj{0x06, "Schneider PLC"},
		)
	}
	if deviceID >= 0x03 {
		objects = append(objects,
			obj{0x07, "Conformity Class 1, Basic"},
		)
	}

	// If a specific objID was asked for, return just that one.
	if deviceID == 0x04 {
		for _, o := range objects {
			if o.id == objID {
				body := []byte{
					0x0E, // MEI subfunction
					0x04, // device_id_code (specific)
					0x83, // conformity (extended + r/w)
					0x00, // more follows
					0x00, // next id
					0x01, // number of objects
					o.id, byte(len(o.data)),
				}
				body = append(body, []byte(o.data)...)
				return append([]byte{0x2B}, body...)
			}
		}
		return []byte{0x2B | 0x80, 0x02}
	}

	body := []byte{
		0x0E,               // MEI subfunction
		deviceID,           // echoed device_id_code
		0x83,               // conformity (extended + r/w)
		0x00,               // more follows
		0x00,               // next id
		byte(len(objects)), // number of objects
	}
	for _, o := range objects {
		body = append(body, o.id, byte(len(o.data)))
		body = append(body, []byte(o.data)...)
	}
	return append([]byte{0x2B}, body...)
}

// modbusIsWrite reports whether a function code mutates PLC state (coils,
// registers, or file records) — the writes worth flagging as control-system
// manipulation rather than reconnaissance.
func modbusIsWrite(fc byte) bool {
	switch fc {
	case 0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17:
		return true
	}
	return false
}

// modbusDiagName names the notable Modbus Diagnostics (FC 0x08) sub-functions
// that affect device availability rather than just looping data back.
func modbusDiagName(sub uint16) string {
	switch sub {
	case 0x0001:
		return "Restart Communications Option"
	case 0x0004:
		return "Force Listen Only Mode"
	}
	return "sub-function 0x" + itoa(int(sub))
}

// modbusFCName returns the symbolic function-code name for the meta
// log so SIEM rules can match on "function_name=Write Multiple
// Registers" instead of bare 0x10. Covers the function codes a
// realistic scanner / attacker would emit.
func modbusFCName(fc byte) string {
	switch fc {
	case 0x01:
		return "Read Coils"
	case 0x02:
		return "Read Discrete Inputs"
	case 0x03:
		return "Read Holding Registers"
	case 0x04:
		return "Read Input Registers"
	case 0x05:
		return "Write Single Coil"
	case 0x06:
		return "Write Single Register"
	case 0x07:
		return "Read Exception Status"
	case 0x08:
		return "Diagnostics"
	case 0x0B:
		return "Get Comm Event Counter"
	case 0x0C:
		return "Get Comm Event Log"
	case 0x0F:
		return "Write Multiple Coils"
	case 0x10:
		return "Write Multiple Registers"
	case 0x11:
		return "Report Server ID"
	case 0x14:
		return "Read File Record"
	case 0x15:
		return "Write File Record"
	case 0x16:
		return "Mask Write Register"
	case 0x17:
		return "Read/Write Multiple Registers"
	case 0x18:
		return "Read FIFO Queue"
	case 0x2B:
		return "Encapsulated Interface Transport"
	}
	return ""
}
