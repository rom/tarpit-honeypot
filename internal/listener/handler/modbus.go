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

	// Per-session register/coil overlay so the emulator is coherent across a
	// multi-PDU session: a value written earlier in the connection is returned
	// by a later read of the same address (the write-then-read-back check a
	// careful attacker uses to tell a real PLC from a stateless decoy).
	mem := newModbusMem()

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
		rpdu := m.respondPDU(pduBuf, entry, mem)
		pdus = append(pdus, entry)

		// Per-PDU enrichment + intent/anomaly classification: register-reference
		// + vendor-tag, control-vs-recon, UMAS / vendor-function / program-
		// transfer / diagnostics. Maps to ATT&CK for ICS (T0836/T0831/...).
		modbusClassify(entry, &res)

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
		// Session-level enumeration: unit-id sweep, function-code scan,
		// broadcast write.
		modbusSessionAnalysis(pdus, &res)
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

// modbusMem is a per-session register/coil overlay. It makes the emulator
// coherent across a multi-PDU session: a value written earlier in the
// connection is returned by a later read of the same address, while unwritten
// addresses fall back to stable synthetic process data. Bounded so a write
// sweep across the address space can't grow memory without limit, and
// per-connection — no shared mutable state between attackers.
type modbusMem struct {
	regs  map[uint16]uint16
	coils map[uint16]bool
}

const modbusMemCap = 4096

func newModbusMem() *modbusMem {
	return &modbusMem{regs: make(map[uint16]uint16), coils: make(map[uint16]bool)}
}

func (s *modbusMem) reg(addr uint16) uint16 {
	if v, ok := s.regs[addr]; ok {
		return v
	}
	return modbusSynthReg(addr)
}

func (s *modbusMem) setReg(addr, val uint16) {
	if _, ok := s.regs[addr]; !ok && len(s.regs) >= modbusMemCap {
		return // bound memory; over-cap writes simply aren't reflected
	}
	s.regs[addr] = val
}

func (s *modbusMem) coil(addr uint16) bool {
	if v, ok := s.coils[addr]; ok {
		return v
	}
	return modbusSynthCoil(addr)
}

func (s *modbusMem) setCoil(addr uint16, on bool) {
	if _, ok := s.coils[addr]; !ok && len(s.coils) >= modbusMemCap {
		return
	}
	s.coils[addr] = on
}

// modbusSynthReg / modbusSynthCoil are the believable defaults for an unwritten
// register / coil, stable per absolute address so repeated reads agree.
func modbusSynthReg(addr uint16) uint16 { return 1000 + (addr*173)%500 }
func modbusSynthCoil(addr uint16) bool  { return (addr*97)&0x40 != 0 }

// respondPDU dispatches by function code, fills meta, and returns the
// reply PDU body. Returns nil if the request was so malformed we
// don't want to reply at all. mem is the per-session register/coil overlay.
func (m *modbus) respondPDU(pdu []byte, meta map[string]any, mem *modbusMem) []byte {
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
		var start uint16
		if len(pdu) >= 5 {
			start = binary.BigEndian.Uint16(pdu[1:3])
			meta["start_addr"] = start
			quantity = binary.BigEndian.Uint16(pdu[3:5])
			meta["quantity"] = quantity
		}
		if quantity == 0 || quantity > 2000 {
			return []byte{fc | 0x80, 0x03} // illegal data value
		}
		nBytes := int((quantity + 7) / 8)
		out := append([]byte{fc, byte(nBytes)}, make([]byte, nBytes)...)
		// Coils (0x01) reflect prior writes this session; discrete inputs
		// (0x02) are read-only synthetic. Either is stable per absolute
		// address, so a re-read returns the same bit.
		for i := uint16(0); i < quantity; i++ {
			on := modbusSynthCoil(start + i)
			if fc == 0x01 {
				on = mem.coil(start + i)
			}
			if on {
				out[2+i/8] |= 1 << (i % 8)
			}
		}
		return out
	case 0x03, 0x04: // Read Holding / Input Registers
		quantity := uint16(1)
		var start uint16
		if len(pdu) >= 5 {
			start = binary.BigEndian.Uint16(pdu[1:3])
			meta["start_addr"] = start
			quantity = binary.BigEndian.Uint16(pdu[3:5])
			meta["quantity"] = quantity
		}
		if quantity == 0 || quantity > 125 {
			return []byte{fc | 0x80, 0x03}
		}
		// Holding registers (0x03) reflect prior writes this session; input
		// registers (0x04) are read-only synthetic. Keyed by absolute address
		// so a re-read of the same register is stable.
		out := append([]byte{fc, byte(quantity * 2)}, make([]byte, quantity*2)...)
		for i := uint16(0); i < quantity; i++ {
			val := modbusSynthReg(start + i)
			if fc == 0x03 {
				val = mem.reg(start + i)
			}
			binary.BigEndian.PutUint16(out[2+2*i:4+2*i], val)
		}
		return out
	case 0x05: // Write Single Coil
		if len(pdu) >= 5 {
			addr := binary.BigEndian.Uint16(pdu[1:3])
			val := binary.BigEndian.Uint16(pdu[3:5])
			meta["coil_addr"] = addr
			meta["coil_value"] = val
			mem.setCoil(addr, val == 0xFF00) // 0xFF00 = ON, 0x0000 = OFF
		}
		// Echo: function + addr + value (5 bytes total).
		out := make([]byte, len(pdu))
		copy(out, pdu)
		return out
	case 0x06: // Write Single Register
		if len(pdu) >= 5 {
			addr := binary.BigEndian.Uint16(pdu[1:3])
			val := binary.BigEndian.Uint16(pdu[3:5])
			meta["reg_addr"] = addr
			meta["reg_value"] = val
			mem.setReg(addr, val)
		}
		out := make([]byte, len(pdu))
		copy(out, pdu)
		return out
	case 0x0F: // Write Multiple Coils
		if len(pdu) >= 6 {
			start := binary.BigEndian.Uint16(pdu[1:3])
			qty := binary.BigEndian.Uint16(pdu[3:5])
			meta["start_addr"] = start
			meta["quantity"] = qty
			meta["byte_count"] = pdu[5]
			for i := uint16(0); i < qty && 6+int(i/8) < len(pdu); i++ {
				mem.setCoil(start+i, pdu[6+i/8]&(1<<(i%8)) != 0)
			}
		}
		if len(pdu) >= 5 {
			return append([]byte{fc}, pdu[1:5]...) // echo addr + quantity
		}
		return []byte{fc | 0x80, 0x03}
	case 0x10: // Write Multiple Registers
		if len(pdu) >= 6 {
			start := binary.BigEndian.Uint16(pdu[1:3])
			meta["start_addr"] = start
			meta["quantity"] = binary.BigEndian.Uint16(pdu[3:5])
			meta["byte_count"] = pdu[5]
			// Apply every written register to the session overlay (so a later
			// read returns it) and capture the first 16 for the log.
			values := []uint16{}
			idx := uint16(0)
			for off := 6; off+1 < len(pdu); off += 2 {
				v := binary.BigEndian.Uint16(pdu[off : off+2])
				mem.setReg(start+idx, v)
				if len(values) < 16 {
					values = append(values, v)
				}
				idx++
			}
			meta["written_values"] = values
		}
		if len(pdu) >= 5 {
			return append([]byte{fc}, pdu[1:5]...) // echo addr + quantity
		}
		return []byte{fc | 0x80, 0x03}
	case 0x16: // Mask Write Register
		if len(pdu) >= 7 {
			addr := binary.BigEndian.Uint16(pdu[1:3])
			andMask := binary.BigEndian.Uint16(pdu[3:5])
			orMask := binary.BigEndian.Uint16(pdu[5:7])
			meta["reg_addr"] = addr
			meta["and_mask"] = andMask
			meta["or_mask"] = orMask
			// result = (current AND and_mask) OR (or_mask AND NOT and_mask)
			mem.setReg(addr, (mem.reg(addr)&andMask)|(orMask&^andMask))
			out := make([]byte, len(pdu))
			copy(out, pdu) // echo request
			return out
		}
		return []byte{fc | 0x80, 0x03}
	case 0x17: // Read/Write Multiple Registers (writes first, then reads)
		if len(pdu) >= 10 {
			readAddr := binary.BigEndian.Uint16(pdu[1:3])
			readQty := binary.BigEndian.Uint16(pdu[3:5])
			writeAddr := binary.BigEndian.Uint16(pdu[5:7])
			writeQty := binary.BigEndian.Uint16(pdu[7:9])
			meta["read_qty"] = readQty
			meta["write_addr"] = writeAddr
			meta["write_qty"] = writeQty
			if readQty == 0 || readQty > 125 {
				return []byte{fc | 0x80, 0x03}
			}
			// Apply the write half first (write registers begin at pdu[10]).
			for i := uint16(0); i < writeQty; i++ {
				off := 10 + int(2*i)
				if off+1 >= len(pdu) {
					break
				}
				mem.setReg(writeAddr+i, binary.BigEndian.Uint16(pdu[off:off+2]))
			}
			out := append([]byte{fc, byte(readQty * 2)}, make([]byte, readQty*2)...)
			for i := uint16(0); i < readQty; i++ {
				binary.BigEndian.PutUint16(out[2+2*i:4+2*i], mem.reg(readAddr+i))
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
		if len(pdu) >= 2 && pdu[1] == 0x0D { // MEI 13 = CANopen General Reference
			meta["mei_subfunction"] = pdu[1]
			return []byte{0x2B, 0x0D, 0x00}
		}
		return []byte{fc | 0x80, 0x01}
	case 0x07: // Read Exception Status
		return []byte{0x07, 0x00}
	case 0x0B: // Get Comm Event Counter
		return []byte{0x0B, 0x00, 0x00, 0x12, 0x34}
	case 0x0C: // Get Comm Event Log
		// byte_count, status(2), event_count(2), message_count(2), events…
		return []byte{0x0C, 0x08, 0x00, 0x00, 0x01, 0x08, 0x01, 0x21, 0x20, 0x00}
	case 0x18: // Read FIFO Queue
		// byte_count(2), fifo_count(2), then fifo_count registers.
		return []byte{0x18, 0x00, 0x06, 0x00, 0x02, 0x01, 0xB8, 0x12, 0x84}
	case 0x14: // Read File Record — return a believable record (config exfil).
		if len(pdu) >= 2 {
			meta["byte_count"] = pdu[1]
		}
		// resp_len, then sub-resp: file_resp_len, ref_type, record data.
		return []byte{0x14, 0x07, 0x06, 0x06, 0x0D, 0xFE, 0x00, 0x20}
	case 0x15: // Write File Record — capture the write attempt.
		if len(pdu) >= 2 {
			meta["byte_count"] = pdu[1]
		}
		out := make([]byte, len(pdu))
		copy(out, pdu) // a real device echoes the request
		return out
	case 0x28: // Schneider program/firmware transfer (vendor)
		meta["vendor_function"] = "program-transfer"
		return []byte{0x28, 0x00}
	case 0x5A: // Schneider UMAS (Unified Messaging Application Services)
		return modbusUMASResponse(pdu, meta)
	case 0x29, 0x2A: // vendor program/firmware (Schneider/others)
		meta["vendor_function"] = "vendor-program"
		return []byte{fc, 0x00}
	}
	// Reserved / vendor-defined function codes (65-72, 100-110, 0x5A handled
	// above): a real device answers vendor-specific; we capture + echo-deny.
	if (fc >= 0x41 && fc <= 0x48) || (fc >= 0x64 && fc <= 0x6E) {
		meta["vendor_function"] = "fc-0x" + itoa(int(fc))
		return []byte{fc | 0x80, 0x01}
	}
	// Exception: illegal function.
	return []byte{fc | 0x80, 0x01}
}

// modbusUMASResponse parses a Schneider UMAS request (Modbus FC 0x5A — the
// proprietary engineering protocol tunnelled inside Modbus that Unity Pro /
// EcoStruxure use). UMAS is unauthenticated by default on Modicon M340/M580 and
// is the channel behind several Schneider advisories; we name the UMAS function
// and return a plausible reply.
func modbusUMASResponse(pdu []byte, meta map[string]any) []byte {
	if len(pdu) < 3 {
		return []byte{0x5A, 0xFE} // UMAS error
	}
	umasFunc := pdu[2] // pdu[1] is the session/pairing byte
	meta["umas_function"] = modbusUMASName(umasFunc)
	meta["umas_function_code"] = umasFunc
	// 0xFD = UMAS positive response prefix.
	return []byte{0x5A, pdu[1], 0xFD}
}

// modbusUMASName names the Schneider UMAS sub-functions that matter for
// attribution (the read/write/run-state/reservation ones).
func modbusUMASName(f byte) string {
	switch f {
	case 0x01:
		return "INIT_COMM"
	case 0x02:
		return "READ_ID"
	case 0x03:
		return "READ_PROJECT_INFO"
	case 0x04:
		return "READ_PLC_INFO"
	case 0x10:
		return "TAKE_PLC_RESERVATION"
	case 0x11:
		return "RELEASE_PLC_RESERVATION"
	case 0x20:
		return "READ_MEMORY_BLOCK"
	case 0x21:
		return "WRITE_MEMORY_BLOCK"
	case 0x22:
		return "READ_VARIABLES"
	case 0x23:
		return "WRITE_VARIABLES"
	case 0x24:
		return "READ_COILS_REGISTERS"
	case 0x25:
		return "WRITE_COILS_REGISTERS"
	case 0x40:
		return "START_PLC"
	case 0x41:
		return "STOP_PLC"
	case 0x50:
		return "MONITOR_PLC"
	}
	return "umas-0x" + itoa(int(f))
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
	case 0x28:
		return "Program (Schneider)"
	case 0x29:
		return "Program 2 (vendor)"
	case 0x2A:
		return "Firmware (vendor)"
	case 0x2B:
		return "Encapsulated Interface Transport"
	case 0x5A:
		return "UMAS (Schneider)"
	}
	if (fc >= 0x41 && fc <= 0x48) || (fc >= 0x64 && fc <= 0x6E) {
		return "Vendor/Reserved 0x" + itoa(int(fc))
	}
	return ""
}
