package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type s7 struct{}

func (s *s7) Name() string { return "s7" }

// Siemens S7comm runs on TPKT/COTP over TCP (port 102). The session is:
// COTP Connection Request (CR) -> Connection Confirm (CC), then S7comm Job
// PDUs over COTP DT data frames. We answer the CC, negotiate Setup
// Communication, and then service the S7comm functions a scanner/attacker
// sends — SZL reads (the module/CPU identification nmap's s7-info parses),
// variable reads/writes, and PLC control (STOP/start, program up/download).
// Read/SZL get believable answers (so the box looks like a live S7-300/400);
// writes and mode/program changes are answered AND flagged as control
// manipulation.
//
// TPKT (RFC 1006): version(1)=0x03 | reserved(1) | length(2)
// COTP CR:  length(1) | type=0xE0 | dst_ref(2) | src_ref(2) | class(1) | params
// COTP DT:  length(1)=0x02 | type=0xF0 | eot(1) | <S7comm...>
// S7comm:   protid=0x32 | rosctr(1) | redid(2) | pduref(2) | parlen(2) | datlen(2)
func (s *s7) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// --- COTP Connection Request -> Connection Confirm ---
	body, ok := readTPKT(conn, &res)
	if !ok {
		return res, nil
	}
	if len(body) < 7 || body[1] != 0xE0 {
		res.Meta["cotp_type"] = fmtByte(safeAt(body, 1))
		return res, nil
	}
	dstRef := binary.BigEndian.Uint16(body[2:4])
	srcRef := binary.BigEndian.Uint16(body[4:6])
	res.Meta["cotp_type"] = "CR"
	res.Meta["dst_ref"] = dstRef
	res.Meta["src_ref"] = srcRef

	params := body[7:]
	cc := make([]byte, 0, 11+len(params))
	cc = append(cc, byte(6+len(params)), 0xD0) // length, type CC
	cc = binary.BigEndian.AppendUint16(cc, srcRef)
	cc = binary.BigEndian.AppendUint16(cc, dstRef)
	cc = append(cc, 0x00) // class 0
	cc = append(cc, params...)
	if err := writeTPKT(conn, cc); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "tpkt+cotp connection confirm"

	// --- S7comm session: service a bounded number of Job PDUs ---
	for i := 0; i < 8; i++ {
		pdu, ok := readTPKT(conn, &res)
		if !ok {
			break
		}
		// COTP DT data PDU: hdr_len(1) type=0xF0 eot(1); S7 begins after it.
		if len(pdu) < 3 || pdu[1] != 0xF0 {
			break
		}
		s7data := pdu[3:]
		if !s.serviceS7(conn, s7data, &res) {
			break
		}
	}
	return res, nil
}

// serviceS7 parses one S7comm PDU, classifies the function, answers it, and
// reports whether the session should continue.
func (s *s7) serviceS7(conn net.Conn, b []byte, res *Result) bool {
	if len(b) < 10 || b[0] != 0x32 {
		return false
	}
	rosctr := b[1]
	pduRef := binary.BigEndian.Uint16(b[4:6])
	parLen := int(binary.BigEndian.Uint16(b[6:8]))
	if rosctr != 1 && rosctr != 7 { // only Job / Userdata carry requests
		return false
	}
	paramStart := 10
	if paramStart+parLen > len(b) || parLen < 1 {
		return false
	}
	param := b[paramStart : paramStart+parLen]
	fn := param[0]

	if rosctr == 7 {
		// Userdata: SZL (system status list) reads = CPU/module fingerprinting.
		return s.serviceUserdata(conn, b, param, pduRef, res)
	}

	res.Meta["s7_function"] = s7FuncName(fn)
	switch fn {
	case 0xF0: // Setup Communication — negotiate, keep the session alive.
		setIfEmpty(res.Meta, "intent", "S7comm setup-communication — negotiating a session with the PLC")
		ack := s7AckData(pduRef, []byte{0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0}, nil)
		writeTPKTDT(conn, ack, res)
		return true
	case 0x04: // Read Var — reading the live process image (recon/collection).
		flagAnomaly(res, "ics-process-data-access")
		setIfEmpty(res.Meta, "intent", "S7comm Read Var — reading PLC memory / process values")
		items := 0
		if len(param) >= 2 {
			items = int(param[1])
		}
		writeTPKTDT(conn, s7AckData(pduRef, []byte{0x04, byte(items)}, s7ReadItems(items)), res)
		return true
	case 0x05: // Write Var — manipulating the control process.
		flagAnomaly(res, "ics-plc-write")
		setIfEmpty(res.Meta, "intent", "S7comm Write Var — writing PLC memory (control manipulation)")
		items := 0
		if len(param) >= 2 {
			items = int(param[1])
		}
		// Acknowledge each item as success (0xFF) so the attacker believes the
		// write landed, while we record it.
		data := make([]byte, items)
		for i := range data {
			data[i] = 0xFF
		}
		writeTPKTDT(conn, s7AckData(pduRef, []byte{0x05, byte(items)}, data), res)
		return true
	case 0x28, 0x29: // PLC Control / PLC Stop — RUN/STOP mode change.
		flagAnomaly(res, "ics-plc-mode-change")
		if fn == 0x29 {
			setIfEmpty(res.Meta, "intent", "S7comm PLC STOP — halting the controller (denial of control)")
		} else {
			setIfEmpty(res.Meta, "intent", "S7comm PLC control — start/restart / program invocation")
		}
		writeTPKTDT(conn, s7Ack(pduRef, param[:1]), res)
		return true
	case 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F: // download/upload of PLC blocks
		flagAnomaly(res, "ics-plc-program-access")
		setIfEmpty(res.Meta, "intent", "S7comm block up/download — accessing PLC program logic")
		writeTPKTDT(conn, s7Ack(pduRef, param[:1]), res)
		return true
	default:
		writeTPKTDT(conn, s7Ack(pduRef, param[:1]), res)
		return true
	}
}

// serviceUserdata handles S7comm Userdata PDUs — specifically SZL reads, which
// nmap's s7-info / plcscan use to fingerprint the CPU (order number, firmware,
// serial). We answer SZL 0x0011 (module identification) and 0x001C (component
// identification) with a believable S7-300 identity.
func (s *s7) serviceUserdata(conn net.Conn, b, param []byte, pduRef uint16, res *Result) bool {
	// Userdata param: 0x00 0x01 0x12, parlen(1), method(1), type/funcgroup(1),
	// subfunc(1), seq(1). Function group low-nibble 0x4 = CPU functions,
	// subfunc 0x01 = Read SZL.
	if len(param) < 8 {
		return false
	}
	funcGroup := param[5] & 0x0F
	subfunc := param[6]
	// SZL id + index live in the data section: 0xFF 0x09 len(2) szlid(2) idx(2).
	dataLen := int(binary.BigEndian.Uint16(b[8:10]))
	dataStart := 10 + int(binary.BigEndian.Uint16(b[6:8]))
	var szlID, szlIdx uint16
	if dataStart+8 <= len(b) && dataLen >= 4 {
		szlID = binary.BigEndian.Uint16(b[dataStart+4 : dataStart+6])
		szlIdx = binary.BigEndian.Uint16(b[dataStart+6 : dataStart+8])
	}
	if funcGroup == 0x4 && subfunc == 0x01 { // Read SZL
		flagAnomaly(res, "ics-field-device-probe")
		res.Meta["s7_szl_id"] = szlID
		setIfEmpty(res.Meta, "intent", "S7comm SZL read — Siemens PLC module/firmware fingerprinting")
		writeTPKTDT(conn, s7SZLResponse(pduRef, param[7], szlID, szlIdx), res)
		return true
	}
	res.Meta["s7_function"] = "Userdata"
	return true
}

// --- S7comm response builders -------------------------------------------

// s7Header frames an S7comm PDU. For Ack/Ack_Data (rosctr 2/3) the header
// carries 2 extra error bytes before the parameters.
func s7Header(rosctr byte, pduRef uint16, param, data []byte) []byte {
	h := []byte{0x32, rosctr, 0x00, 0x00}
	h = binary.BigEndian.AppendUint16(h, pduRef)
	h = binary.BigEndian.AppendUint16(h, uint16(len(param)))
	h = binary.BigEndian.AppendUint16(h, uint16(len(data)))
	if rosctr == 2 || rosctr == 3 || rosctr == 7 {
		h = append(h, 0x00, 0x00) // error class / error code = no error
	}
	h = append(h, param...)
	return append(h, data...)
}

func s7Ack(pduRef uint16, param []byte) []byte { return s7Header(2, pduRef, param, nil) }
func s7AckData(pduRef uint16, param, data []byte) []byte {
	return s7Header(3, pduRef, param, data)
}

// s7ReadItems builds n success data items (return code 0xFF, transport size
// BYTE, 2 bytes of plausible process data each).
func s7ReadItems(n int) []byte {
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, 0xFF, 0x04)                // success, transport size = BYTE
		out = binary.BigEndian.AppendUint16(out, 16) // length in bits (2 bytes)
		out = binary.BigEndian.AppendUint16(out, uint16(1000+i*173%500))
	}
	return out
}

// s7SZLResponse builds a Userdata Ack_Data SZL reply for the well-known SZL
// ids, advertising a Siemens S7-315-2 PN/DP CPU.
func s7SZLResponse(pduRef uint16, seq byte, szlID, szlIdx uint16) []byte {
	param := []byte{0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, seq}

	var records []byte
	recLen := uint16(0)
	switch szlID {
	case 0x0011: // module identification
		recLen = 28
		records = append(records, s7SZLRecord(0x0001, "6ES7 315-2EH14-0AB0 ", recLen)...)
	case 0x001C: // component identification
		recLen = 34
		records = append(records, s7SZLComponent(0x0001, "Technodrome PLC")...)
		records = append(records, s7SZLComponent(0x0005, "S C-C2UR28922012")...)
		records = append(records, s7SZLComponent(0x0007, "Original Siemens Equipment")...)
		records = append(records, s7SZLComponent(0x000A, "Boot Loader           A")...)
	default:
		recLen = 28
		records = append(records, s7SZLRecord(0x0001, "6ES7 315-2EH14-0AB0 ", recLen)...)
	}
	n := uint16(len(records)) / recLen
	data := []byte{0xFF, 0x09}
	data = binary.BigEndian.AppendUint16(data, uint16(4+len(records))) // data length
	data = binary.BigEndian.AppendUint16(data, szlID)
	data = binary.BigEndian.AppendUint16(data, szlIdx)
	data = binary.BigEndian.AppendUint16(data, recLen)
	data = binary.BigEndian.AppendUint16(data, n)
	data = append(data, records...)
	return s7Header(7, pduRef, param, data)
}

// s7SZLRecord builds a fixed-width SZL module-identification record: index(2)
// + MlfB order number (20) + bgtyp(2) + ausbg(2) + ausbg2(2) = 28 bytes.
func s7SZLRecord(index uint16, mlfb string, recLen uint16) []byte {
	rec := make([]byte, recLen)
	binary.BigEndian.PutUint16(rec[0:2], index)
	copy(rec[2:22], padRight(mlfb, 20))
	binary.BigEndian.PutUint16(rec[24:26], 0x0001) // version of the module
	return rec
}

// s7SZLComponent builds a component-identification record: index(2) + 32-byte
// text field = 34 bytes.
func s7SZLComponent(index uint16, text string) []byte {
	rec := make([]byte, 34)
	binary.BigEndian.PutUint16(rec[0:2], index)
	copy(rec[2:34], padRight(text, 32))
	return rec
}

// --- TPKT/COTP framing helpers ------------------------------------------
// (readTPKT/writeTPKT/safeAt are shared with s7comm_plus.go.)

// writeTPKTDT wraps an S7comm PDU in a COTP DT data header + TPKT and writes it.
func writeTPKTDT(conn net.Conn, s7 []byte, res *Result) bool {
	cotp := append([]byte{0x02, 0xF0, 0x80}, s7...) // DT data, EOT
	if err := writeTPKT(conn, cotp); err != nil {
		res.Meta["write_err"] = err.Error()
		return false
	}
	return true
}

func s7FuncName(fn byte) string {
	switch fn {
	case 0xF0:
		return "Setup Communication"
	case 0x04:
		return "Read Var"
	case 0x05:
		return "Write Var"
	case 0x1A:
		return "Request Download"
	case 0x1B:
		return "Download Block"
	case 0x1C:
		return "Download Ended"
	case 0x1D:
		return "Start Upload"
	case 0x1E:
		return "Upload"
	case 0x1F:
		return "End Upload"
	case 0x28:
		return "PLC Control"
	case 0x29:
		return "PLC Stop"
	}
	return "fn" + fmtByte(fn)
}

func padRight(s string, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if i < len(s) {
			out[i] = s[i]
		} else {
			out[i] = ' '
		}
	}
	return out
}

func fmtByte(b byte) string {
	const hex = "0123456789abcdef"
	return "0x" + string([]byte{hex[b>>4], hex[b&0x0f]})
}
