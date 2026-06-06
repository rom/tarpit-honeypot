package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// s7commPlus emulates the S7comm-Plus protocol used by Siemens S7-1200 /
// S7-1500 PLCs (TCP 102). Like classic S7comm it rides TPKT (RFC 1006) +
// COTP: the client opens with a COTP Connection Request, we answer with a
// Connection Confirm, then the client sends the first S7comm-Plus data
// PDU (TPKT + COTP DT + protocol id 0x72, vs classic S7comm's 0x32). We
// capture that PDU and classify the protocol so a scanner records an
// S7-1500-class controller. Read-only / fingerprint-grade.
type s7commPlus struct{}

func (s *s7commPlus) Name() string { return "s7comm_plus" }

func (s *s7commPlus) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	cr, ok := readTPKT(conn, &res)
	if !ok {
		return res, nil
	}
	if len(cr) < 7 || cr[1] != 0xE0 { // COTP CR type 0xE0
		res.Meta["cotp_type"] = fmtByte(safeAt(cr, 1))
		return res, nil
	}
	dstRef := binary.BigEndian.Uint16(cr[2:4])
	srcRef := binary.BigEndian.Uint16(cr[4:6])
	res.Meta["cotp_type"] = "CR"

	// Connection Confirm (type 0xD0), echoing the negotiated params.
	params := cr[7:]
	cc := []byte{byte(6 + len(params)), 0xD0}
	cc = binary.BigEndian.AppendUint16(cc, srcRef)
	cc = binary.BigEndian.AppendUint16(cc, dstRef)
	cc = append(cc, 0x00)
	cc = append(cc, params...)
	if err := writeTPKT(conn, cc); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "tpkt+cotp connection confirm"

	// Read the first data PDU and classify S7comm-Plus (0x72) vs classic
	// S7comm (0x32). The protocol id sits just past the COTP DT header
	// (COTP DT = length(1) 0xF0 eot(1)), i.e. body[3].
	dt, ok := readTPKT(conn, &res)
	if !ok || len(dt) < 4 {
		return res, nil
	}
	switch dt[3] {
	case 0x72:
		res.Meta["s7_protocol"] = "S7comm-Plus"
		flagAnomaly(&res, "ics-s7commplus-probe")
		s7plusClassify(dt, &res)
	case 0x32:
		res.Meta["s7_protocol"] = "S7comm"
	default:
		res.Meta["s7_protocol"] = "unknown"
	}
	return res, nil
}

// s7plusClassify parses an S7comm-Plus data PDU and classifies the function.
// Layout after the COTP DT header (dt[0:3] = 02 F0 80):
//
//	protocolID(1)=0x72 | version(1) | dataLen(2) | opcode(1) | reserved(2) |
//	function(2 BE) | ...
//
// We name the opcode + function and map read/write/explore/object ops to the
// ATT&CK-for-ICS techniques. The protocol version hints the firmware family
// (v1 ≈ S7-1200, v2/v3 ≈ S7-1500).
func s7plusClassify(dt []byte, res *Result) {
	if len(dt) < 5 {
		return
	}
	ver := dt[4]
	res.Meta["s7plus_version"] = ver
	switch ver {
	case 0x01:
		res.Meta["s7plus_family"] = "S7-1200"
	case 0x02, 0x03:
		res.Meta["s7plus_family"] = "S7-1500"
	}
	if len(dt) < 8 {
		return
	}
	res.Meta["s7plus_opcode"] = s7plusOpcodeName(dt[7])
	if len(dt) < 12 {
		return
	}
	fn := binary.BigEndian.Uint16(dt[10:12])
	res.Meta["s7plus_function"] = s7plusFuncName(fn)
	switch fn {
	case 0x04bb: // Explore — browse the object/variable tree
		flagAnomaly(res, "ics-field-device-probe")
		setIfEmpty(res.Meta, "intent", "S7comm-Plus Explore — enumerating the S7-1500 object tree")
	case 0x0560, 0x04f2, 0x0586: // GetMultiVariables / GetVarSubStreamed
		flagAnomaly(res, "ics-process-data-access")
		setIfEmpty(res.Meta, "intent", "S7comm-Plus read — reading PLC variables")
	case 0x0524, 0x0554, 0x0556: // SetVariable / SetMultiVariables / SetVarSubStreamed
		flagAnomaly(res, "ics-plc-write")
		res.Meta["intent"] = "S7comm-Plus write — writing PLC variables (control manipulation)"
	case 0x04ca, 0x04d4, 0x0589: // CreateObject / DeleteObject / Invoke
		flagAnomaly(res, "ics-plc-program-access")
		res.Meta["intent"] = "S7comm-Plus " + s7plusFuncName(fn) + " — object/program manipulation"
	}
}

func s7plusOpcodeName(op byte) string {
	switch op {
	case 0x31:
		return "Request"
	case 0x32:
		return "Response"
	case 0x33:
		return "Notification"
	}
	return "op-0x" + fmtByte(op)[2:]
}

func s7plusFuncName(fn uint16) string {
	switch fn {
	case 0x04bb:
		return "Explore"
	case 0x04ca:
		return "CreateObject"
	case 0x04d4:
		return "DeleteObject"
	case 0x04f2:
		return "GetVarSubStreamed"
	case 0x0524:
		return "SetVariable"
	case 0x0554:
		return "SetMultiVariables"
	case 0x0556:
		return "SetVarSubStreamed"
	case 0x0560:
		return "GetMultiVariables"
	case 0x0586:
		return "GetVarSubStreamed2"
	case 0x0589:
		return "Invoke"
	}
	return "fn-0x" + fmtByteU16(fn)
}

func fmtByteU16(v uint16) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[v>>12&0xf], hex[v>>8&0xf], hex[v>>4&0xf], hex[v&0xf]})
}

// readTPKT reads one TPKT (RFC 1006) message and returns its COTP+payload
// body. Appends the raw bytes to res.Payload.
func readTPKT(conn net.Conn, res *Result) ([]byte, bool) {
	t := make([]byte, 4)
	if _, err := io.ReadFull(conn, t); err != nil {
		res.Meta["read_err"] = err.Error()
		return nil, false
	}
	if t[0] != 0x03 {
		res.Meta["non_tpkt_version"] = t[0]
		return nil, false
	}
	tlen := binary.BigEndian.Uint16(t[2:4])
	if tlen < 5 || tlen > 4096 {
		res.Meta["bad_tpkt_len"] = tlen
		return nil, false
	}
	body := make([]byte, int(tlen)-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta["read_err"] = err.Error()
		return nil, false
	}
	res.Payload = append(res.Payload, t...)
	res.Payload = append(res.Payload, body...)
	return body, true
}

func writeTPKT(conn net.Conn, body []byte) error {
	tpkt := []byte{0x03, 0x00, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(body)))
	_, err := conn.Write(append(tpkt, body...))
	return err
}

func safeAt(b []byte, i int) byte {
	if i < len(b) {
		return b[i]
	}
	return 0
}
