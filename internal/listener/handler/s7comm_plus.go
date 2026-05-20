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
	case 0x32:
		res.Meta["s7_protocol"] = "S7comm"
	default:
		res.Meta["s7_protocol"] = "unknown"
	}
	return res, nil
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
