package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type s7 struct{}

func (s *s7) Name() string { return "s7" }

// Siemens S7comm runs on TPKT/COTP over TCP (port 102). The first thing
// any client does is a COTP Connection Request (CR). A real PLC answers
// with a Connection Confirm (CC). We answer with a CC and then read one
// more PDU (often the S7 setup-communication) so we capture what the
// scanner is looking for.
//
// TPKT (RFC 1006): version(1) | reserved(1) | length(2)
// COTP CR: length(1) | type=0xE0 | dst_ref(2) | src_ref(2) | class(1) | params...
// COTP CC: same shape with type=0xD0
func (s *s7) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	// Read TPKT header.
	t := make([]byte, 4)
	if _, err := io.ReadFull(conn, t); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if t[0] != 0x03 {
		res.Meta = map[string]any{"non_tpkt_version": t[0]}
		return res, nil
	}
	tlen := binary.BigEndian.Uint16(t[2:4])
	if tlen < 7 || tlen > 4096 {
		res.Meta = map[string]any{"bad_tpkt_len": tlen}
		return res, nil
	}
	body := make([]byte, int(tlen)-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(t, body...)

	// A real COTP CR carries at least 7 bytes (length, type, dst_ref(2),
	// src_ref(2), class(1)) — additional bytes are variable-length
	// parameters (TSAPs etc). We need at minimum 7 to slice body[7:]
	// for the parameter echo; without this tighter guard a body of
	// exactly 6 bytes (tlen=10) would panic at the slice on line below.
	if len(body) < 7 || body[1] != 0xE0 {
		res.Meta = map[string]any{"cotp_type": fmtByte(body[1])}
		return res, nil
	}
	// Mirror dst_ref/src_ref but flip them.
	dstRef := binary.BigEndian.Uint16(body[2:4])
	srcRef := binary.BigEndian.Uint16(body[4:6])
	res.Meta = map[string]any{
		"cotp_type": "CR",
		"dst_ref":   dstRef,
		"src_ref":   srcRef,
	}

	// Build a Connection Confirm (type 0xD0). Reuse the parameters by echoing
	// the variable-part bytes; that's usually fine for a fingerprint.
	params := body[7:]
	cc := make([]byte, 0, 11+len(params))
	cc = append(cc, byte(6+len(params))) // length
	cc = append(cc, 0xD0)                // type CC
	cc = binary.BigEndian.AppendUint16(cc, srcRef)
	cc = binary.BigEndian.AppendUint16(cc, dstRef)
	cc = append(cc, 0x00) // class 0
	cc = append(cc, params...)

	tpkt := []byte{0x03, 0x00, 0, 0}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(4+len(cc)))
	if _, err := conn.Write(append(tpkt, cc...)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "tpkt+cotp connection confirm"
	return res, nil
}

func fmtByte(b byte) string {
	const hex = "0123456789abcdef"
	return "0x" + string([]byte{hex[b>>4], hex[b&0x0f]})
}
