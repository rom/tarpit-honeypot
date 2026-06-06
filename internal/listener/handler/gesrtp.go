package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// geSRTP is a minimal GE-SRTP (GE Fanuc Service Request Transfer
// Protocol) responder on TCP 18245 — the management protocol of GE /
// Emerson PACSystems + Series 90 PLCs. SRTP messages are 56-byte
// fixed-length records; the first request a client sends is typically a
// session/"return controller type and ID" request. We capture the
// request and reply with a believable 56-byte response carrying a
// success status so a scanner records a live GE PLC. This is a
// fingerprint-grade responder, not a full SRTP stack.
type geSRTP struct{}

func (g *geSRTP) Name() string { return "ge_srtp" }

func (g *geSRTP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	req := make([]byte, 64)
	n, _ := conn.Read(req)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	req = req[:n]
	res.Payload = append([]byte(nil), req...)
	res.Meta["srtp_request_type"] = fmtByte(req[0])

	// A 56-byte SRTP response: byte 0 = message type 0x03 (response),
	// a success status in the status fields, the rest zero-padded. Real
	// PACSystems embed the controller model further in; this is enough to
	// look like a live outstation to a banner-grab scanner.
	resp := make([]byte, 56)
	resp[0] = 0x03  // response
	resp[2] = 0x01  // sequence-ish
	resp[31] = 0x01 // status: success
	resp[42] = 0x94 // a plausible PLC type byte (Series 90-30 family)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "ge-srtp response"
	flagAnomaly(&res, "ics-ge-srtp-probe")
	res.Meta["intent"] = "GE-SRTP service request — GE/Emerson PACSystems PLC access / fingerprint"
	return res, nil
}
