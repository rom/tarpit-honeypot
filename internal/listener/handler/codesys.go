package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// codesys is a minimal CODESYS responder on TCP 1217 (the CODESYS V3
// gateway / runtime control port used across many soft-PLC vendors —
// WAGO, Beckhoff, Schneider, ABB, …). The CODESYS block-driver protocol
// is proprietary + layered; this is a fingerprint-grade responder: it
// captures the first request and returns a short, believable
// acknowledgement so a scanner records a live CODESYS runtime, and flags
// the probe. It does not implement the full block-driver session.
type codesys struct{}

func (c *codesys) Name() string { return "codesys" }

func (c *codesys) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	res.Payload = append([]byte(nil), buf[:n]...)
	res.Meta["bytes"] = n

	// CODESYS V3 block-driver frames begin with a 0xC5/0xC9-class magic;
	// echo a minimal channel-open acknowledgement (header + zero status).
	resp := []byte{0xC5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "codesys ack"
	flagAnomaly(&res, "ics-codesys-probe")
	return res, nil
}
