package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// pcworx is a Phoenix Contact PCWorx responder on TCP 1962 — the
// engineering protocol of ILC-class PLCs (and the nmap pcworx-info probe).
// The client opens with a connect/identify request; a real controller
// replies with a frame carrying its model + firmware strings, which is what
// recon tools grep for. We answer the first request with a believable
// identification frame and capture the probe. Fingerprint-grade — no PLC
// program access.
type pcworx struct{}

func (p *pcworx) Name() string { return "pcworx" }

func (p *pcworx) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	res.Payload = append([]byte(nil), buf[:n]...)
	res.Meta["pcworx_request_len"] = n
	flagAnomaly(&res, "ics-pcworx-probe")

	// Identification response: a PCWorx-shaped frame whose payload carries
	// the ASCII model + firmware a scanner extracts.
	model := "ILC 330 ETH"
	fw := "3.95L"
	body := append([]byte(model+"\x00"), []byte(fw+"\x00")...)
	resp := make([]byte, 0, 4+len(body))
	resp = append(resp, 0x81, 0x00) // response opcode
	resp = append(resp, byte(len(body)>>8), byte(len(body)))
	resp = append(resp, body...)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.Meta["pcworx_model"] = model
	res.BannerSent = "pcworx ident"
	return res, nil
}
