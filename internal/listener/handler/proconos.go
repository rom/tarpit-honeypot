package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// proconos is a ProConOS / ProConOS eCLR responder on TCP 20547 — the
// soft-PLC runtime from KW-Software (Phoenix Contact) that executes the IEC
// 61131 logic engineered in PCWorx / MULTIPROG, embedded in ILC / RFC
// controllers and many OEM PLCs. The runtime's control protocol has no
// authentication (ICS-ALERT-13-016: ProConOS exposes start/stop and program
// download to anyone who can reach the port), so a reachable ProConOS port
// is a direct logic-manipulation surface.
//
// We capture the first request, classify the runtime service it requests
// from its opcode, flag the start/stop/download operations as control
// manipulation, and answer with a short believable acknowledgement so a
// scanner records a live ProConOS runtime. Fingerprint-grade — no logic
// engine, nothing is ever executed.
type proconos struct{}

func (p *proconos) Name() string { return "proconos" }

func (p *proconos) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	req := buf[:n]
	res.Payload = append([]byte(nil), req...)
	res.Meta["proconos_request_len"] = n
	flagAnomaly(&res, "ics-plc-program-access")
	setIfEmpty(res.Meta, "intent", "ProConOS runtime probe — soft-PLC logic engine access")

	// The ProConOS protocol carries a service/opcode in the first payload
	// bytes. We classify the well-known runtime operations conservatively by
	// opcode byte and flag the ones that alter the running program.
	if n >= 2 {
		op := req[1]
		res.Meta["proconos_opcode"] = fmtByte(op)
		switch op {
		case 0x02, 0x03: // start / cold-start the PLC program
			flagAnomaly(&res, "ics-plc-mode-change")
			res.Meta["intent"] = "ProConOS START — starting PLC logic execution"
		case 0x04, 0x05: // stop / reset the PLC
			flagAnomaly(&res, "ics-plc-mode-change")
			res.Meta["intent"] = "ProConOS STOP — halting PLC logic (denial of control)"
		case 0x06, 0x07, 0x08: // download / write project (logic)
			flagAnomaly(&res, "ics-plc-write")
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2022-31801")
			flagAnomaly(&res, "cve:CVE-2022-31801")
			res.Meta["intent"] = "ProConOS DOWNLOAD — unauthenticated PLC logic upload / RCE (OT:ICEFALL CVE-2022-31801)"
		}
	}

	// ProConOS-shaped acknowledgement: a short header echoing a success status.
	resp := []byte{0x50, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // "PS" + status ok
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "proconos ack"
	return res, nil
}
