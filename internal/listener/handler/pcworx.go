package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// pcworx is a Phoenix Contact PCWorx responder on TCP 1962 — the engineering
// protocol of ILC-class PLCs (and the nmap pcworx-info probe). The ILC family
// runs ProConOS and exposes unauthenticated read/write of PLC variables and
// run-state control (CVE-2016-8367). We answer the identify handshake with a
// believable device-identification frame, then run a bounded session: each
// follow-up frame's opcode + in-clear tokens are classified as read / write /
// run-state / program-transfer / login, and the unauthenticated-access CVE is
// attributed when the attacker reaches a read/write/control service.
type pcworx struct{}

func (p *pcworx) Name() string { return "pcworx" }

func (p *pcworx) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}
	res.Payload = append([]byte(nil), buf[:n]...)
	res.Meta["pcworx_request_len"] = n
	flagAnomaly(&res, "ics-pcworx-probe")
	setIfEmpty(res.Meta, "intent", "PCWorx identify — Phoenix Contact ILC PLC fingerprinting")
	if n >= 2 {
		res.Meta["pcworx_opcode"] = fmtByteU16(binary.BigEndian.Uint16(buf[0:2]))
	}
	p.classify(buf[:n], &res)

	// Identification response: vendor / model / firmware / order-number /
	// firmware-date a scanner extracts (nmap pcworx-info).
	model, fw := "ILC 330 ETH", "3.95L"
	ident := "Phoenix Contact\x00" + model + "\x002700728\x00" + fw + "\x002016/03/14\x00"
	body := []byte(ident)
	resp := []byte{0x81, 0x00, byte(len(body) >> 8), byte(len(body))}
	resp = append(resp, body...)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.Meta["pcworx_model"] = model
	res.BannerSent = "pcworx ident"

	// Bounded follow-up session — a real engineering tool issues read/write/
	// control frames after identify.
	for i := 0; i < 6; i++ {
		m, _ := conn.Read(buf)
		if m <= 0 {
			break
		}
		res.Payload = append(res.Payload, buf[:m]...)
		p.classify(buf[:m], &res)
		_, _ = conn.Write([]byte{0x81, 0x00, 0x00, 0x00}) // generic ack
	}
	return res, nil
}

// classify maps a PCWorx frame's opcode + in-clear tokens to a service class.
func (p *pcworx) classify(frame []byte, res *Result) {
	low := strings.ToLower(asciiOnly(frame))
	control := false
	switch {
	case strings.Contains(low, "stop") || strings.Contains(low, "start") || strings.Contains(low, "reset") || strings.Contains(low, "coldstart"):
		flagAnomaly(res, "ics-plc-mode-change")
		res.Meta["intent"] = "PCWorx run-state change (start/stop/reset)"
		control = true
	case strings.Contains(low, "download") || strings.Contains(low, "upload") || strings.Contains(low, "boot") || strings.Contains(low, "program"):
		flagAnomaly(res, "ics-plc-program-access")
		res.Meta["intent"] = "PCWorx program transfer (download/upload PLC logic)"
		control = true
	case strings.Contains(low, "write") || strings.Contains(low, "force") || strings.Contains(low, "setvalue"):
		flagAnomaly(res, "ics-plc-write")
		res.Meta["intent"] = "PCWorx variable write/force (control manipulation)"
		control = true
	case strings.Contains(low, "read") || strings.Contains(low, "getvalue") || strings.Contains(low, "var"):
		flagAnomaly(res, "ics-process-data-access")
		setIfEmpty(res.Meta, "intent", "PCWorx variable read (process data)")
		control = true
	case strings.Contains(low, "login") || strings.Contains(low, "passw") || strings.Contains(low, "auth"):
		flagAnomaly(res, "ics-pcworx-login")
		setIfEmpty(res.Meta, "intent", "PCWorx login — ILC runtime authentication attempt")
		control = true
	}
	// The ILC exposes these without authentication (CVE-2016-8367).
	if control {
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2016-8367")
		flagAnomaly(res, "cve:CVE-2016-8367")
	}
}
