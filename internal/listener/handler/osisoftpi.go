package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// osisoftPI is an OSIsoft / AVEVA PI System responder on TCP 5450 — the port
// the PI Network Manager (pinetmgr) listens on for the PI Data Archive (the
// process-historian at the heart of most enterprise OT/IT convergence).
// PI clients (PI SDK / AF SDK / PI API, the PI Buffer Subsystem, PI
// Interfaces) open a connection here, negotiate a protocol version, and then
// authenticate via a PI Mapping (Windows identity), a PI Trust (host/app
// based), or an explicit PI identity before reading/writing tag (PI Point)
// time-series data.
//
// The PINet wire protocol is proprietary and undocumented, so this is a
// fingerprint-grade responder: it captures the client's opening message,
// answers with a believable PI Network Manager identification carrying a
// server version + name so a scanner records a live PI Data Archive, and
// flags the probe. Reaching a PI Data Archive is historian/process-data
// access (and a pivot from IT into OT), so the access is surfaced as such.
// No PI point database is served and nothing is read or written.
type osisoftPI struct{ id *identity.Identity }

func (p *osisoftPI) Name() string { return "osisoft_pi" }

func (p *osisoftPI) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		// Some PI clients expect the server to greet first; a bare connect is a
		// scanner. Send the identification banner anyway and record the probe.
		res.Meta["read_err"] = "no data"
	} else {
		req := buf[:n]
		res.Payload = append([]byte(nil), req...)
		res.Meta["pi_request_len"] = n
		classifyHistorianOp(&res, req, "OSIsoft/AVEVA PI Data Archive")
	}
	flagAnomaly(&res, "ics-historian-access")
	flagAnomaly(&res, "ics-field-device-probe")
	setIfEmpty(res.Meta, "intent", "OSIsoft/AVEVA PI Data Archive access — process-historian connection (IT→OT pivot / data exfil)")

	// A believable PI Network Manager identification: a short header followed
	// by the ASCII server name + version a scanner greps for. Real PI servers
	// report a build like "PI Data Archive 3.4.445.688" (PI Server 2018+).
	serverName := "PISRV01"
	if p.id != nil {
		serverName = "PI-" + p.id.HostName()
	}
	version := "PI Data Archive 3.4.445.688"
	res.Meta["pi_server"] = serverName
	res.Meta["pi_version"] = version
	body := []byte(version + "\x00" + serverName + "\x00")
	// PINet-shaped framing: a 4-byte header (message class/type + length) then
	// the identification body.
	resp := []byte{0x50, 0x49, byte(len(body) >> 8), byte(len(body))} // "PI" + len
	resp = append(resp, body...)
	if _, err := conn.Write(resp); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "osisoft pi netmgr ident"
	return res, nil
}
