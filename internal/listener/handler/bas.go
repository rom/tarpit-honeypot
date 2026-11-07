package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Building-automation / BMS protocol decoys beyond the BACnet / KNX / LonTalk /
// Fox / C-Bus / Crestron / AMX / Vantage / Loxone / M-Bus / DLMS / OSDP set.
// Each answers just enough to look like a live building controller, captures
// the request + intent, and flags the probe. Nothing is ever controlled.

// --- Tridium Niagara platform daemon (niagarad, TCP 3011 / TLS 5011) --------
//
// The Niagara Framework (Tridium, a Honeywell company) runs much of the world's
// commercial building automation. Beside the Fox application protocol (1911 /
// 4911, handler `fox`) each JACE/Supervisor exposes the *platform* daemon —
// station install, backup, file transfer, user + TLS-cert management — on
// 3011 (plaintext) / 5011 (TLS). It is a high-value target (CVE-2012-4701 and
// the BlueFrost Niagara chain), so any reach at it is strong BAS recon.
type niagaraPlatform struct{}

func (n *niagaraPlatform) Name() string { return "niagara_platform" }

func (n *niagaraPlatform) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 8192)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "niagara-platform-probe")
	setIfEmpty(res.Meta, "intent", "Tridium Niagara platform daemon access — BAS supervisor (station/backup/cert management; CVE-2012-4701 chain)")
	res.Meta["bas_product"] = "Tridium Niagara"
	if len(got) > 0 {
		s := strings.ToLower(string(got))
		res.Meta["niagara_request"] = safe.SanitizeForLog(clipStr(string(got), 256))
		switch {
		case strings.HasPrefix(s, "fox "), strings.Contains(s, "fox hello"):
			res.Meta["niagara_phase"] = "fox-hello"
		case strings.Contains(s, "baja") || strings.Contains(s, "niagara"):
			res.Meta["niagara_phase"] = "platform-hello"
		}
		noteCWE(&res, "CWE-306") // missing authentication for a critical function
	}
	// The platform daemon answers a connection with a fox-style hello line.
	banner := "fox a 1 -1 fox hello\n{\nfox.version=s:1.0.1\nid=i:1\nhostName=s:jace-8000\nhostId=s:Qnx-NPM6E-0000-1A2B-3C4D\nvmName=s:Oracle Corporation Java HotSpot(TM) Client VM\nvmVersion=s:25.202-b08\nosName=s:qnx\nstation.name=s:BuildingSupervisor\n};;\n"
	_, _ = conn.Write([]byte(banner))
	res.BannerSent = "niagara-fox-hello"
	return res, nil
}

// --- oBIX (Open Building Information eXchange, HTTP/XML) ---------------------
//
// oBIX is the OASIS RESTful-XML standard that sits above BACnet/LonWorks and
// exposes a supervisor's whole building model (points, histories, alarms,
// schedules) over HTTP — so one oBIX endpoint is a read/write window onto the
// entire BAS. Commonly reachable at /obix/ on a BAS web server. We answer a
// believable oBIX lobby so a scanner keeps enumerating, and flag writes
// (<real .../> / <bool val=.../> back to a point) as control attempts.
type obix struct{}

func (o *obix) Name() string { return "obix" }

func (o *obix) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 16384)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "obix-probe")
	res.Meta["bas_product"] = "oBIX building web-services"
	setIfEmpty(res.Meta, "intent", "oBIX building web-services access — read/write the BAS point/alarm/schedule model")
	req := string(got)
	line := req
	if i := strings.IndexAny(req, "\r\n"); i >= 0 {
		line = req[:i]
	}
	if line != "" {
		res.Meta["http_request"] = safe.SanitizeForLog(clipStr(line, 256))
	}
	method := strings.ToUpper(extractMethod(line))
	lower := strings.ToLower(req)
	switch {
	case method == "PUT" || method == "POST":
		flagAnomaly(&res, "bas-point-write")
		res.Meta["intent"] = "oBIX point write (" + method + ") — attempting to change a building setpoint/output"
		noteCWE(&res, "CWE-306")
	case strings.Contains(lower, "/obix/watchservice") || strings.Contains(lower, "watch"):
		res.Meta["obix_op"] = "watch" // subscribe to live point changes
	case strings.Contains(lower, "/obix/histories") || strings.Contains(lower, "history"):
		res.Meta["obix_op"] = "history-query"
	}
	// Minimal oBIX lobby document.
	body := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<obj href="/obix/" is="obix:Lobby"><ref name="about" href="about/"/>` +
		`<op name="batch" href="batch/"/><ref name="watchService" href="watchService/"/>` +
		`<ref name="histories" href="histories/"/></obj>`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=UTF-8\r\nServer: Niagara Web Server/4.10\r\nContent-Length: " +
		itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	_, _ = conn.Write([]byte(resp))
	res.BannerSent = "obix-lobby"
	return res, nil
}

// --- EnOcean ESP3 (serial-over-IP gateway) ----------------------------------
//
// EnOcean is the batteryless-wireless protocol under a great many building
// sensors/switches; EnOcean-to-IP gateways bridge the serial ESP3 framing over
// TCP so a BMS can reach the radio network remotely. ESP3 frames are
// 0x55 <dataLen:2> <optLen:1> <type:1> <crc8h> <data> <optdata> <crc8d>; packet
// type 5 is COMMON_COMMAND (e.g. CO_WR_* writes to the gateway/devices). We
// parse the header, classify read vs command, and flag the probe.
type enocean struct{}

func (e *enocean) Name() string { return "enocean" }

func (e *enocean) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	buf := make([]byte, 4096)
	got := readCapped(conn, cfg, buf)
	res.Payload = got
	flagAnomaly(&res, "enocean-probe")
	res.Meta["bas_product"] = "EnOcean ESP3 gateway"
	setIfEmpty(res.Meta, "intent", "EnOcean ESP3 gateway access — wireless building sensors/actuators over serial-to-IP")
	// ESP3 header: 0x55 | dataLen(2) | optLen(1) | packetType(1) | crc8h(1).
	if len(got) >= 6 && got[0] == 0x55 {
		res.Meta["esp3_framed"] = true
		ptype := got[4]
		res.Meta["esp3_packet_type"] = enoceanPacketType(ptype)
		switch ptype {
		case 0x05: // COMMON_COMMAND — gateway config / device writes
			flagAnomaly(&res, "bas-point-write")
			res.Meta["intent"] = "EnOcean COMMON_COMMAND — writing gateway/device configuration (control)"
			noteCWE(&res, "CWE-306")
		case 0x07: // REMOTE_MAN_COMMAND — remote management
			flagAnomaly(&res, "bas-point-write")
			res.Meta["intent"] = "EnOcean remote-management command"
		}
	} else if len(got) > 0 {
		res.Meta["esp3_framed"] = false
	}
	// ESP3 CO_RD_VERSION-style response (type 2 RESPONSE, return code 0 OK).
	resp := []byte{0x55, 0x00, 0x05, 0x01, 0x02, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00}
	_, _ = conn.Write(resp)
	res.BannerSent = "esp3-response"
	return res, nil
}

func enoceanPacketType(t byte) string {
	switch t {
	case 0x01:
		return "RADIO_ERP1"
	case 0x02:
		return "RESPONSE"
	case 0x03:
		return "RADIO_SUB_TEL"
	case 0x04:
		return "EVENT"
	case 0x05:
		return "COMMON_COMMAND"
	case 0x06:
		return "SMART_ACK_COMMAND"
	case 0x07:
		return "REMOTE_MAN_COMMAND"
	case 0x0A:
		return "RADIO_ERP2"
	}
	return "unknown"
}
