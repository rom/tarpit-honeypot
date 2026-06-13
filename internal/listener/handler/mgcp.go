package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// mgcp emulates a Media Gateway Control Protocol gateway (MGCP, UDP 2427; the
// call-agent side listens on 2727). MGCP gateways are a VoIP toll-fraud /
// call-control target alongside SIP: a scanner audits endpoints (AUEP) to
// enumerate the gateway, then opens media connections (CRCX) to place
// fraudulent calls. We parse the request line (verb, transaction-id, endpoint),
// classify the intent, and answer with a believable MGCP response so the
// gateway looks live — sanitized, bounded, and rate-limited so it can't be
// abused as a reflector.
type mgcp struct{ lim *udpReflectLimiter }

func (m *mgcp) Name() string { return "mgcp" }

func (m *mgcp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}

	firstLine := string(payload)
	if i := strings.IndexAny(firstLine, "\r\n"); i >= 0 {
		firstLine = firstLine[:i]
	}
	// Request line: <verb> <transaction-id> <endpoint> MGCP <version>
	parts := strings.Fields(firstLine)
	if len(parts) < 5 || !strings.EqualFold(parts[3], "MGCP") {
		res.Meta["non_mgcp"] = true
		return res, nil
	}
	verb := strings.ToUpper(parts[0])
	txid := parts[1]
	res.Meta["mgcp_verb"] = verb
	res.Meta["mgcp_command"] = mgcpVerbName(verb)
	res.Meta["mgcp_transaction"] = safe.SanitizeForLog(txid)
	res.Meta["mgcp_endpoint"] = safe.SanitizeForLog(parts[2])
	res.Meta["mgcp_version"] = safe.SanitizeForLog(parts[4])
	flagAnomaly(&res, "mgcp-probe")

	code, text, extra := "200", "OK", ""
	switch verb {
	case "CRCX": // CreateConnection — establishes media (toll-fraud / call setup)
		flagAnomaly(&res, "mgcp-create-connection")
		res.Meta["intent"] = "MGCP CreateConnection — establishing a media connection (toll-fraud / call-setup)"
		ip := mgcpLocalIP(pc)
		extra = "I: " + fmt.Sprintf("%08X", mgcpHash(txid)) + "\r\n\r\n" +
			"v=0\r\no=- 25678 753849 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip +
			"\r\nt=0 0\r\nm=audio 16386 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
	case "MDCX":
		flagAnomaly(&res, "mgcp-modify-connection")
		res.Meta["intent"] = "MGCP ModifyConnection — modifying a media connection"
	case "DLCX":
		flagAnomaly(&res, "mgcp-delete-connection")
		res.Meta["intent"] = "MGCP DeleteConnection — tearing down a media connection"
		code, text = "250", "Connection was deleted"
	case "AUEP": // AuditEndpoint — endpoint / capability enumeration (recon)
		flagAnomaly(&res, "mgcp-audit")
		res.Meta["intent"] = "MGCP AuditEndpoint — enumerating gateway endpoints/capabilities (recon)"
		extra = "A: a:PCMU;a:PCMA;a:G729\r\nM: sendonly;recvonly;sendrecv;inactive\r\n"
	case "AUCX":
		flagAnomaly(&res, "mgcp-audit")
		res.Meta["intent"] = "MGCP AuditConnection — auditing a media connection (recon)"
	case "RQNT":
		setIfEmpty(res.Meta, "intent", "MGCP NotificationRequest — arming endpoint event detection")
	case "RSIP":
		flagAnomaly(&res, "mgcp-restart")
		res.Meta["intent"] = "MGCP RestartInProgress — gateway restart signaling"
	default:
		setIfEmpty(res.Meta, "intent", "MGCP "+mgcpVerbName(verb)+" command")
	}

	// Every echoed value is attacker-controlled and source-spoofable over UDP,
	// so sanitize (strip CR/LF/NUL) to deny CRLF-injection reflection, bound the
	// size, and rate-limit so this can't be used as an amplifier.
	reply := code + " " + safe.SanitizeHeader(txid) + " " + text + "\r\n" + extra
	if len(reply) > 1200 {
		reply = reply[:1200]
	}
	if m.lim.allow() {
		if _, err := pc.WriteTo([]byte(reply), src); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = "mgcp " + code
	}
	_ = cfg
	return res, nil
}

func mgcpHash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

func mgcpLocalIP(pc net.PacketConn) string {
	if pc != nil {
		if a, ok := pc.LocalAddr().(*net.UDPAddr); ok && a.IP != nil && !a.IP.IsUnspecified() {
			return a.IP.String()
		}
	}
	return "10.0.0.1"
}

func mgcpVerbName(v string) string {
	switch v {
	case "CRCX":
		return "CreateConnection"
	case "MDCX":
		return "ModifyConnection"
	case "DLCX":
		return "DeleteConnection"
	case "RQNT":
		return "NotificationRequest"
	case "NTFY":
		return "Notify"
	case "AUEP":
		return "AuditEndpoint"
	case "AUCX":
		return "AuditConnection"
	case "RSIP":
		return "RestartInProgress"
	case "EPCF":
		return "EndpointConfiguration"
	}
	return v
}
