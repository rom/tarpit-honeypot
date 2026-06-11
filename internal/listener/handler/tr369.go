package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// tr369 emulates a TR-369 / USP (User Services Platform) agent endpoint — the
// successor to TR-069. USP carries protobuf-encoded Records/Messages over a
// Message Transfer Protocol (MTP); the standardized internet-facing MTP is
// WebSocket, negotiated with the "v1.usp" subprotocol (TR-369 / TR-469). A
// reachable USP agent lets a controller read and write the whole device data
// model (Device.) and invoke operations (Reboot, FactoryReset, firmware
// Download) — TR-069's power with a modern transport.
//
// We recognize both shapes a probe arrives in: the USP WebSocket upgrade
// (which we complete as the decoy, echoing v1.usp) and a raw USP Record
// protobuf (whose endpoint IDs — proto::/os::/self:: — and version we
// scavenge). We never act on a USP message; we attribute the intent, the MTP,
// the controller/agent endpoint IDs, and the CWE for an unauthenticated /
// cleartext USP MTP exposure.
type tr369 struct{}

func (t *tr369) Name() string { return "tr369" }

func (t *tr369) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	res.Meta["protocol_name"] = "TR-369 USP"

	br := bufio.NewReader(conn)
	// Read the leading bytes: stop at the HTTP header terminator for an HTTP /
	// WebSocket upgrade, else read up to the cap for a binary USP Record.
	var raw []byte
	for len(raw) < capN {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		raw = append(raw, b)
		if bytes.HasSuffix(raw, []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = raw
	if len(raw) == 0 {
		res.Meta["read_err"] = "no data"
		return res, nil
	}

	if looksHTTP(raw) {
		t.handleHTTP(conn, br, &res, parseHTTPHead(raw))
		return res, nil
	}

	// Raw USP Record protobuf over a non-WebSocket MTP (e.g. STOMP/CoAP/MQTT
	// payload landing on this port). Scavenge the endpoint IDs + version.
	t.handleBinary(&res, raw)
	return res, nil
}

// handleHTTP handles the HTTP-framed cases: the USP WebSocket upgrade (v1.usp)
// and any plain HTTP MTP POST carrying a USP message.
func (t *tr369) handleHTTP(conn net.Conn, br *bufio.Reader, res *Result, h httpHead) {
	res.Meta["request_line"] = safe.SanitizeForLog(strings.TrimSpace(h.Method + " " + h.URI + " " + h.Proto))
	if h.URI != "" {
		res.Meta["http_uri"] = safe.SanitizeForLog(clipStr(h.URI, 256))
	}
	if ua := h.header("user-agent"); ua != "" {
		res.Meta["user_agent"] = safe.SanitizeForLog(clipStr(ua, 256))
	}

	wsKey := h.header("sec-websocket-key")
	subproto := h.header("sec-websocket-protocol")
	upgrade := strings.ToLower(h.header("upgrade"))

	switch {
	case wsKey != "" && upgrade == "websocket":
		res.Meta["usp_mtp"] = "websocket"
		if subproto != "" {
			res.Meta["ws_subprotocol"] = safe.SanitizeForLog(clipStr(subproto, 96))
		}
		flagAnomaly(res, "usp-agent-access")
		flagAnomaly(res, "usp-websocket-mtp")
		// Plaintext WebSocket MTP: USP mandates TLS on the internet-facing MTP.
		flagAnomaly(res, "usp-cleartext-mtp")
		noteCWE(res, "CWE-319", "CWE-306") // cleartext transmission; missing authentication
		intent := "TR-369 USP controller session over WebSocket"
		if uspSubproto(subproto) {
			intent = "TR-369 USP controller session over WebSocket (v1.usp) — remote device-model management"
		}
		res.Meta["intent"] = intent
		t.completeWebSocket(conn, br, res, h, subproto)
	case h.Method == "POST" && (strings.Contains(strings.ToLower(h.header("content-type")), "usp") || uspBytes(h.Body)):
		res.Meta["usp_mtp"] = "http"
		flagAnomaly(res, "usp-agent-access")
		flagAnomaly(res, "usp-cleartext-mtp")
		noteCWE(res, "CWE-319", "CWE-306")
		captureUSP(res, h.Body)
		res.Meta["intent"] = "TR-369 USP message to the agent over an HTTP MTP — remote device management"
		writeConn(conn, res, cpeHTTPResp("200 OK", "uspd/1.0", "application/vnd.bbf.usp.msg", ""))
		res.BannerSent = "tr369 usp http 200"
	default:
		// HTTP probe that isn't a USP upgrade — answer like a USP agent that
		// requires the WebSocket upgrade, so a scanner classifies the port.
		flagAnomaly(res, "usp-agent-access")
		res.Meta["intent"] = "TR-369 USP agent probe — endpoint requires the v1.usp WebSocket MTP"
		writeConn(conn, res, cpeHTTPResp("426 Upgrade Required", "uspd/1.0", "text/plain", "USP agent: WebSocket MTP required",
			`Sec-WebSocket-Protocol: v1.usp`))
		res.BannerSent = "tr369 426"
	}
}

// completeWebSocket finishes the RFC 6455 handshake (echoing the v1.usp
// subprotocol) so a real USP controller believes it connected — the decoy.
func (t *tr369) completeWebSocket(conn net.Conn, br *bufio.Reader, res *Result, h httpHead, subproto string) {
	accept := wsAcceptKey(h.header("sec-websocket-key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if subproto != "" {
		resp += "Sec-WebSocket-Protocol: " + safe.SanitizeHeader(strings.TrimSpace(strings.Split(subproto, ",")[0])) + "\r\n"
	}
	resp += "\r\n"
	writeConn(conn, res, resp)
	res.BannerSent = "tr369 usp websocket 101"
	// Capture a USP Record frame if the controller sends one (reusing the same
	// buffered reader so any bytes that arrived with the upgrade aren't lost).
	if payload, _, ok := readWSFrame(br, 8192); ok && len(payload) > 0 {
		captureUSP(res, payload)
	}
}

// handleBinary processes a raw USP Record protobuf delivered without an HTTP
// frame (STOMP/CoAP/MQTT MTP payloads).
func (t *tr369) handleBinary(res *Result, raw []byte) {
	res.Meta["usp_mtp"] = "binary"
	flagAnomaly(res, "usp-agent-access")
	flagAnomaly(res, "usp-cleartext-mtp")
	noteCWE(res, "CWE-319", "CWE-306")
	captureUSP(res, raw)
	res.Meta["intent"] = "TR-369 USP Record to the agent — remote device management (USP)"
}

// captureUSP scavenges the USP endpoint IDs (proto::/os::/self::/doc::) and any
// USP version string from a record/message payload (protobuf or text).
func captureUSP(res *Result, data []byte) {
	if eps := uspEndpointIDs(data); len(eps) > 0 {
		res.Meta["usp_endpoints"] = eps
	}
	if v := uspVersion(data); v != "" {
		res.Meta["usp_version"] = v
	}
}

// uspSubproto reports whether a Sec-WebSocket-Protocol value offers the USP
// subprotocol (v1.usp per TR-469).
func uspSubproto(sp string) bool { return strings.Contains(strings.ToLower(sp), "usp") }

// uspBytes reports whether a body looks like a USP Record protobuf: it carries
// a USP endpoint-id token (type::instance) or the USP record version field.
func uspBytes(data []byte) bool {
	return len(uspEndpointIDs(data)) > 0 || uspVersion(data) != ""
}

// uspEndpointIDs extracts USP endpoint identifiers — printable tokens of the
// form "<type>::<instance>" (proto::, os::, self::, doc::) — from a record's
// bytes. Bounded and dedup'd.
func uspEndpointIDs(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(string(data), func(r rune) bool {
		return r < 0x20 || r >= 0x7f || r == '"' || r == '\''
	}) {
		if !strings.Contains(tok, "::") || len(tok) < 5 || len(tok) > 128 {
			continue
		}
		if !uspEndpointPrefix(tok) || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func uspEndpointPrefix(tok string) bool {
	for _, p := range []string{"proto::", "os::", "self::", "doc::", "cpe::", "usp::"} {
		if strings.HasPrefix(strings.ToLower(tok), p) {
			return true
		}
	}
	return false
}

// uspVersion returns the USP record version ("1.x") when the literal appears in
// the bytes near the start of the record (field 1 of a USP Record), else "".
func uspVersion(data []byte) string {
	for _, v := range []string{"1.0", "1.1", "1.2", "1.3", "1.4"} {
		if bytes.Contains(data, []byte("\x03"+v)) || bytes.Contains(data, []byte("USP/"+v)) {
			return v
		}
	}
	return ""
}
