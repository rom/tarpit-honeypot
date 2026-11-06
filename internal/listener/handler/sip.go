package handler

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// sip is a UDP SIP receiver (port 5060). SIP is text-based — request
// lines look like `OPTIONS sip:1000@1.2.3.4 SIP/2.0`. Common scanner
// behavior: send OPTIONS, REGISTER, or INVITE to enumerate extensions.
// We capture the method + From + To + User-Agent and reply with
// 200 OK so the scanner's enumeration loop is misled.
type sipUDP struct{}

func (s *sipUDP) Name() string { return "sip" }

func (s *sipUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) < 1 {
		return res, nil
	}
	reqLine := lines[0]
	parts := strings.Fields(reqLine)
	if len(parts) < 3 {
		res.Meta["non_sip"] = true
		return res, nil
	}
	method := strings.ToUpper(parts[0])
	res.Meta["method"] = method
	res.Meta["request_line"] = reqLine
	via := ""
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "from:"):
			res.Meta["from"] = strings.TrimSpace(line[5:])
		case strings.HasPrefix(lower, "to:"):
			res.Meta["to"] = strings.TrimSpace(line[3:])
		case strings.HasPrefix(lower, "call-id:"):
			res.Meta["call_id"] = strings.TrimSpace(line[8:])
		case strings.HasPrefix(lower, "user-agent:"):
			res.Meta["user_agent"] = strings.TrimSpace(line[11:])
		case strings.HasPrefix(lower, "authorization:"):
			res.Meta["authorization"] = strings.TrimSpace(line[14:])
		case strings.HasPrefix(lower, "via:"):
			via = strings.TrimSpace(line[4:])
			res.Meta["via"] = via
		case strings.HasPrefix(lower, "cseq:"):
			res.Meta["cseq"] = strings.TrimSpace(line[5:])
		}
	}
	// Identify SIP scanners by their User-Agent (sipvicious / friendly-scanner
	// / sipcli are the dominant PBX-enumeration tools).
	if ua := strings.ToLower(valueOr(res.Meta, "user_agent", "")); ua != "" {
		if strings.Contains(ua, "friendly-scanner") || strings.Contains(ua, "sipvicious") ||
			strings.Contains(ua, "sipcli") || strings.Contains(ua, "sip-scan") {
			flagAnomaly(&res, "tool:sipvicious")
		}
	}
	// OPTIONS with no dialog is the classic PBX liveness / enumeration sweep.
	if method == "OPTIONS" {
		flagAnomaly(&res, "sip-options-scan")
	}
	// Capture the digest username from an Authorization header — the credential
	// the brute-force loop replays after our 401 challenge (surfaced as a
	// captured credential via extractCreds' sip_user key).
	if auth := valueOr(res.Meta, "authorization", ""); auth != "" {
		if u := sipAuthUser(auth); u != "" {
			res.Meta["sip_user"] = u
			flagAnomaly(&res, "sip-auth-attempt")
		}
	}

	// Method-aware reply. SECURITY: every echoed value is attacker-controlled
	// (SIP headers from the request). Without SanitizeHeader, CRLF in any of
	// them lets an off-path attacker (UDP source-IP-spoofable) inject
	// arbitrary SIP/HTTP-shaped headers and even a body into a packet sent to
	// any IP they choose — a reflection / amplification primitive against a
	// third party. SanitizeHeader strips CR/LF/NUL.
	sVia := safe.SanitizeHeader(via)
	sFrom := safe.SanitizeHeader(valueOr(res.Meta, "from", ""))
	sTo := safe.SanitizeHeader(valueOr(res.Meta, "to", ""))
	sCallID := safe.SanitizeHeader(valueOr(res.Meta, "call_id", ""))
	sCSeq := safe.SanitizeHeader(valueOr(res.Meta, "cseq", ""))

	status, extra := "200 OK", ""
	switch method {
	case "REGISTER", "INVITE", "SUBSCRIBE":
		// Real PBXs challenge these — reply 401 with a Digest nonce so the
		// scanner's enumeration/brute loop sends credentials next (captured
		// from the follow-up Authorization header).
		status = "401 Unauthorized"
		extra = "WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"" + sipNonce(sCallID) + "\", algorithm=MD5\r\n"
		if method == "REGISTER" {
			flagAnomaly(&res, "sip-register-probe")
		}
		if method == "INVITE" {
			flagAnomaly(&res, "sip-invite-attempt") // toll-fraud / call-spam primitive
		}
	}
	reply := fmt.Sprintf("SIP/2.0 %s\r\n"+
		"Via: %s\r\n"+
		"From: %s\r\n"+
		"To: %s;tag=as%x\r\n"+
		"Call-ID: %s\r\n"+
		"CSeq: %s\r\n"+
		"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY\r\n"+
		"%s"+
		"Server: Asterisk PBX 16.16.2\r\n"+
		"Content-Length: 0\r\n\r\n",
		status, sVia, sFrom, sTo, len(payload), sCallID, sCSeq, extra)
	if _, err := pc.WriteTo([]byte(reply), src); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "sip " + status
	_ = cfg
	return res, nil
}

// sipAuthUser extracts the username from a SIP Digest Authorization header
// (username="alice"); "" if not present.
func sipAuthUser(auth string) string {
	// Length-preserving case-insensitive search (asciiIndexFold): indexing a
	// strings.ToLower copy and slicing the original auth can panic, because
	// ToLower is not length-preserving.
	i := asciiIndexFold(auth, "username=")
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(auth[i+len("username="):])
	v = strings.TrimPrefix(v, "\"")
	if j := strings.IndexAny(v, "\","); j >= 0 {
		v = v[:j]
	}
	return v
}

// sipNonce derives a stable-looking Digest nonce from the request's Call-ID
// (already sanitized) so each challenge differs without leaking anything.
func sipNonce(seed string) string {
	const hexd = "0123456789abcdef"
	h := uint32(0x811c9dc5)
	for i := 0; i < len(seed); i++ {
		h = (h ^ uint32(seed[i])) * 0x01000193
	}
	if seed == "" {
		h = 0xdeadbeef
	}
	out := make([]byte, 16)
	for i := range out {
		out[i] = hexd[(h>>(uint(i%8)*4))&0x0f]
		if i%4 == 3 {
			h *= 0x01000193
		}
	}
	return string(out)
}

func valueOr(m map[string]any, k, def string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}
