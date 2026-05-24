package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Round-six VoIP / telephony decoys: SIP over TCP, the Cisco SCCP (Skinny)
// phone protocol, H.225/H.323 call signalling, the Asterisk Manager Interface,
// and IAX2 (UDP). Exposed telephony is monetized through toll fraud (premium /
// international call origination) and PBX takeover, so each captures the
// high-signal markers — the dialed number on an INVITE, the credentials on an
// AMI login — and answers just enough to look like a live PBX.

// --- SIP over TCP (5060/5061) --------------------------------------------
//
// SIP carries call setup. We parse the request line + key headers, capture the
// REGISTER credentials (extension brute) and the INVITE destination (the
// dialed number that reveals toll fraud), and answer a 401 so the scanner sees
// a live, auth-required SIP service.
type sipTCP struct{}

func (h *sipTCP) Name() string { return "sip_tcp" }

func sipHeader(lines []string, name string) string {
	for _, l := range lines {
		if i := strings.IndexByte(l, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(l[:i]), name) {
			return sipClean(strings.TrimSpace(l[i+1:]))
		}
	}
	return ""
}

// sipClean strips CR/LF (defence against header injection on the echoed
// response) and bounds the length.
func sipClean(s string) string {
	s = strings.NewReplacer("\r", "", "\n", "").Replace(s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

func sipUser(hdr string) string {
	if i := strings.Index(hdr, "sip:"); i >= 0 {
		rest := hdr[i+4:]
		if j := strings.IndexAny(rest, "@>;? "); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

func (h *sipTCP) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 4096))
	res.Payload = got
	flagAnomaly(&res, "sip-scan")
	lines := strings.Split(string(got), "\n")
	parts := strings.Fields(strings.TrimRight(lines[0], "\r"))
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "SIP/") {
		return res, nil
	}
	method := strings.ToUpper(parts[0])
	res.Meta["sip_method"] = method
	via, from, to := sipHeader(lines, "via"), sipHeader(lines, "from"), sipHeader(lines, "to")
	callid, cseq := sipHeader(lines, "call-id"), sipHeader(lines, "cseq")
	if ua := sipHeader(lines, "user-agent"); ua != "" {
		res.Meta["sip_user_agent"] = safe.SanitizeForLog(ua)
	}
	status := "501 Not Implemented"
	wwwAuth := false
	switch method {
	case "REGISTER":
		flagAnomaly(&res, "sip-register-probe")
		if u := sipUser(from); u != "" {
			res.Meta["sip_user"] = safe.SanitizeForLog(u)
		}
		if a := sipHeader(lines, "authorization"); a != "" {
			res.Meta["sip_auth"] = safe.SanitizeForLog(a)
			flagAnomaly(&res, "sip-auth-attempt")
		}
		status, wwwAuth = "401 Unauthorized", true
	case "INVITE":
		flagAnomaly(&res, "sip-invite-attempt")
		if n := sipUser(to); n != "" {
			res.Meta["sip_dest"] = safe.SanitizeForLog(n) // dialed number — toll-fraud signal
		}
		status, wwwAuth = "401 Unauthorized", true
	case "OPTIONS":
		flagAnomaly(&res, "sip-options-scan")
		status = "200 OK"
	}
	var b strings.Builder
	b.WriteString("SIP/2.0 " + status + "\r\n")
	for h, v := range map[string]string{"Via": via, "From": from, "Call-ID": callid, "CSeq": cseq} {
		if v != "" {
			b.WriteString(h + ": " + v + "\r\n")
		}
	}
	if to != "" {
		b.WriteString("To: " + to + ";tag=hp001\r\n")
	}
	if wwwAuth {
		b.WriteString("WWW-Authenticate: Digest realm=\"asterisk\",nonce=\"4a2b8f1c\"\r\n")
	}
	if status == "200 OK" {
		b.WriteString("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\n")
	}
	b.WriteString("Server: Asterisk PBX 18.10.0\r\nContent-Length: 0\r\n\r\n")
	_, _ = conn.Write([]byte(b.String()))
	res.BannerSent = "sip " + method + " response"
	return res, nil
}

// --- Cisco SCCP / Skinny (2000) ------------------------------------------
//
// SCCP is the Cisco IP-phone-to-CallManager protocol. Messages are
// [length(4 LE)][reserved(4)][message-id(4 LE)][data]; message 0x0001 is a
// phone RegisterMessage carrying the device name. We capture it and answer a
// RegisterAck so a scanner records a live CallManager.
type sccp struct{}

func (h *sccp) Name() string { return "sccp" }

func sccpMsg(msgID uint32, data []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(8+len(data))) // length covers reserved+id+data
	b = binary.LittleEndian.AppendUint32(b, 0)                      // reserved / header version
	b = binary.LittleEndian.AppendUint32(b, msgID)
	return append(b, data...)
}

func (h *sccp) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 512))
	res.Payload = got
	flagAnomaly(&res, "sccp-probe")
	if len(got) < 12 {
		return res, nil
	}
	msgID := binary.LittleEndian.Uint32(got[8:12])
	res.Meta["sccp_message_id"] = int(msgID)
	if msgID == 0x0001 { // RegisterMessage
		flagAnomaly(&res, "sccp-register")
		if len(got) >= 27 {
			res.Meta["sccp_device"] = safe.SanitizeForLog(strings.TrimRight(string(got[12:27]), "\x00"))
		}
		// RegisterAck (0x0081): keepAlive=60, dateTemplate, secondaryKeepAlive=120.
		ack := []byte{60, 0, 0, 0, 'M', '/', 'D', '/', 'Y', 'A', 0, 0, 120, 0, 0, 0, 0, 0, 0, 0}
		_, _ = conn.Write(sccpMsg(0x0081, ack))
		res.BannerSent = "sccp register ack"
	}
	return res, nil
}

// --- H.225 / H.323 (1720) ------------------------------------------------
//
// H.323 call signalling rides Q.931 inside a TPKT frame. We verify the TPKT
// header, classify the Q.931 message (SETUP = an inbound call), and answer a
// Release Complete so a scanner records a live H.323 gateway.
type h323 struct{}

func (h *h323) Name() string { return "h323" }

func (h *h323) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	got := readCapped(conn, cfg, make([]byte, 1024))
	res.Payload = got
	flagAnomaly(&res, "h323-probe")
	if len(got) < 6 || got[0] != 0x03 || got[4] != 0x08 { // TPKT v3 + Q.931 discriminator
		return res, nil
	}
	callRefLen := int(got[5])
	mtIdx := 6 + callRefLen
	if mtIdx < len(got) {
		mt := got[mtIdx]
		res.Meta["q931_message_type"] = int(mt)
		if mt == 0x05 { // SETUP
			flagAnomaly(&res, "h323-setup")
		}
	}
	// TPKT + Q.931 Release Complete (message type 0x5a), call ref 0.
	q931 := []byte{0x08, 0x00, 0x5a}
	tpkt := []byte{0x03, 0x00, 0x00, byte(4 + len(q931))}
	_, _ = conn.Write(append(tpkt, q931...))
	res.BannerSent = "h323 release complete"
	return res, nil
}

// --- Asterisk Manager Interface (5038) -----------------------------------
//
// The AMI is full administrative control of an Asterisk PBX — Login carries
// the manager credentials and Originate places arbitrary calls (toll fraud).
// The server greets first; we capture the action + credentials and reject.
type asteriskAMI struct{}

func (h *asteriskAMI) Name() string { return "asterisk_ami" }

func (h *asteriskAMI) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	_, _ = conn.Write([]byte("Asterisk Call Manager/7.0.3\r\n"))
	got := readCapped(conn, cfg, make([]byte, 2048))
	res.Payload = got
	fields := map[string]string{}
	for _, l := range strings.Split(string(got), "\n") {
		if i := strings.IndexByte(l, ':'); i > 0 {
			fields[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(strings.TrimRight(l[i+1:], "\r"))
		}
	}
	action := strings.ToLower(fields["action"])
	if action != "" {
		res.Meta["ami_action"] = safe.SanitizeForLog(action)
	}
	switch action {
	case "login":
		flagAnomaly(&res, "ami-login")
		user, secret := fields["username"], fields["secret"]
		if user != "" {
			res.Meta["ami_username"] = safe.SanitizeForLog(user)
		}
		if secret != "" {
			res.Meta["ami_secret"] = safe.SanitizeForLog(secret)
		}
		flagDefaultCred(&res, user, secret)
	case "originate": // place a call — the toll-fraud action
		flagAnomaly(&res, "ami-originate")
	default:
		if action != "" {
			flagAnomaly(&res, "ami-command")
		}
	}
	_, _ = conn.Write([]byte("Response: Error\r\nMessage: Authentication failed\r\n\r\n"))
	res.BannerSent = "ami greeting"
	return res, nil
}

// --- IAX2 (UDP 4569) -----------------------------------------------------
//
// IAX2 trunks Asterisk PBXs together. This is detection-only: we classify the
// frame and flag the probe but never reply — an IAX2 response to a spoofable
// UDP source would be a reflection primitive the sensor must not become.
type iax2 struct{}

func (h *iax2) Name() string { return "iax2" }

func (h *iax2) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}, Payload: payload}
	flagAnomaly(&res, "iax2-probe")
	if len(payload) >= 12 && payload[0]&0x80 != 0 { // full frame
		res.Meta["iax2_full_frame"] = true
	}
	return res, nil
}
