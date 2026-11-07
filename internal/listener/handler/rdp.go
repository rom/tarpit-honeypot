package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/fingerprint"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

type rdp struct {
	tlsMgr *certManager
	arch   *archetype.Profile
	id     *identity.Identity
}

func newRDP(deps Deps) *rdp {
	return &rdp{tlsMgr: maybeCertMgr(deps), arch: deps.Archetype, id: deps.Identity}
}

func (r *rdp) Name() string { return "rdp" }

// Microsoft RDP (port 3389). The handshake opens with X.224 / TPKT:
//
//	TPKT (4 bytes): version=3, reserved=0, length(big-endian)
//	X.224 Connection Request: length(1), code=0xE0, dst_ref(2), src_ref(2),
//	                          class(1), then optional Cookie/RDP_NEG_REQ
//
// Inside the variable part the client puts a "Cookie: mstshash=<user>\r\n"
// line and/or an RDP_NEG_REQ TLV announcing supported security protocols
// (PROTOCOL_SSL=0x01, PROTOCOL_HYBRID=0x02, etc.). We capture both and
// reply with an X.224 Connection Confirm announcing PROTOCOL_SSL. The client
// then starts TLS; with a cert manager we complete it (recording JA3/JA3S) and
// drive the CredSSP/NLA NTLM exchange one round further than a real server
// needs to — issuing the NTLMSSP CHALLENGE so the client sends its
// AUTHENTICATE — to harvest the offline-crackable NetNTLMv1 / v2. We never speak
// full RDP and never validate the credential (capture only).
func (r *rdp) Handle(ctx context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{}

	tpkt := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpkt); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	if tpkt[0] != 0x03 {
		res.Meta = map[string]any{"non_tpkt_version": tpkt[0]}
		return res, nil
	}
	total := binary.BigEndian.Uint16(tpkt[2:4])
	if total < 7 || total > 4096 {
		res.Meta = map[string]any{"bad_tpkt_length": total}
		return res, nil
	}
	body := make([]byte, int(total)-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		res.Meta = map[string]any{"read_err": err.Error()}
		return res, nil
	}
	res.Payload = append(tpkt, body...)

	// CVE exploit-attempt recognition (BlueKeep's rogue "MS_T120"
	// channel name appears as ASCII in the MCS Connect PDU). Detection only.
	for _, rec := range cve.MatchPayload("rdp", string(res.Payload)) {
		res.CVEHits = appendUnique(res.CVEHits, rec.ID)
		flagAnomaly(&res, "cve:"+rec.ID)
	}

	if len(body) < 6 || body[1] != 0xE0 {
		res.Meta = map[string]any{"cotp_type": body[1]}
		return res, nil
	}
	dstRef := binary.BigEndian.Uint16(body[2:4])
	srcRef := binary.BigEndian.Uint16(body[4:6])
	res.Meta = map[string]any{
		"dst_ref": dstRef,
		"src_ref": srcRef,
	}
	// Variable part after class byte.
	if len(body) > 7 {
		variable := body[7:]
		if cookie := extractCookie(variable); cookie != "" {
			res.Meta["cookie"] = cookie
			if strings.HasPrefix(strings.ToLower(cookie), "msts=") {
				// "Cookie: msts=..." is the RD load-balancer routing token —
				// reveals target collection/host routing, not a username.
				flagAnomaly(&res, "rdp-routing-token")
				setIfEmpty(res.Meta, "intent", "RDP load-balancer routing token (msts=) — backend routing recon")
			} else {
				// mstshash carries the username the client is targeting —
				// credential reconnaissance even before any auth. Strip the
				// "mstshash=" prefix so the bare username flows into the
				// credential store / export-creds / cred-reuse correlation.
				flagAnomaly(&res, "rdp-username-harvest")
				res.Meta["intent"] = "RDP username harvest via mstshash cookie (" + cookie + ")"
				user := cookie
				if eq := strings.IndexByte(cookie, '='); eq >= 0 {
					user = cookie[eq+1:]
				}
				if user = strings.TrimSpace(user); user != "" {
					res.Meta["username"] = user
				}
			}
		}
		if negReq := findNegReq(variable); negReq != nil {
			nr := describeNegReq(negReq)
			res.Meta["rdp_neg_req"] = nr
			// PROTOCOL_RDP (0) = legacy "Standard RDP Security" with no NLA/TLS;
			// requesting it (or SSL-only, no HYBRID) is an NLA/CredSSP downgrade
			// — the precondition for a NetNTLM MITM/relay (e.g. Seth).
			if p, ok := nr["requested_protocol"].(uint32); ok {
				if p == 0 {
					flagAnomaly(&res, "rdp-nla-downgrade")
					setIfEmpty(res.Meta, "intent", "RDP standard-security requested (no NLA/TLS) — CredSSP/NLA downgrade")
				} else if p&0x02 == 0 && p&0x08 == 0 { // SSL/RDSTLS but no HYBRID(_EX)
					flagAnomaly(&res, "rdp-nla-downgrade")
					setIfEmpty(res.Meta, "intent", "RDP requested without HYBRID/NLA — CredSSP downgrade (NetNTLM MITM setup)")
				}
			}
		}
	}

	// Build X.224 Connection Confirm with RDP_NEG_RSP selecting PROTOCOL_SSL.
	cc := []byte{
		0x0E, 0xD0, // length, type=CC
		0x00, 0x00, // dst ref echoes server-chosen
		byte(srcRef >> 8), byte(srcRef & 0xFF), // mirror src
		0x00, // class 0
		// RDP_NEG_RSP TLV: type=0x02, flags=0x00, length(2)=0x0008, selected_protocol(4)
		0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
	tpktOut := []byte{0x03, 0x00, 0x00, byte(4 + len(cc))}
	if _, err := conn.Write(append(tpktOut, cc...)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "rdp X.224 CC + RDP_NEG_RSP(PROTOCOL_SSL)"

	// Having selected PROTOCOL_SSL, a real server now performs the TLS
	// handshake the client expects. Without a cert manager (no data dir) we
	// stop here as before. With one, we complete the handshake — recording
	// JA3/JA3S — and then read the CredSSP/NLA exchange, best-effort harvesting
	// the NTLMSSP domain/user (and the offline-crackable NetNTLM response) an
	// NLA brute-force leaks.
	if r.tlsMgr == nil {
		return res, nil
	}
	tcfg, err := r.tlsMgr.serverConfig(cfg.ID, tlsHosts(cfg), r.arch)
	if err != nil {
		res.Meta["cert_err"] = err.Error()
		return res, nil
	}
	peeker := newPeekConn(conn)
	ja3Hash, ja3Raw, ja4 := "", "", ""
	if ch, ok := peeker.peekClientHello(); ok {
		ja3Raw, ja3Hash = fingerprint.JA3(ch)
		ja4 = fingerprint.JA4(ch)
	}
	capConn := newCaptureConn(peeker, 4096)
	tlsConn := tls.Server(capConn, tcfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.Meta["tls_err"] = err.Error()
		addFP(res.Meta, ja3Hash, ja3Raw, ja4, "", "")
		return res, nil
	}
	res.Meta["tls"] = true
	res.Meta["tls_version"] = tlsVersionName(tlsConn.ConnectionState().Version)
	ja3sRaw, ja3sHash := "", ""
	if sh := capConn.serverHello(); sh != nil {
		ja3sRaw, ja3sHash = fingerprint.JA3S(sh)
	}
	addFP(res.Meta, ja3Hash, ja3Raw, ja4, ja3sHash, ja3sRaw)
	res.BannerSent = "rdp TLS + CredSSP"

	// Drive the CredSSP/NLA NTLM exchange to completion so we harvest the
	// offline-crackable NetNTLMv1 / v2 response (not just the pre-auth username).
	r.captureNLA(tlsConn, cfg, &res)
	return res, nil
}

// captureNLA runs the post-TLS CredSSP/NLA NTLM handshake far enough to harvest
// the attacker's NetNTLM (v1 or v2): it reads the client's NTLMSSP NEGOTIATE (type 1),
// replies with an NTLMSSP CHALLENGE (type 2) wrapped in SPNEGO + a CredSSP
// TSRequest, then reads the client's AUTHENTICATE (type 3) and extracts the
// hashcat-format NetNTLM hash (mode 5500 for v1, 5600 for v2). We never validate it — capture only.
func (r *rdp) captureNLA(conn net.Conn, cfg config.Listener, res *Result) {
	withTimeout(conn, cfg.ReadTimeout)
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return
	}
	msg1 := buf[:n]
	res.Payload = append(res.Payload, msg1...)
	ntlm1 := findNTLMSSP(msg1)
	if ntlm1 == nil || len(ntlm1) < 12 {
		return
	}
	switch binary.LittleEndian.Uint32(ntlm1[8:12]) { // NTLMSSP MessageType
	case 3:
		// Some tools send the AUTHENTICATE unsolicited (no challenge round).
		// Without our challenge it isn't crackable, but record what we can.
		if dom, user, nt := parseNTLMType3(ntlm1); user != "" {
			res.Meta["ntlm_domain"] = dom
			res.Meta["ntlm_user"] = user
			if nt != "" {
				res.Meta["ntlm_response_hex"] = nt
			}
			flagAnomaly(res, "rdp-ntlm-auth")
		}
		return
	case 1:
		// fall through to the challenge/response below
	default:
		return
	}

	// Send our CHALLENGE (type 2) wrapped in SPNEGO + a CredSSP TSRequest.
	serverChallenge := randomChallenge(r.id)
	challenge := buildCredSSPTSRequest(credsspVersion(msg1), spnegoChallenge(ntlmsspChallenge(serverChallenge)))
	if _, err := conn.Write(challenge); err != nil {
		return
	}

	// Read the client's AUTHENTICATE (type 3) and harvest the NetNTLM hash.
	withTimeout(conn, cfg.ReadTimeout)
	n2, _ := conn.Read(buf)
	if n2 <= 0 {
		return
	}
	msg3 := buf[:n2]
	res.Payload = append(res.Payload, msg3...)
	ntlm3 := findNTLMSSP(msg3)
	if ntlm3 == nil || len(ntlm3) < 12 || binary.LittleEndian.Uint32(ntlm3[8:12]) != 3 {
		return
	}
	res.Meta["nla"] = true
	captureNetNTLM("rdp", ntlm3, serverChallenge, res)
}

// buildCredSSPTSRequest wraps a single SPNEGO/NTLM token in a CredSSP
// (MS-CSSP) TSRequest negoTokens field, announcing the given protocol version:
//
//	TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] NegoData, ... }
//	NegoData  ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
func buildCredSSPTSRequest(version int, negoToken []byte) []byte {
	ver := der(0xa0, der(0x02, []byte{byte(version)}))                // [0] version INTEGER
	tok := der(0xa0, der(0x04, negoToken))                            // [0] negoToken OCTET STRING
	negoData := der(0x30, der(0x30, tok))                             // NegoData: SEQUENCE OF SEQUENCE
	negoTokens := der(0xa1, negoData)                                 // [1] negoTokens
	return der(0x30, append(append([]byte{}, ver...), negoTokens...)) // TSRequest
}

// credsspVersion reads the [0] version INTEGER from the head of a TSRequest,
// clamped to the CredSSP-defined 2..6 range; defaults to 6 when absent.
func credsspVersion(ts []byte) int {
	for i := 0; i+5 <= len(ts) && i < 16; i++ {
		// [0] { INTEGER len=1 value } == a0 03 02 01 0X
		if ts[i] == 0xa0 && ts[i+1] == 0x03 && ts[i+2] == 0x02 && ts[i+3] == 0x01 {
			v := int(ts[i+4])
			if v < 2 {
				v = 2
			}
			if v > 6 {
				v = 6
			}
			return v
		}
	}
	return 6
}

// findNTLMSSP returns the slice of b starting at the NTLMSSP signature (the NTLM
// token embedded in a CredSSP/SPNEGO blob), or nil if absent.
func findNTLMSSP(b []byte) []byte {
	if i := bytes.Index(b, []byte("NTLMSSP\x00")); i >= 0 {
		return b[i:]
	}
	return nil
}

func extractCookie(b []byte) string {
	// "Cookie: mstshash=<user>\r\n"
	const prefix = "Cookie: "
	for i := 0; i+len(prefix) <= len(b); i++ {
		if string(b[i:i+len(prefix)]) == prefix {
			end := i + len(prefix)
			for end < len(b) && b[end] != '\r' && b[end] != '\n' {
				end++
			}
			return string(b[i+len(prefix) : end])
		}
	}
	return ""
}

func findNegReq(b []byte) []byte {
	// RDP_NEG_REQ TLV begins with type=0x01.
	for i := 0; i+8 <= len(b); i++ {
		if b[i] == 0x01 && b[i+2] == 0x08 && b[i+3] == 0x00 {
			return b[i : i+8]
		}
	}
	return nil
}

func describeNegReq(t []byte) map[string]any {
	if len(t) < 8 {
		return nil
	}
	flags := t[1]
	proto := binary.LittleEndian.Uint32(t[4:8])
	out := map[string]any{
		"flags":              flags,
		"requested_protocol": proto,
	}
	names := []string{}
	if proto&0x01 != 0 {
		names = append(names, "SSL")
	}
	if proto&0x02 != 0 {
		names = append(names, "HYBRID")
	}
	if proto&0x04 != 0 {
		names = append(names, "RDSTLS")
	}
	if proto&0x08 != 0 {
		names = append(names, "HYBRID_EX")
	}
	if len(names) > 0 {
		out["requested_protocol_names"] = names
	}
	return out
}
