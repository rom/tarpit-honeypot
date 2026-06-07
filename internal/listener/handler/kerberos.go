package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type kerberos struct{}

func (k *kerberos) Name() string { return "kerberos" }

// Kerberos KDC (port 88 TCP). Wire format is a 4-byte big-endian length
// followed by a DER-encoded ASN.1 message. The first message a client
// sends is almost always an AS-REQ (0x6A in DER-tagged form via
// [APPLICATION 10]).
//
// We capture the principal name + service name + encryption types claimed,
// reply KRB-ERROR(KDC_ERR_PREAUTH_REQUIRED=25), then read the pre-auth retry:
// a client that comes back with a PA-ENC-TIMESTAMP is brute-forcing, and that
// encrypted timestamp is offline-crackable to recover the password — so we
// capture it before answering KDC_ERR_PREAUTH_FAILED.
func (k *kerberos) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	body, ok := readKRB(conn)
	if !ok {
		res.Meta["read_err"] = "short or oversized first message"
		return res, nil
	}
	res.Payload = append(res.Payload, krbFrame(body)...)
	k.analyzeKRB(body, &res)

	// Reply with KDC_ERR_PREAUTH_REQUIRED so a real client (or a brute-forcer)
	// retries with a PA-ENC-TIMESTAMP.
	if _, err := conn.Write(krbFrame(buildKRBError(25))); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "kerberos KRB-ERROR (preauth required)"

	// Pre-auth retry: capture the encrypted timestamp (crackable to the
	// password) and answer KDC_ERR_PREAUTH_FAILED.
	body2, ok := readKRB(conn)
	if !ok {
		return res, nil
	}
	res.Payload = append(res.Payload, krbFrame(body2)...)
	if blob := paEncTimestamp(body2); blob != nil {
		res.Meta["preauth_enc_timestamp_hex"] = byteToHex(blob)
		flagAnomaly(&res, "kerberos-preauth-bruteforce")
		_, _ = conn.Write(krbFrame(buildKRBError(24))) // KDC_ERR_PREAUTH_FAILED
		res.BannerSent = "kerberos KRB-ERROR (preauth failed)"
	}
	return res, nil
}

// analyzeKRB records the message type, principal/realm/service names, and the
// requested encryption types from a KDC-REQ, flagging the Kerberoasting /
// roasting / delegation-abuse tells. Shared by the TCP KDC and the UDP probe.
func (k *kerberos) analyzeKRB(body []byte, res *Result) { classifyKRB(body, res) }

// classifyKRB is the protocol-agnostic Kerberos request classifier. It detects
// the legacy Kerberos 4 / KTH-KRB wire format, the KRB5 message type, the
// padata set (which distinguishes pre-auth brute-force, AS-REP roasting,
// PKINIT / Shadow-Credentials, S4U constrained-delegation abuse, and the
// Bronze Bit RBCD path), the requested enctypes (RC4 downgrade), and the
// targeted principals.
func classifyKRB(body []byte, res *Result) {
	if len(body) < 2 {
		return
	}
	// --- Legacy Kerberos 4 / KTH-KRB / eBones --------------------------------
	// A KRB5 message is always a DER [APPLICATION n] tag (0x6A/0x6C/0x6E/0x7E).
	// Kerberos 4 instead opens with the protocol-version byte (4) followed by a
	// small message-type byte (the low bit is a byte-order flag). KTH-KRB and
	// the eBones lineage share this v4 wire format. A v4 request hitting a
	// modern KDC port is either an ancient client or a downgrade probe.
	if body[0] == 0x04 && body[1] <= 0x20 {
		res.Meta["kerberos_version"] = 4
		res.Meta["message_type"] = krb4MsgName(body[1])
		flagAnomaly(res, "kerberos-v4-legacy")
		res.Meta["intent"] = "Legacy Kerberos 4 / KTH-KRB request — obsolete protocol (downgrade or ancient client)"
		if names := kerberosStrings(body); len(names) > 0 {
			res.Meta["principals"] = names
			res.Meta["principal"] = names[0]
		}
		return
	}

	res.Meta["kerberos_version"] = 5
	tag := body[0]
	res.Meta["asn1_tag"] = tag
	isAS := tag == 0x6A
	switch tag {
	case 0x6A:
		res.Meta["message_type"] = "AS-REQ"
	case 0x6C:
		res.Meta["message_type"] = "TGS-REQ"
		// A TGS-REQ asks for a service ticket; on a honeypot KDC no legitimate
		// client does this — it's the Kerberoasting primitive (request service
		// tickets to crack offline).
		flagAnomaly(res, "kerberos-tgs-request")
	default:
		res.Meta["message_type"] = "unknown"
	}

	// --- padata classification ----------------------------------------------
	pa := kerberosPadataTypes(body)
	if len(pa) > 0 {
		res.Meta["padata_types"] = pa
	}
	hasPreauth := false
	for _, t := range pa {
		switch t {
		case 2: // PA-ENC-TIMESTAMP — pre-authentication present.
			hasPreauth = true
		case 16, 17: // PA-PK-AS-REQ/REP — PKINIT (certificate / Shadow Credentials).
			flagAnomaly(res, "kerberos-pkinit")
			res.Meta["intent"] = "Kerberos PKINIT request — certificate pre-auth (key-trust / Shadow-Credentials abuse vector)"
		case 129: // PA-FOR-USER — S4U2Self (protocol transition / constrained delegation).
			flagAnomaly(res, "kerberos-s4u")
			res.Meta["intent"] = "Kerberos S4U2Self (PA-FOR-USER) — constrained-delegation / protocol-transition abuse"
		case 167: // PA-PAC-OPTIONS — resource-based constrained delegation / Bronze Bit.
			flagAnomaly(res, "kerberos-pac-options")
			res.Meta["intent"] = "Kerberos PA-PAC-OPTIONS — resource-based delegation / Bronze Bit (CVE-2020-17049) path"
		}
	}
	// AS-REQ with no PA-ENC-TIMESTAMP = the account allows pre-auth-less AS-REP
	// (or the attacker is probing for one): the AS-REP roasting primitive, where
	// the returned AS-REP is encrypted with the user's key and cracked offline.
	if isAS && !hasPreauth {
		flagAnomaly(res, "kerberos-asrep-roast")
		setIfEmpty(res.Meta, "intent", "Kerberos AS-REQ without pre-auth — AS-REP roasting (offline crack of accounts with pre-auth disabled)")
	}

	if names := kerberosStrings(body); len(names) > 0 {
		res.Meta["principals"] = names
		res.Meta["principal"] = names[0]
		flagAnomaly(res, "kerberos-principal-probe")
	}
	if ets := kerberosEnctypes(body); len(ets) > 0 {
		res.Meta["enctypes"] = ets
		for _, e := range ets {
			if e == "rc4-hmac" {
				// RC4 in the requested etype list is the offline-crack downgrade
				// Kerberoasting / AS-REP roasting rely on (modern Windows
				// defaults to AES 17/18).
				res.Meta["rc4_requested"] = true
				flagAnomaly(res, "kerberos-rc4-requested")
			}
		}
	}
}

// krb4MsgName names a Kerberos 4 message type (the low bit is a byte-order
// flag, so we mask it off before naming).
func krb4MsgName(b byte) string {
	switch b & 0xFE {
	case 2:
		return "KRB4 AUTH_MSG_KDC_REQUEST"
	case 4:
		return "KRB4 AUTH_MSG_KDC_REPLY"
	case 6:
		return "KRB4 AUTH_MSG_APPL_REQUEST"
	case 8:
		return "KRB4 AUTH_MSG_APPL_REQUEST_MUTUAL"
	case 10:
		return "KRB4 AUTH_MSG_ERR_REPLY"
	}
	return "KRB4 msg-type " + itoa(int(b))
}

// kerberosPadataTypes scans a KDC-REQ for the padata-type integers in its
// PA-DATA sequence. Each PA-DATA is SEQUENCE { [1] padata-type INTEGER,
// [2] padata-value OCTET STRING }; the [1] wrapper around a 1-byte type is
// 0xA1 0x03 0x02 0x01 <type>, and around a 2-byte type (>=128) is
// 0xA1 0x04 0x02 0x02 <hi> <lo>. We match both forms.
func kerberosPadataTypes(body []byte) []int {
	var out []int
	for i := 0; i+4 < len(body) && len(out) < 32; i++ {
		if body[i] != 0xA1 {
			continue
		}
		switch {
		case body[i+1] == 0x03 && body[i+2] == 0x02 && body[i+3] == 0x01:
			out = append(out, int(body[i+4]))
		case body[i+1] == 0x04 && body[i+2] == 0x02 && body[i+3] == 0x02 && i+5 < len(body):
			out = append(out, int(body[i+4])<<8|int(body[i+5]))
		}
	}
	return out
}

// readKRB reads one length-prefixed Kerberos message body (4-byte big-endian
// length + DER), bounded.
func readKRB(conn net.Conn) ([]byte, bool) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, false
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n < 4 || n > 65535 {
		return nil, false
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, false
	}
	return body, true
}

// krbFrame prepends the 4-byte big-endian length to a Kerberos message.
func krbFrame(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

// kerberosEnctypes returns the named encryption types requested in a KDC-REQ
// (best-effort: scans for the DER INTEGER encodings of the common etypes, which
// are specific enough to be reliable).
func kerberosEnctypes(body []byte) []string {
	var out []string
	for _, e := range []struct {
		v    byte
		name string
	}{{0x12, "aes256-cts"}, {0x11, "aes128-cts"}, {0x17, "rc4-hmac"}} {
		if bytes.Contains(body, []byte{0x02, 0x01, e.v}) {
			out = append(out, e.name)
		}
	}
	return out
}

// paEncTimestamp extracts the EncryptedData octets of a PA-ENC-TIMESTAMP
// padata (the offline-crackable encrypted timestamp), or nil if absent.
// PA-DATA ::= SEQUENCE { [1] padata-type INTEGER(2), [2] padata-value OCTET STRING }.
func paEncTimestamp(body []byte) []byte {
	idx := bytes.Index(body, []byte{0xA1, 0x03, 0x02, 0x01, 0x02}) // [1] padata-type = 2
	if idx < 0 {
		return nil
	}
	j := idx + 5
	if j >= len(body) || body[j] != 0xA2 { // [2] padata-value
		return nil
	}
	_, vhdr, ok := derLen(body, j+1)
	if !ok {
		return nil
	}
	k := j + 1 + vhdr
	if k >= len(body) || body[k] != 0x04 { // OCTET STRING
		return nil
	}
	olen, ohdr, ok := derLen(body, k+1)
	if !ok || olen <= 0 || olen > 4096 {
		return nil
	}
	start := k + 1 + ohdr
	if start+olen > len(body) {
		return nil
	}
	return body[start : start+olen]
}

// derLen reads a DER length at b[i], returning the length value and the number
// of bytes the length field occupies.
func derLen(b []byte, i int) (n, hdr int, ok bool) {
	if i >= len(b) {
		return 0, 0, false
	}
	l := b[i]
	if l < 0x80 {
		return int(l), 1, true
	}
	nb := int(l & 0x7f)
	if nb == 0 || nb > 4 || i+1+nb > len(b) {
		return 0, 0, false
	}
	v := 0
	for k := 0; k < nb; k++ {
		v = v<<8 | int(b[i+1+k])
	}
	return v, 1 + nb, true
}

// kerberosStrings pulls the GeneralString values (DER tag 0x1B) out of a
// Kerberos message — these are the realm + principal/service name components,
// i.e. the username an AS-REP-roast / password spray is targeting. Bounded to
// short, printable, single-length-byte strings (principal components are well
// under 128 bytes) so a malformed message can't drive an unbounded scan.
func kerberosStrings(b []byte) []string {
	var out []string
	for i := 0; i+1 < len(b) && len(out) < 16; {
		if b[i] == 0x1B {
			n := int(b[i+1])
			if n > 0 && n < 128 && i+2+n <= len(b) {
				s := b[i+2 : i+2+n]
				if !hasNonPrintable(string(s)) {
					out = append(out, string(s))
					i += 2 + n
					continue
				}
			}
		}
		i++
	}
	return out
}

// buildKRBError is intentionally minimal — most scanners just check the
// outer tag and outer error code field. We send a [APPLICATION 30] (0x7E)
// wrapping a SEQUENCE with a small error-code INTEGER.
func buildKRBError(code int) []byte {
	// Inner: SEQUENCE { [0] pvno INTEGER, [1] msg-type INTEGER,
	// [6] error-code INTEGER, [9] realm GeneralString }. The realm is the KDC's
	// realm — the deployment DNS domain, uppercased (AD convention), so the KDC
	// identity is consistent with the rest of the sensor.
	inner := []byte{
		0xA0, 0x03, 0x02, 0x01, 0x05, // [0] pvno = 5
		0xA1, 0x03, 0x02, 0x01, 0x1E, // [1] msg-type = 30 (KRB-ERROR)
		0xA6, 0x03, 0x02, 0x01, byte(code), // [6] error-code
	}
	realm := strings.ToUpper(deploymentDomainOr("EXAMPLE.INTERNAL"))
	if len(realm) > 0 && len(realm) < 250 {
		gs := append([]byte{0x1B, byte(len(realm))}, []byte(realm)...) // GeneralString
		field := append([]byte{0xA9, byte(len(gs))}, gs...)            // [9] realm
		inner = append(inner, field...)
	}
	seq := append([]byte{0x30, byte(len(inner))}, inner...)
	wrapped := append([]byte{0x7E, byte(len(seq))}, seq...)
	return wrapped
}
