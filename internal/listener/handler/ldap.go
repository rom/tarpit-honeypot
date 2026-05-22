package handler

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

type ldap struct {
	hosts []HoneynetHost
}

func (l *ldap) Name() string { return "ldap" }

// SetHoneynetView installs the honeynet topology so the handler can
// advertise virtual computer accounts in BindResponse meta.
func (l *ldap) SetHoneynetView(v HoneynetSnapshot) { l.hosts = v.Hosts }

// LDAP (port 389). Every protocol message is BER-encoded:
//
//	LDAPMessage ::= SEQUENCE {
//	  messageID INTEGER,
//	  protocolOp CHOICE { bindRequest [APPLICATION 0] ..., ... }
//	}
//
// A BindRequest carries version, bindDN, and authentication choice.
// Authentication choice 0x80 = simple (cleartext password). That's the
// juicy field — scanners brute-forcing AD service accounts ship the
// password in the clear here.
//
// We capture bindDN + simple-auth password, then reply with a BindResponse
// of resultCode 49 (invalidCredentials).
func (l *ldap) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	var ops []string
	for i := 0; i < 8; i++ {
		pkt, err := readBERMessage(conn, 8192)
		if err != nil {
			if i == 0 {
				res.Meta["read_err"] = err.Error()
			}
			break
		}
		res.Payload = append(res.Payload, pkt...)
		messageID, op, opBody, ok := parseLDAPMessage(pkt)
		if !ok {
			res.Meta["bad_ldap_message"] = true
			break
		}
		ops = append(ops, ldapOpName(op))
		res.Meta["message_id"] = messageID
		res.Meta["op"] = ldapOpName(op)

		switch op {
		case 0x60: // BindRequest [APPLICATION 0]
			ver, bindDN, simplePw, mech := parseBindRequest(opBody)
			res.Meta["ldap_version"] = ver
			if bindDN != "" {
				res.Meta["bind_dn"] = bindDN
			}
			if simplePw != "" {
				res.Meta["bind_pw"] = simplePw
			}
			if mech != "" {
				res.Meta["sasl_mechanism"] = mech
			}
			anonymous := bindDN == "" && simplePw == "" && mech == ""
			if !anonymous && (bindDN != "" || simplePw != "") {
				flagDefaultCred(&res, bindDN, simplePw)
			}
			if len(l.hosts) > 0 {
				computers := make([]map[string]string, 0, len(l.hosts))
				for _, h := range l.hosts {
					computers = append(computers, map[string]string{
						"dn": "cn=" + h.Hostname + ",ou=Computers", "hostname": h.Hostname, "ip": h.IP, "os": h.OS,
					})
				}
				res.Meta["honeynet_computer_accounts"] = computers
			}
			// Accept an anonymous bind (resultCode 0) to elicit the
			// follow-up search a scanner runs; reject credentialed binds
			// (49) so a brute-force keeps shipping passwords.
			code := 49
			if anonymous {
				code = 0
			}
			if _, err := conn.Write(buildLDAPBindResponse(messageID, code)); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			res.BannerSent = "ldap BindResponse"
		case 0x63: // SearchRequest [APPLICATION 3]
			detectLDAPEnumeration(&res, pkt)
			if _, err := conn.Write(buildLDAPSearchDone(messageID, 0)); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			res.BannerSent = "ldap SearchResultDone"
		case 0x42: // UnbindRequest
			res.Meta["ops"] = ops
			return res, nil
		default:
			// Unhandled op — stop rather than guess a response.
			break
		}
	}
	if len(ops) > 0 {
		res.Meta["ops"] = ops
	}
	return res, nil
}

// detectLDAPEnumeration flags AD-reconnaissance search patterns by scanning
// the raw BER message for the attribute names / filter OIDs that appear as
// ASCII in the request: SPN enumeration (Kerberoasting recon), the
// DONT_REQ_PREAUTH filter (AS-REP roasting recon), and broad account/object
// enumeration.
func detectLDAPEnumeration(res *Result, pkt []byte) {
	low := bytes.ToLower(pkt)
	if bytes.Contains(low, []byte("serviceprincipalname")) {
		flagAnomaly(res, "ldap-spn-enumeration")
	}
	// userAccountControl:1.2.840.113556.1.4.803:=4194304 → accounts with
	// "do not require pre-auth" set = AS-REP roasting targets.
	if bytes.Contains(low, []byte("1.2.840.113556.1.4.803")) || bytes.Contains(pkt, []byte("4194304")) {
		flagAnomaly(res, "ldap-asrep-roast-recon")
	}
	for _, attr := range []string{"objectclass", "samaccountname", "objectcategory", "memberof", "admincount"} {
		if bytes.Contains(low, []byte(attr)) {
			flagAnomaly(res, "ldap-enumeration")
			break
		}
	}
}

// buildLDAPSearchDone returns a SearchResultDone [APPLICATION 5] with the
// given resultCode (0 = success, no entries).
func buildLDAPSearchDone(messageID, code int) []byte {
	inner := []byte{0x0A, 0x01, byte(code), 0x04, 0x00, 0x04, 0x00}
	op := append([]byte{0x65, byte(len(inner))}, inner...)
	body := append(encodeBERInt(messageID), op...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func ldapOpName(op byte) string {
	switch op {
	case 0x60:
		return "BindRequest"
	case 0x61:
		return "BindResponse"
	case 0x42:
		return "UnbindRequest"
	case 0x63:
		return "SearchRequest"
	}
	return ""
}

// readBERMessage reads one BER-encoded SEQUENCE from r. Caller supplies a
// soft cap to avoid allocating from a malicious giant length.
func readBERMessage(r io.Reader, cap int) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[0] != 0x30 { // SEQUENCE
		return nil, io.ErrUnexpectedEOF
	}
	lenBytes, length, err := readBERLength(head[1], r)
	if err != nil {
		return nil, err
	}
	if length > cap {
		length = cap
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+1+len(lenBytes)+length)
	out = append(out, head[0])
	out = append(out, head[1])
	out = append(out, lenBytes...)
	out = append(out, body...)
	return out, nil
}

func readBERLength(first byte, r io.Reader) ([]byte, int, error) {
	if first&0x80 == 0 {
		return nil, int(first), nil
	}
	nbytes := int(first & 0x7F)
	if nbytes == 0 || nbytes > 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	extra := make([]byte, nbytes)
	if _, err := io.ReadFull(r, extra); err != nil {
		return nil, 0, err
	}
	n := 0
	for _, b := range extra {
		n = n<<8 | int(b)
	}
	return extra, n, nil
}

// parseLDAPMessage extracts message_id and protocolOp tag + body from a
// SEQUENCE payload, skipping the outer SEQUENCE tag/length we already
// consumed.
func parseLDAPMessage(pkt []byte) (int, byte, []byte, bool) {
	if len(pkt) < 2 || pkt[0] != 0x30 {
		return 0, 0, nil, false
	}
	p := 1
	_, hdrLen, body, ok := stripBERHeader(pkt[p:])
	if !ok {
		return 0, 0, nil, false
	}
	p += hdrLen
	if p >= len(pkt) {
		return 0, 0, nil, false
	}
	// message_id INTEGER
	mid, n, ok := parseBERInteger(pkt[p:])
	if !ok {
		return 0, 0, nil, false
	}
	p += n
	if p >= len(pkt) {
		return 0, 0, nil, false
	}
	op := pkt[p]
	opTagLen, _, opBody, ok := stripBERHeader(pkt[p+1:])
	if !ok {
		return 0, 0, nil, false
	}
	_ = opTagLen
	_ = body
	return mid, op, opBody, true
}

// stripBERHeader takes bytes starting with a length byte and returns
// (lenByteCount, totalHeaderBytesConsumed, body, ok).
func stripBERHeader(b []byte) (lenBytes int, hdrBytes int, body []byte, ok bool) {
	if len(b) < 1 {
		return 0, 0, nil, false
	}
	first := b[0]
	if first&0x80 == 0 {
		// Short form: 1-byte length encoding. Check bounds *before*
		// slicing — a malicious / fuzzer-generated input can set
		// length to a value that overflows the available bytes.
		n := int(first)
		if 1+n > len(b) {
			return 0, 0, nil, false
		}
		return 1, 1, b[1 : 1+n], true
	}
	nbytes := int(first & 0x7F)
	if nbytes == 0 || nbytes > 4 || 1+nbytes > len(b) {
		return 0, 0, nil, false
	}
	n := 0
	for i := 0; i < nbytes; i++ {
		n = n<<8 | int(b[1+i])
	}
	if 1+nbytes+n > len(b) {
		return 0, 0, nil, false
	}
	return nbytes, 1 + nbytes, b[1+nbytes : 1+nbytes+n], true
}

func parseBERInteger(b []byte) (int, int, bool) {
	if len(b) < 2 || b[0] != 0x02 {
		return 0, 0, false
	}
	_, hdr, body, ok := stripBERHeader(b[1:])
	if !ok {
		return 0, 0, false
	}
	n := 0
	for _, by := range body {
		n = n<<8 | int(by)
	}
	// Total bytes consumed = tag(1) + length-encoding(hdr) + body.
	return n, 1 + hdr + len(body), true
}

// parseBindRequest unpacks version + bindDN + (simple password or SASL
// mech name). opBody is the inside of the [APPLICATION 0] SEQUENCE.
func parseBindRequest(opBody []byte) (version int, bindDN, simplePW, saslMech string) {
	p := 0
	// version INTEGER
	if v, n, ok := parseBERInteger(opBody[p:]); ok {
		version = v
		p += n
	}
	// name OCTET STRING (0x04)
	if p < len(opBody) && opBody[p] == 0x04 {
		_, hdr, body, ok := stripBERHeader(opBody[p+1:])
		if ok {
			bindDN = string(body)
			p += 1 + hdr + len(body)
		}
	}
	// authentication: simple [0] OCTET STRING (0x80) or SASL [3] (0xA3)
	if p < len(opBody) {
		tag := opBody[p]
		switch tag {
		case 0x80:
			_, hdr, body, ok := stripBERHeader(opBody[p+1:])
			if ok {
				simplePW = string(body)
				_ = hdr
			}
		case 0xA3:
			// SEQUENCE of mechanism + credentials
			_, _, saslBody, ok := stripBERHeader(opBody[p+1:])
			if ok && len(saslBody) > 0 && saslBody[0] == 0x04 {
				_, _, mechBody, ok := stripBERHeader(saslBody[1:])
				if ok {
					saslMech = string(mechBody)
				}
			}
		}
	}
	return
}

// buildLDAPBindResponse returns a BindResponse with resultCode = code.
// Layout: SEQUENCE { messageID INTEGER, BindResponse [APP 1] { resultCode ENUMERATED, matchedDN, diagnosticMessage } }
func buildLDAPBindResponse(messageID int, code int) []byte {
	// Inner protocolOp body.
	inner := []byte{}
	// resultCode ENUMERATED (0x0A, 1 byte)
	inner = append(inner, 0x0A, 0x01, byte(code))
	// matchedDN OCTET STRING (empty)
	inner = append(inner, 0x04, 0x00)
	// diagnosticMessage OCTET STRING (empty)
	inner = append(inner, 0x04, 0x00)

	// [APP 1] = 0x61
	op := append([]byte{0x61, byte(len(inner))}, inner...)

	// messageID INTEGER
	midBytes := encodeBERInt(messageID)
	body := append(midBytes, op...)

	return append([]byte{0x30, byte(len(body))}, body...)
}

func encodeBERInt(v int) []byte {
	// Single-byte path (good enough for low message IDs).
	if v >= -128 && v <= 127 {
		return []byte{0x02, 0x01, byte(v)}
	}
	// Two-byte path (covers up to ~32k).
	return []byte{0x02, 0x02, byte(v >> 8), byte(v)}
}
