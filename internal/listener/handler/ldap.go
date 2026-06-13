package handler

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

type ldap struct {
	hosts    []HoneynetHost
	arch     *archetype.Profile
	hostname string // virtual-host short name for per-host rootDSE identity
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
			flagAnomaly(&res, "ldap-malformed-ber")
			setIfEmpty(res.Meta, "intent", "Malformed LDAP/BER message — protocol fuzzing or a crafted-request slapd DoS attempt")
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
			detectLDAPInjection(&res, pkt)
			// A rootDSE base search (empty baseObject) reads the directory's
			// naming contexts — answer like a real DC with the AD naming-context
			// attributes derived from the deployment domain, then the done.
			if isRootDSESearch(opBody) {
				res.Meta["ldap_rootdse_query"] = true
				dom := deploymentDomainOr("example.internal")
				res.Meta["ldap_default_naming_context"] = domainToDN(dom)
				if _, err := conn.Write(buildLDAPRootDSE(messageID, dom, l.arch.ADFunctionalLevel(), l.hostname)); err != nil {
					res.Meta["write_err"] = err.Error()
				}
			}
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

// detectLDAPInjection flags LDAP filter-injection probing (CWE-90). In a
// well-formed SearchRequest the filter STRUCTURE (&, |, parentheses) is
// BER-encoded as tags/lengths, so a literal ASCII filter-breakout sequence
// only appears when an attacker has stuffed filter metacharacters into an
// assertion value — the hallmark of an injection probe, and effectively
// absent from benign traffic.
func detectLDAPInjection(res *Result, pkt []byte) {
	low := bytes.ToLower(pkt)
	for _, sig := range [][]byte{[]byte("*)("), []byte(")(|("), []byte(")(&(")} {
		if bytes.Contains(low, sig) {
			flagAnomaly(res, "ldap-injection")
			res.Meta["intent"] = "LDAP search-filter injection probe — filter metacharacters in an assertion value (CWE-90)"
			return
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

// --- rootDSE / Active Directory naming-context emission --------------------

// isRootDSESearch reports whether a SearchRequest body targets the rootDSE: an
// empty baseObject (LDAPDN ""), which is how a client/scanner reads the
// directory's defaultNamingContext / namingContexts (base scope, base "").
func isRootDSESearch(opBody []byte) bool {
	return len(opBody) >= 2 && opBody[0] == 0x04 && opBody[1] == 0x00
}

// berLen encodes a BER definite length (short form < 128, else long form).
func ldapBERLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// berTLV wraps content in a tag + definite length.
func berTLV(tag byte, content []byte) []byte {
	out := append([]byte{tag}, ldapBERLen(len(content))...)
	return append(out, content...)
}

func berOctet(s string) []byte { return berTLV(0x04, []byte(s)) }

// ldapAttr builds a PartialAttribute: SEQUENCE { type OCTET STRING, vals SET OF }.
func ldapAttr(name string, vals ...string) []byte {
	var set []byte
	for _, v := range vals {
		set = append(set, berOctet(v)...)
	}
	content := append(berOctet(name), berTLV(0x31, set)...) // 0x31 = SET
	return berTLV(0x30, content)
}

// domainToDN turns "corp.example.com" into "DC=corp,DC=example,DC=com".
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i := range parts {
		parts[i] = "DC=" + parts[i]
	}
	return strings.Join(parts, ",")
}

// buildLDAPRootDSE builds a SearchResultEntry [APPLICATION 4] for the rootDSE,
// advertising the Active-Directory naming contexts + service identity derived
// from the deployment domain — what a real DC returns to an anonymous base
// search, and what AD-recon tools read first.
func buildLDAPRootDSE(messageID int, domain string, level int, hostname string) []byte {
	base := domainToDN(domain)
	cfgNC := "CN=Configuration," + base
	schemaNC := "CN=Schema," + cfgNC
	realm := strings.ToUpper(domain)
	// Per-virtual-host identity: each honeynet DC presents its own name; the
	// stand-alone listener (no hostname) keeps the canonical dc01.
	short := strings.ToLower(hostname)
	if short == "" {
		short = "dc01"
	}
	upper := strings.ToUpper(short)
	host := short + "." + domain
	// A real DC always reports a functional level; default to 7 ("Windows2016",
	// the level 2016/2019/2022 DCs run at) when the archetype didn't pin one.
	if level <= 0 {
		level = 7
	}
	lvl := strconv.Itoa(level)

	var attrs []byte
	add := func(b []byte) { attrs = append(attrs, b...) }
	add(ldapAttr("namingContexts", base, cfgNC, schemaNC,
		"DC=DomainDnsZones,"+base, "DC=ForestDnsZones,"+base))
	add(ldapAttr("defaultNamingContext", base))
	add(ldapAttr("rootDomainNamingContext", base))
	add(ldapAttr("configurationNamingContext", cfgNC))
	add(ldapAttr("schemaNamingContext", schemaNC))
	add(ldapAttr("dnsHostName", host))
	add(ldapAttr("ldapServiceName", domain+":"+short+"$@"+realm))
	add(ldapAttr("serverName", "CN="+upper+",CN=Servers,CN=Default-First-Site-Name,CN=Sites,"+cfgNC))
	add(ldapAttr("dsServiceName", "CN=NTDS Settings,CN="+upper+",CN=Servers,CN=Default-First-Site-Name,CN=Sites,"+cfgNC))
	add(ldapAttr("supportedLDAPVersion", "3", "2"))
	// AD forest/domain functional level (msDS-Behavior-Version), what AD-recon
	// tools read to gauge the domain's age + attack surface.
	add(ldapAttr("domainControllerFunctionality", lvl))
	add(ldapAttr("forestFunctionality", lvl))
	add(ldapAttr("domainFunctionality", lvl))
	add(ldapAttr("isGlobalCatalogReady", "TRUE"))
	add(ldapAttr("isSynchronized", "TRUE"))
	add(ldapAttr("supportedSASLMechanisms", "GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"))
	add(ldapAttr("supportedCapabilities", adCapabilityOIDs(level)...))

	// SearchResultEntry: objectName LDAPDN ("") + attributes SEQUENCE OF.
	entry := append(berOctet(""), berTLV(0x30, attrs)...)
	op := berTLV(0x64, entry) // [APPLICATION 4]
	body := append(encodeBERInt(messageID), op...)
	return berTLV(0x30, body)
}

// adCapabilityOIDs returns the supportedCapabilities LDAP_CAP_* OIDs a DC at the
// given functional level advertises — tools cross-check these against
// domainControllerFunctionality, so they grow with the level.
func adCapabilityOIDs(level int) []string {
	caps := []string{
		"1.2.840.113556.1.4.800",  // ACTIVE_DIRECTORY
		"1.2.840.113556.1.4.1670", // ACTIVE_DIRECTORY_V51
		"1.2.840.113556.1.4.1791", // ACTIVE_DIRECTORY_LDAP_INTEG
	}
	if level >= 4 { // 2008 R2+
		caps = append(caps, "1.2.840.113556.1.4.1935") // V61_R2
	}
	if level >= 5 { // 2012+
		caps = append(caps, "1.2.840.113556.1.4.2080") // V80
	}
	if level >= 6 { // 2012 R2+
		caps = append(caps, "1.2.840.113556.1.4.2237") // V81
	}
	return caps
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
