package handler

// More protocol-parser fuzz targets (continued from protocol_parsers_fuzz_test.go),
// covering LDAP BER decoding, XMPP SASL PLAIN, Elasticsearch/HTTP content-length,
// IMAP argument splitting, webshell detection, RDP negotiation TLVs, QUIC header
// detection, SIP header extraction, PJL filesystem queries, and the WinRM HTTP
// request / Negotiate token decoders.
//
// Dumb targets assert "never panic / hang / read OOB"; smart targets seed with
// protocol-valid structures and assert bounds + determinism invariants (the BER
// decoders' whole job is to never read past a length-prefixed body).

import (
	"encoding/base64"
	"strings"
	"testing"
)

// --- dumb -------------------------------------------------------------------

func FuzzParseBERIntegerDumb(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x03})
	f.Add([]byte{0x02, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = parseBERInteger(data) })
}

func FuzzStripBERHeaderDumb(f *testing.F) {
	f.Add([]byte{0x05, 1, 2, 3, 4, 5})
	f.Add([]byte{0x81, 0x03, 1, 2, 3})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _, _ = stripBERHeader(data) })
}

func FuzzParseBindRequestDumb(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x03, 0x04, 0x03, 'a', 'b', 'c', 0x80, 0x02, 'p', 'w'})
	f.Add([]byte{})
	f.Add([]byte{0x02})
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _, _ = parseBindRequest(data) })
}

func FuzzXMPPDecodePLAINDumb(f *testing.F) {
	f.Add(`<auth xmlns="x">AGFkbWluAHB3</auth>`)
	f.Add(`<auth></auth>`)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) { _, _, _ = xmppDecodePLAIN(s) })
}

func FuzzParseContentLengthDumb(f *testing.F) {
	f.Add("Content-Length: 42")
	f.Add("content-length:   -1")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) { _, _ = parseContentLength(line) })
}

func FuzzSplitIMAPArgsDumb(f *testing.F) {
	f.Add(`"a" "b c" d`)
	f.Add(`"unterminated`)
	f.Fuzz(func(t *testing.T, s string) { _ = splitIMAPArgs(s) })
}

func FuzzDetectWebshellDumb(f *testing.F) {
	f.Add("/shell.php", []byte("cmd=id"))
	f.Add("/", []byte{})
	f.Fuzz(func(t *testing.T, path string, body []byte) {
		_, _ = detectWebshell(path, body, "application/x-www-form-urlencoded")
	})
}

func FuzzSplitPathQueryDumb(f *testing.F) {
	f.Add("/a/b?x=1&y=2")
	f.Add("?")
	f.Add("")
	f.Fuzz(func(t *testing.T, p string) { _, _ = splitPathQuery(p) })
}

func FuzzRDPNegReqDumb(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00})
	f.Add([]byte("Cookie: mstshash=user\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = findNegReq(data)
		_ = describeNegReq(data)
	})
}

func FuzzIsQUICLongHeaderDumb(f *testing.F) {
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _ = isQUICLongHeader(data) })
}

func FuzzSIPHeaderDumb(f *testing.F) {
	f.Add("INVITE sip:x SIP/2.0\nVia: SIP/2.0/UDP h\nFrom: <sip:a>\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		lines := strings.Split(raw, "\n")
		_ = sipHeader(lines, "Via")
		_ = sipHeader(lines, "From")
	})
}

func FuzzPJLFSQueryDumb(f *testing.F) {
	f.Add("@PJL FSDIRLIST NAME=\"0:\\\" ENTRY=1 COUNT=10")
	f.Add("@PJL")
	f.Fuzz(func(t *testing.T, line string) { _ = pjlFSQuery(line) })
}

func FuzzWinrmRequestDumb(f *testing.F) {
	f.Add([]byte("POST /wsman HTTP/1.1\r\nAuthorization: Negotiate TlRMTVNTUAA=\r\n\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, head []byte) {
		_ = winrmParseRequest(head, map[string]any{})
		_ = negotiateToken("Negotiate " + string(head))
	})
}

// --- smart: protocol-valid seeds + bounds / determinism invariants ----------

func FuzzStripBERHeaderSmart(f *testing.F) {
	f.Add([]byte{0x05, 1, 2, 3, 4, 5})          // short form, len 5
	f.Add([]byte{0x81, 0x03, 1, 2, 3})          // long form, 1 length byte
	f.Add([]byte{0x82, 0x00, 0x02, 0xaa, 0xbb}) // long form, 2 length bytes
	f.Fuzz(func(t *testing.T, data []byte) {
		_, hdrBytes, body, ok := stripBERHeader(data)
		if !ok {
			return
		}
		if hdrBytes < 1 || hdrBytes+len(body) > len(data) {
			t.Fatalf("stripBERHeader over-read: hdr=%d body=%d len=%d (%x)", hdrBytes, len(body), len(data), data)
		}
	})
}

func FuzzParseBERIntegerSmart(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x2a})
	f.Add([]byte{0x02, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, consumed, ok := parseBERInteger(data)
		if ok && (consumed < 2 || consumed > len(data)) {
			t.Fatalf("parseBERInteger consumed %d out of [2,%d] (%x)", consumed, len(data), data)
		}
	})
}

func ldapBindSeed() []byte {
	b := []byte{0x02, 0x01, 0x03} // version INTEGER 3
	b = append(b, 0x04, 0x08)     // name OCTET STRING len 8
	b = append(b, []byte("cn=admin")...)
	b = append(b, 0x80, 0x06) // simple password [0] len 6
	b = append(b, []byte("secret")...)
	return b
}

func FuzzParseBindRequestSmart(f *testing.F) {
	f.Add(ldapBindSeed())
	f.Add([]byte{0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}) // empty DN + empty PW
	f.Fuzz(func(t *testing.T, data []byte) {
		v1, dn1, pw1, m1 := parseBindRequest(data)
		v2, dn2, pw2, m2 := parseBindRequest(append([]byte(nil), data...))
		if v1 != v2 || dn1 != dn2 || pw1 != pw2 || m1 != m2 {
			t.Fatalf("parseBindRequest non-deterministic for %x", data)
		}
		// Extracted strings are slices of the input — never longer than it.
		if len(dn1) > len(data) || len(pw1) > len(data) || len(m1) > len(data) {
			t.Fatalf("parseBindRequest fabricated data: dn=%d pw=%d sasl=%d len=%d", len(dn1), len(pw1), len(m1), len(data))
		}
	})
}

func xmppPlainSeed() string {
	blob := base64.StdEncoding.EncodeToString([]byte("\x00admin\x00s3cr3t"))
	return `<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">` + blob + `</auth>`
}

func FuzzXMPPDecodePLAINSmart(f *testing.F) {
	f.Add(xmppPlainSeed())
	f.Add(`<auth>` + base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")) + `</auth>`)
	f.Fuzz(func(t *testing.T, s string) {
		u1, p1, ok1 := xmppDecodePLAIN(s)
		u2, p2, ok2 := xmppDecodePLAIN(s)
		if u1 != u2 || p1 != p2 || ok1 != ok2 {
			t.Fatalf("xmppDecodePLAIN non-deterministic for %q", s)
		}
		if ok1 && (strings.ContainsRune(u1, 0) || strings.ContainsRune(p1, 0)) {
			t.Fatalf("decoded user/pass retained a NUL separator: %q / %q", u1, p1)
		}
	})
}
