package handler

import "testing"

// ldapSearchFilter builds an LDAPMessage: SearchRequest with a non-empty
// baseObject and a single equalityMatch filter (attr=val), so the assertion
// value `val` lands in the request as a literal octet string.
func ldapSearchFilter(msgID byte, attr, val string) []byte {
	eq := []byte{0x04, byte(len(attr))}
	eq = append(eq, attr...)
	eq = append(eq, 0x04, byte(len(val)))
	eq = append(eq, val...)
	filter := append([]byte{0xA3, byte(len(eq))}, eq...) // equalityMatch [3]

	base := "dc=x"
	body := []byte{0x04, byte(len(base))}
	body = append(body, base...)
	body = append(body,
		0x0a, 0x01, 0x00, // scope
		0x0a, 0x01, 0x00, // derefAliases
		0x02, 0x01, 0x00, // sizeLimit
		0x02, 0x01, 0x00, // timeLimit
		0x01, 0x01, 0x00, // typesOnly
	)
	body = append(body, filter...)
	body = append(body, 0x30, 0x00) // attributes (empty)
	op := append([]byte{0x63, byte(len(body))}, body...)
	msg := append([]byte{0x02, 0x01, msgID}, op...)
	return append([]byte{0x30, byte(len(msg))}, msg...)
}

// ldapUnbindMsg is an LDAPMessage UnbindRequest [APPLICATION 2], which makes
// the handler return promptly instead of waiting out the read timeout.
func ldapUnbindMsg(msgID byte) []byte {
	return []byte{0x30, 0x05, 0x02, 0x01, msgID, 0x42, 0x00}
}

func TestLDAPFilterInjectionDetected(t *testing.T) {
	in := append(ldapSearchFilter(2, "sAMAccountName", "admin*)(uid=*"), ldapUnbindMsg(3)...)
	res, _ := roundtrip(t, &ldap{}, string(in))
	if !hasAnom(res, "ldap-injection") {
		t.Errorf("LDAP filter injection not flagged: %v", res.Meta["anomalies"])
	}
}

func TestLDAPNormalSearchNotInjection(t *testing.T) {
	in := append(ldapSearchFilter(2, "sAMAccountName", "jdoe"), ldapUnbindMsg(3)...)
	res, _ := roundtrip(t, &ldap{}, string(in))
	if hasAnom(res, "ldap-injection") {
		t.Errorf("benign search wrongly flagged as LDAP injection: %v", res.Meta["anomalies"])
	}
}

func TestLDAPMalformedBER(t *testing.T) {
	// A framed-but-unparseable LDAPMessage (SEQUENCE whose contents aren't a
	// valid messageID INTEGER) — the crafted-request shape of the slapd DoS class.
	res, _ := roundtrip(t, &ldap{}, string([]byte{0x30, 0x03, 0xff, 0xff, 0xff}))
	if !hasAnom(res, "ldap-malformed-ber") {
		t.Errorf("malformed LDAP/BER not flagged: %v", res.Meta["anomalies"])
	}
}
