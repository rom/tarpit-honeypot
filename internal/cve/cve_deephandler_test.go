package cve

import "testing"

// TestIntelAMTDigestBypassDetected locks in CVE-2017-5689: the Intel AMT
// auth bypass is recognized from an HTTP Digest authorization whose `response`
// value is empty (the firmware compares only the bytes the client sends), and
// must NOT fire on a normal non-empty digest response.
func TestIntelAMTDigestBypassDetected(t *testing.T) {
	bypass := "GET /index.htm HTTP/1.1\r\n" +
		"Authorization: Digest username=\"admin\", realm=\"Digest:A4070000\", " +
		"nonce=\"deadbeefcafebabe\", uri=\"/index.htm\", response=\"\"\r\n\r\n"
	if !matched(MatchPayload("intel_amt", bypass), "CVE-2017-5689") {
		t.Errorf("CVE-2017-5689 not detected on empty-digest-response request")
	}

	normal := "GET / HTTP/1.1\r\n" +
		"Authorization: Digest username=\"admin\", response=\"a1b2c3d4e5f60718\"\r\n\r\n"
	if matched(MatchPayload("intel_amt", normal), "CVE-2017-5689") {
		t.Errorf("CVE-2017-5689 false-positive on a non-empty digest response")
	}
}

// TestDeepHandlerAdvisoryRecords confirms the protocol CVEs detected inside
// their handlers (no request-payload signature) are catalogued advisory-only
// but still carry an ATT&CK mapping and a service.
func TestDeepHandlerAdvisoryRecords(t *testing.T) {
	for _, id := range []string{
		"CVE-2012-1675", // Oracle TNS Poison
		"CVE-2017-7650", // Mosquitto pattern-ACL bypass
		"CVE-2016-8704", // memcached append/prepend overflow
		"CVE-2016-8705", // memcached update overflow
		"CVE-2016-8706", // memcached SASL overflow
	} {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only (handler-detected, no payload signature)", id)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
		if r.Service == "" {
			t.Errorf("%s missing Service", id)
		}
	}
}

// TestDeepHandlerRound2Advisory covers the SSH supply-chain + Windows LDAP
// patch-level records: advisory-only (they activate client-side or need the
// attacker's key), with the right service and ATT&CK tagging.
func TestDeepHandlerRound2Advisory(t *testing.T) {
	want := map[string]string{
		"CVE-2024-3094":  "ssh",
		"CVE-2024-49112": "ldap",
		"CVE-2024-49113": "ldap",
	}
	for id, svc := range want {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only (no inbound request signature)", id)
		}
		if r.Service != svc {
			t.Errorf("%s: Service=%q want %q", id, r.Service, svc)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
	}
}

func matched(hits []Record, id string) bool {
	for _, h := range hits {
		if h.ID == id {
			return true
		}
	}
	return false
}
