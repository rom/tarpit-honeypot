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
		"CVE-2023-2953":  "ldap", // OpenLDAP slapd NULL-deref DoS
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

// TestICEFALLRecords covers the OT:ICEFALL ProConOS + Omron FINS records:
// advisory-only catalog entries (the handlers emit them in-protocol), with the
// correct service and ICS ATT&CK tagging.
func TestICEFALLRecords(t *testing.T) {
	want := map[string]string{
		"CVE-2022-31801": "proconos",
		"CVE-2022-31800": "proconos",
		"CVE-2022-31207": "fins",
		"CVE-2022-31204": "fins",
	}
	for id, svc := range want {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Service != svc {
			t.Errorf("%s: Service=%q want %q", id, r.Service, svc)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only (handler-emitted, no payload signature)", id)
		}
	}
}

// TestTRITONRecord covers the Triconex/TRITON safety-system CVE: handler-
// emitted (advisory), correct service, ICS ATT&CK tagged.
func TestTRITONRecord(t *testing.T) {
	r, ok := Lookup("CVE-2018-8872")
	if !ok {
		t.Fatal("CVE-2018-8872 (TRITON) missing from catalog")
	}
	if r.Service != "tristation" {
		t.Errorf("TRITON service = %q want tristation", r.Service)
	}
	if r.Detectable() {
		t.Errorf("CVE-2018-8872 should be advisory-only (handler-emitted)")
	}
	if r.Technique == "" || r.Tactic == "" {
		t.Errorf("CVE-2018-8872 missing ATT&CK mapping")
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
