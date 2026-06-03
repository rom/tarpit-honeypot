package cve

import (
	"testing"
)

// TestCiscoMoxaCoverage pins the Cisco / Cisco ASA / Moxa device CVEs added to
// the catalog: each must be present, well-formed, and reachable via Lookup, and
// the detectable WebVPN/router ones must fire on their signatures.
func TestCiscoMoxaCoverage(t *testing.T) {
	want := []string{
		// Cisco ASA / FTD
		"CVE-2018-0101", "CVE-2018-0296", "CVE-2020-3187", "CVE-2018-15454",
		"CVE-2021-1585", "CVE-2022-20829", "CVE-2023-20269", "CVE-2024-20353",
		"CVE-2024-20359", "CVE-2016-6366",
		// Cisco IOS / IOS-XE / routers / HyperFlex
		"CVE-2023-20273", "CVE-2017-3881", "CVE-2017-6736", "CVE-2019-1652",
		"CVE-2023-20025", "CVE-2022-20708", "CVE-2020-3118", "CVE-2021-1497",
		// Moxa
		"CVE-2016-9361", "CVE-2017-14459", "CVE-2020-25198", "CVE-2020-25196",
		"CVE-2019-10963", "CVE-2016-8350", "CVE-2021-39279",
	}
	if len(want) != 25 {
		t.Fatalf("expected 25 new vendor CVEs, listed %d", len(want))
	}
	for _, id := range want {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Service == "" || r.Technique == "" || r.Tactic == "" || r.Description == "" {
			t.Errorf("%s under-specified: %+v", id, r)
		}
		if len(r.CWE) == 0 || r.CPE == "" {
			t.Errorf("%s missing CWE/CPE enrichment", id)
		}
	}

	// The Cisco ASA WebVPN traversal must be detected from its URL signature on
	// the http handler.
	hits := MatchPayload("http", "GET /+CSCOU+/../+CSCOE+/session_password.html HTTP/1.0")
	if !containsID(hits, "CVE-2018-0296") {
		t.Errorf("ASA WebVPN traversal not detected: %v", ids(hits))
	}
	// The Cisco RV320 command injection fires on its certificate endpoint.
	if hits := MatchPayload("http", "POST /certificate_handle.cgi HTTP/1.1"); !containsID(hits, "CVE-2019-1652") {
		t.Errorf("RV320 command injection not detected: %v", ids(hits))
	}
}
