package cve

import (
	"strings"
	"testing"
)

// TestKEVAuto2026WellFormed: every auto-derived KEV record must carry at least
// one exploit signature (the whole point of this batch is detection, not
// advisory listing), an http service, and an ATT&CK technique/tactic. CVSS must
// be a sane score. These are generated from CISA-KEV ∩ Nuclei, so a malformed
// entry means the generator drifted.
func TestKEVAuto2026WellFormed(t *testing.T) {
	if len(cveKEVAuto2026) == 0 {
		t.Fatal("cveKEVAuto2026 is empty")
	}
	for _, r := range cveKEVAuto2026 {
		if !strings.HasPrefix(r.ID, "CVE-") {
			t.Errorf("%s: not a CVE id", r.ID)
		}
		if len(r.Signatures) == 0 {
			t.Errorf("%s: KEV-auto record has no signatures", r.ID)
		}
		if r.Service != "http" {
			t.Errorf("%s: expected http service, got %q", r.ID, r.Service)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s: missing technique/tactic", r.ID)
		}
		if r.CVSS < 0 || r.CVSS > 10 {
			t.Errorf("%s: CVSS %v out of range", r.ID, r.CVSS)
		}
		if r.Name == "" || r.Description == "" {
			t.Errorf("%s: missing name/description", r.ID)
		}
	}
}

// TestKEVAuto2026Detects: a representative spread of the batch (across years and
// vendors) must actually fire through MatchPayload on its canonical exploit path
// and resolve through Lookup. If any of these regress, the catalog wiring or a
// signature has broken.
func TestKEVAuto2026Detects(t *testing.T) {
	cases := []struct {
		id, payload string
	}{
		{"CVE-2016-1555", "POST /boarddataww.php HTTP/1.1"},
		{"CVE-2017-3506", "GET /wls-wsat/registrationRequesterPortType HTTP/1.1"},
		{"CVE-2019-16278", "GET /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1"},
		{"CVE-2020-15415", "POST /cgi-bin/mainfunction.cgi/cvmcfgupload?1=2 HTTP/1.1"},
		{"CVE-2021-35464", "GET /openam/oauth2/..;/ccversion/Version HTTP/1.1"},
		{"CVE-2022-36804", "GET /rest/api/latest/projects/ HTTP/1.1"},
		{"CVE-2023-6549", "POST /nf/auth/startwebview.do HTTP/1.1"},
		{"CVE-2024-13159", "POST /WSVulnerabilityCore/VulCore.asmx HTTP/1.1"},
		{"CVE-2025-2775", "POST /mdm/checkin HTTP/1.1"},
		{"CVE-2026-34197", "GET /api/jolokia/ HTTP/1.1"},
	}
	for _, c := range cases {
		if _, ok := Lookup(c.id); !ok {
			t.Errorf("%s not in catalog", c.id)
			continue
		}
		if hits := MatchPayload("http", c.payload); !containsID(hits, c.id) {
			t.Errorf("%s: MatchPayload(%q) did not flag it; got %v", c.id, c.payload, ids(hits))
		}
	}
}
