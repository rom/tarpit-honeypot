package cve

import (
	"strings"
	"testing"
)

// TestNewVulnCohortPresent confirms the Danfoss + 2026 web/PHP additions are in
// the catalog with a well-formed ATT&CK mapping and enrichment.
func TestNewVulnCohortPresent(t *testing.T) {
	ids := []string{
		// PHP2Shell + related 2026 engine/web CVEs.
		"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560",
		"CVE-2026-119977", "CVE-2026-111497", "CVE-2026-97229", "CVE-2026-46300",
		// Danfoss refrigeration / drive controllers.
		"CVE-2025-41450", "CVE-2025-41451", "CVE-2025-41452",
		"CVE-2023-25913", "CVE-2023-25914", "CVE-2023-25915",
		"CVE-2023-22583", "CVE-2023-22584", "CVE-2023-22585",
		"CVE-2023-22586", "CVE-2023-25911", "CVE-2023-25912",
		"CVE-2026-15203",
	}
	for _, id := range ids {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
		if r.Service == "" {
			t.Errorf("%s missing Service", id)
		}
		if len(r.CWE) == 0 {
			t.Errorf("%s missing CWE enrichment", id)
		}
	}
}

// TestDanfossServiceBinding checks the Danfoss CVEs are bound to the
// danfoss_aksm handler service so ForService drives version/patch emulation.
func TestDanfossServiceBinding(t *testing.T) {
	recs := ForService("danfoss_aksm")
	if len(recs) < 10 {
		t.Fatalf("ForService(danfoss_aksm) = %d records; want >=10", len(recs))
	}
	want := map[string]bool{"CVE-2025-41450": false, "CVE-2025-41451": false, "CVE-2025-41452": false, "CVE-2026-15203": false}
	for _, r := range recs {
		if _, ok := want[r.ID]; ok {
			want[r.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("%s not returned by ForService(danfoss_aksm)", id)
		}
	}
}

// TestDanfoss2023TraversalDetectable confirms the AK-SM 800A xml.cgi traversal
// (CVE-2023-25914) is recognized by MatchPayload on its signature.
func TestDanfoss2023TraversalDetectable(t *testing.T) {
	hits := MatchPayload("danfoss_aksm", "GET /xml.cgi?../../../../etc/passwd HTTP/1.1")
	found := false
	for _, h := range hits {
		if h.ID == "CVE-2023-25914" {
			found = true
		}
	}
	if !found {
		t.Errorf("CVE-2023-25914 not detected; hits=%v", ids(hits))
	}
}

// TestPHP2ShellAdvisoryOnly confirms the PHP2Shell catalog records carry no
// MatchPayload signatures (detection lives in the vulnweb handler, so the
// forward-looking 2026 records can never mis-tag raw banner traffic).
func TestPHP2ShellAdvisoryOnly(t *testing.T) {
	for _, id := range []string{"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560", "CVE-2026-119977"} {
		r, _ := Lookup(id)
		if r.Detectable() {
			t.Errorf("%s should be advisory-only (handler-detected), has signatures", id)
		}
		if !strings.HasPrefix(r.CPE, "cpe:2.3:") {
			t.Errorf("%s CPE not 2.3 form: %q", id, r.CPE)
		}
	}
}
