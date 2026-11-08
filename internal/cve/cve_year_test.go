package cve

import (
	"strings"
	"testing"
)

// TestRecent2025And2026Coverage checks the freshly-added year cohorts: at least
// 30 from each of 2025 and 2026, and a couple of 2025 signatures fire.
//
// The 2026 cohort is mixed by design. The original hand-seeded 2026 entries are
// FORWARD-LOOKING placeholders generated from recurring vendor vulnerability
// classes; those stay advisory-only (no payload signature) so a guessed pattern
// can never mis-tag live traffic. The cveKEVAuto2026 batch, by contrast, is real
// CISA-KEV CVEs confirmed exploited in the wild, each paired with an actual
// Nuclei exploit path — those are legitimately detectable. So the invariant is
// not "no 2026 record detects" but "only the real KEV-backed 2026 records do;
// the speculative placeholders remain advisory-only."
func TestRecent2025And2026Coverage(t *testing.T) {
	kevAuto := make(map[string]bool, len(cveKEVAuto2026))
	for _, r := range cveKEVAuto2026 {
		kevAuto[r.ID] = true
	}

	var n2025, n2026, detectableKEV2026 int
	for _, r := range All() {
		switch {
		case strings.HasPrefix(r.ID, "CVE-2025-"):
			n2025++
		case strings.HasPrefix(r.ID, "CVE-2026-"):
			n2026++
			if r.Detectable() {
				if !kevAuto[r.ID] {
					// A speculative placeholder must never carry a signature.
					t.Errorf("forward-looking 2026 placeholder %s is detectable; placeholders must be advisory-only", r.ID)
				} else {
					detectableKEV2026++
				}
			}
		}
	}
	if n2025 < 30 {
		t.Errorf("want >=30 CVE-2025 records, have %d", n2025)
	}
	if n2026 < 30 {
		t.Errorf("want >=30 CVE-2026 records, have %d", n2026)
	}
	if detectableKEV2026 == 0 {
		t.Error("expected the real KEV-backed 2026 records to be detectable, found none")
	}

	// A few 2025 detections must fire on their signatures.
	if hits := MatchPayload("http", "POST /developmentserver/metadatauploader HTTP/1.1"); !containsID(hits, "CVE-2025-31324") {
		t.Errorf("SAP NetWeaver upload not detected: %v", ids(hits))
	}
	if hits := MatchPayload("http", "GET /_layouts/15/ToolPane.aspx?DisplayMode=Edit HTTP/1.1"); !containsID(hits, "CVE-2025-53770") {
		t.Errorf("SharePoint ToolShell not detected: %v", ids(hits))
	}
	if hits := MatchPayload("http", "POST /api/v1/validate/code HTTP/1.1"); !containsID(hits, "CVE-2025-3248") {
		t.Errorf("Langflow RCE not detected: %v", ids(hits))
	}

	// And a real KEV-backed 2026 record fires on its Nuclei-sourced exploit path.
	if hits := MatchPayload("http", "GET /psemhub/hub HTTP/1.1"); !containsID(hits, "CVE-2026-35273") {
		t.Errorf("PeopleSoft PeopleTools KEV detection not firing: %v", ids(hits))
	}
}
