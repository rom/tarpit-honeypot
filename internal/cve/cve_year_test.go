package cve

import (
	"strings"
	"testing"
)

// TestRecent2025And2026Coverage checks the freshly-added year cohorts: at least
// 30 from each of 2025 and 2026, a couple of 2025 signatures fire, and every
// 2026 entry is advisory-only (no payload signature) so the forward-looking
// placeholders can never mis-tag live traffic.
func TestRecent2025And2026Coverage(t *testing.T) {
	var n2025, n2026, detectable2026 int
	for _, r := range All() {
		switch {
		case strings.HasPrefix(r.ID, "CVE-2025-"):
			n2025++
		case strings.HasPrefix(r.ID, "CVE-2026-"):
			n2026++
			if r.Detectable() {
				detectable2026++
			}
		}
	}
	if n2025 < 30 {
		t.Errorf("want >=30 CVE-2025 records, have %d", n2025)
	}
	if n2026 < 30 {
		t.Errorf("want >=30 CVE-2026 records, have %d", n2026)
	}
	if detectable2026 != 0 {
		t.Errorf("the 2026 placeholders must be advisory-only (no signatures); %d carry signatures", detectable2026)
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
}
