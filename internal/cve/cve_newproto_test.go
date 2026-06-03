package cve

import "testing"

// The appliance/framework CVEs added for the new Lua personas must be detected
// over plain http too (the http handler runs MatchPayload), and the advisory
// SLP amplification CVE must be present but non-detectable.
func TestNewProtocolCVEs(t *testing.T) {
	cases := []struct {
		service, payload, wantID string
	}{
		{"http", "GET /cf_scripts/scripts/ajax/ckeditor/x HTTP/1.1\r\n\r\n", "CVE-2023-26360"},
		{"http", "GET /setup/setup-/%u002e%u002e/log.jsp HTTP/1.1\r\n\r\n", "CVE-2023-32315"},
		{"http", "GET /photo/p/api/video.php HTTP/1.1\r\n\r\n", "CVE-2022-27593"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.service, c.payload)
		found := false
		for _, h := range hits {
			if h.ID == c.wantID {
				found = true
			}
		}
		if !found {
			t.Errorf("%s payload should detect %s, got %v", c.service, c.wantID, hits)
		}
	}

	// SLP CVE is advisory-only (no signatures) — present in the catalog but not
	// flagged as a live payload match.
	rec, ok := Lookup("CVE-2023-29552")
	if !ok {
		t.Fatal("CVE-2023-29552 missing from catalog")
	}
	if rec.Detectable() {
		t.Error("CVE-2023-29552 should be advisory-only (no signatures)")
	}
}
