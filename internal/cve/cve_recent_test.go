package cve

import "testing"

// TestMatchPayloadRecentWebExploits locks in detection of the 2023-2025
// additions: each carries a distinctive request signature.
func TestMatchPayloadRecentWebExploits(t *testing.T) {
	cases := []struct {
		name, handler, req, want string
	}{
		{"Confluence SSTI", "http",
			"POST /template/aui/text-inline.vm HTTP/1.1\r\n\r\nlabel=x", "CVE-2023-22527"},
		{"Check Point traversal", "http",
			"POST /clients/MyCRL HTTP/1.1\r\n\r\naCSHELL/../../../../etc/shadow", "CVE-2024-24919"},
		{"PAN-OS auth bypass", "http",
			"POST /php/utils/createRemoteAppwebSession.php HTTP/1.1\r\n\r\n", "CVE-2024-0012"},
		{"HFS template RCE", "http",
			"GET /?search=%7B.exec%7Cwhoami.%7D HTTP/1.0\r\n\r\n{.exec|whoami.}", "CVE-2024-23692"},
		{"GeoServer OGC RCE", "http",
			"GET /geoserver/wfs?valueReference=exec(java.lang.Runtime.getRuntime()) HTTP/1.1\r\n\r\n", "CVE-2024-36401"},
		{"Bricks Builder RCE", "http",
			"POST /wp-json/bricks/v1/render_element HTTP/1.1\r\n\r\n", "CVE-2024-25600"},
		{"TP-Link Archer cmdi", "http",
			"POST /cgi-bin/luci HTTP/1.1\r\n\r\noperation=write&country=$(id)", "CVE-2023-1389"},
		{"Serv-U traversal", "http",
			"GET /?InternalDir=../../../../&InternalFile=x HTTP/1.1\r\n\r\n", "CVE-2024-28995"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.handler, c.req)
		found := false
		for _, h := range hits {
			if h.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected %s; got %+v", c.name, c.want, hits)
		}
	}
}

// TestRecentAdvisoryRecords confirms the binary/handshake exploits are present
// as advisory-only (no payload signature) but still ATT&CK-tagged.
func TestRecentAdvisoryRecords(t *testing.T) {
	for _, id := range []string{"CVE-2023-48795", "CVE-2024-21762", "CVE-2025-22457"} {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only (no signatures)", id)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
	}
}
