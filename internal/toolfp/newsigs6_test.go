package toolfp

import "testing"

// TestNewToolSignaturesBatch6 pins the sixth batch of 25 web-injection / WAF /
// OSINT-engine / recon fingerprints: each UA must identify the expected tool
// and resolve to the right severity category.
func TestNewToolSignaturesBatch6(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// SQL-injection / web-exploit / secret-file scanners → "vuln-scanner".
		{"WAFNinja", "wafninja", "vuln-scanner"},
		{"sqlninja", "sqlninja", "vuln-scanner"},
		{"BBQSQL", "bbqsql", "vuln-scanner"},
		{"jSQL Injection", "jsql", "vuln-scanner"},
		{"snallygaster", "snallygaster", "vuln-scanner"},
		{"YAWAST/0.11", "yawast", "vuln-scanner"},
		// WAF / origin / web recon → "tool".
		{"whatwaf", "whatwaf", "tool"},
		{"identYwaf", "identywaf", "tool"},
		{"CloudFlair", "cloudflair", "tool"},
		{"VHostScan", "vhostscan", "tool"},
		// Interception / MITM → "tool".
		{"cadaver/0.23.3", "cadaver", "tool"},
		{"mitmproxy/9.0", "mitmproxy", "tool"},
		{"bettercap", "bettercap", "tool"},
		// Internet-wide search-engine clients → "tool".
		{"fofa", "fofa", "tool"},
		{"ZoomEye", "zoomeye", "tool"},
		{"netlas", "netlas", "tool"},
		{"FullHunt", "fullhunt", "tool"},
		// OSINT / recon frameworks + dorking + DNS enum → "tool".
		{"Raccoon", "raccoon", "tool"},
		{"sn0int", "sn0int", "tool"},
		{"infoga", "infoga", "tool"},
		{"metagoofil", "metagoofil", "tool"},
		{"pagodo", "pagodo", "tool"},
		{"sudomy", "sudomy", "tool"},
		{"dnsenum", "dnsenum", "tool"},
		{"WPForce", "wpforce", "tool"},
	}
	if len(cases) != 25 {
		t.Fatalf("expected 25 new signatures in this batch, have %d", len(cases))
	}
	for _, c := range cases {
		v := IdentifyHTTP(HTTPSignals{Method: "GET", Path: "/", UserAgent: c.ua})
		ok := false
		for _, tl := range v.Tools {
			if tl == c.tool {
				ok = true
			}
		}
		if !ok {
			t.Errorf("UA %q: %q not identified (%v)", c.ua, c.tool, v.Tools)
		} else if v.Category != c.cat {
			t.Errorf("UA %q: category %q, want %q (tools %v)", c.ua, v.Category, c.cat, v.Tools)
		}
	}
}
