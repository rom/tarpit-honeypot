package toolfp

import "testing"

// TestNewToolSignaturesBatch7 pins the seventh batch of 50 web-exploit / API /
// AD / cloud / recon / C2 fingerprints.
func TestNewToolSignaturesBatch7(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// Web injection / XSS / redirect / cache / NoSQL → "vuln-scanner".
		{"ghauri", "ghauri", "vuln-scanner"},
		{"SSTImap", "sstimap", "vuln-scanner"},
		{"tinja", "tinja", "vuln-scanner"},
		{"XSSer", "xsser", "vuln-scanner"},
		{"XSpear", "xspear", "vuln-scanner"},
		{"Oralyzer", "oralyzer", "vuln-scanner"},
		{"OpenRedireX", "openredirex", "vuln-scanner"},
		{"crlfsuite", "crlfsuite", "vuln-scanner"},
		{"wcvs", "wcvs", "vuln-scanner"},
		{"mongoaudit", "mongoaudit", "vuln-scanner"},
		{"domdig", "domdig", "vuln-scanner"},
		// JWT attack tooling → "tool".
		{"jwt_tool", "jwt-tool", "tool"},
		{"jwt-cracker", "jwt-cracker", "tool"},
		{"jwt-hack", "jwt-hack", "tool"},
		// AD / Windows / Kerberos → "tool".
		{"ldapdomaindump", "ldapdomaindump", "tool"},
		{"PingCastle", "pingcastle", "tool"},
		{"ADRecon", "adrecon", "tool"},
		{"bloodyAD", "bloodyad", "tool"},
		{"pre2k", "pre2k", "tool"},
		{"targetedKerberoast", "targetedkerberoast", "tool"},
		{"krbrelayx", "krbrelayx", "tool"},
		{"certsync", "certsync", "tool"},
		{"spraycharles", "spraycharles", "tool"},
		{"snmpwn", "snmpwn", "tool"},
		// Cloud / bucket enumeration → "tool".
		{"CloudBrute", "cloudbrute", "tool"},
		{"GCPBucketBrute", "gcpbucketbrute", "tool"},
		{"cloud_enum", "cloud_enum", "tool"},
		{"festin", "festin", "tool"},
		{"S3Enum", "s3enum", "tool"},
		{"cf-hero", "cf-hero", "tool"},
		// Subdomain takeover + DNS / asset recon → "tool".
		{"dnsReaper", "dnsreaper", "tool"},
		{"subzy", "subzy", "tool"},
		{"subjack", "subjack", "tool"},
		{"Scilla", "scilla", "tool"},
		{"haktrails", "haktrails", "tool"},
		{"tldfinder", "tldfinder", "tool"},
		{"shosubgo", "shosubgo", "tool"},
		{"github-subdomains", "github-subdomains", "tool"},
		{"alterx", "alterx", "tool"},
		{"gotator", "gotator", "tool"},
		{"ripgen", "ripgen", "tool"},
		{"bgpview", "bgpview", "tool"},
		// Crawlers / discovery → "tool".
		{"galer", "galer", "tool"},
		{"urldedupe", "urldedupe", "tool"},
		{"dorkscout", "dorkscout", "tool"},
		// Port scanners → "tool".
		{"NimScan", "nimscan", "tool"},
		{"sandmap", "sandmap", "tool"},
		{"threader3000", "threader3000", "tool"},
		// C2 → "c2".
		{"HardHatC2", "hardhatc2", "c2"},
		{"AdaptixC2", "adaptixc2", "c2"},
	}
	if len(cases) != 50 {
		t.Fatalf("expected 50 new signatures in this batch, have %d", len(cases))
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
