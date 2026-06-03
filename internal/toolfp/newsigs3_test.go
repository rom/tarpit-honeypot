package toolfp

import "testing"

// TestNewToolSignaturesBatch3 pins the AD / post-exploitation / web-exploit /
// DNS-C2 fingerprints added in the third batch: each UA must identify the
// expected tool and resolve to the right severity category.
func TestNewToolSignaturesBatch3(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// AD / Windows post-exploitation → "tool".
		{"kerbrute/v1.0.3", "kerbrute", "tool"},
		{"smbmap", "smbmap", "tool"},
		{"enum4linux-ng", "enum4linux", "tool"},
		{"Evil-WinRM", "evil-winrm", "tool"},
		{"impacket/0.11", "impacket", "tool"},
		{"BloodHound", "bloodhound", "tool"},
		{"Certipy v4.8.2", "certipy", "tool"},
		{"windapsearch", "windapsearch", "tool"},
		// Web / API exploit scanners → "vuln-scanner".
		{"graphw00f/1.1.0", "graphw00f", "tool"},
		{"GraphQLmap", "graphqlmap", "vuln-scanner"},
		{"log4j-scan/1.0", "log4j-scanner", "vuln-scanner"},
		{"struts-pwn", "struts-pwn", "vuln-scanner"},
		{"fuxploider", "fuxploider", "vuln-scanner"},
		{"shortscan/0.9", "shortscan", "vuln-scanner"},
		{"DAVTest/1.0", "davtest", "vuln-scanner"},
		{"magescan", "magescan", "vuln-scanner"},
		{"aem-hacker", "aem-hacker", "vuln-scanner"},
		{"wprecon", "wprecon", "vuln-scanner"},
		{"byp4xx", "byp4xx", "vuln-scanner"},
		{"h2csmuggler", "h2csmuggler", "vuln-scanner"},
		// Crawlers / fingerprinters → "tool".
		{"crawlergo", "crawlergo", "tool"},
		{"webanalyze/0.4", "webanalyze", "tool"},
		// DNS / HTTP C2 → highest-severity "c2".
		{"dnscat", "dnscat2", "c2"},
		{"hoaxshell", "hoaxshell", "c2"},
		{"Manjusaka", "manjusaka", "c2"},
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
			t.Errorf("UA %q: category %q, want %q", c.ua, v.Category, c.cat)
		}
	}
}
