package toolfp

import "testing"

// TestNewToolSignaturesBatch5 pins the fifth batch of 30 web-exploit / API /
// OSINT / recon-framework / cloud fingerprints: each UA must identify the
// expected tool and resolve to the right severity category.
func TestNewToolSignaturesBatch5(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// Web / API exploit + injection scanners → "vuln-scanner".
		{"Gxss", "gxss", "vuln-scanner"},
		{"kxss", "kxss", "vuln-scanner"},
		{"ppfuzz/1.0", "ppfuzz", "vuln-scanner"},
		{"ppmap", "ppmap", "vuln-scanner"},
		{"Gopherus", "gopherus", "vuln-scanner"},
		{"DirDar", "dirdar", "vuln-scanner"},
		{"wpprobe", "wpprobe", "vuln-scanner"},
		{"JoomlaVS", "joomlavs", "vuln-scanner"},
		{"drupwn", "drupwn", "vuln-scanner"},
		{"graphql-cop", "graphql-cop", "vuln-scanner"},
		{"akto", "akto", "vuln-scanner"},
		// JS / CSP / endpoint discovery → "tool".
		{"csprecon", "csprecon", "tool"},
		{"mantra", "mantra", "tool"},
		{"jsluice", "jsluice", "tool"},
		{"uddup", "uddup", "tool"},
		// Recon frameworks → "tool".
		{"AutoRecon", "autorecon", "tool"},
		{"reconftw", "reconftw", "tool"},
		{"reNgine", "rengine", "tool"},
		{"FavFreak", "favfreak", "tool"},
		// People / account / breach OSINT → "tool".
		{"h8mail", "h8mail", "tool"},
		{"holehe", "holehe", "tool"},
		{"maigret", "maigret", "tool"},
		{"sherlock", "sherlock", "tool"},
		{"GHunt", "ghunt", "tool"},
		{"dnstwist", "dnstwist", "tool"},
		// GraphQL tooling → "tool".
		{"InQL", "inql", "tool"},
		{"clairvoyance", "clairvoyance", "tool"},
		{"CrackQL", "crackql", "tool"},
		// Cloud / IAM enumeration → "tool".
		{"CloudFox", "cloudfox", "tool"},
		{"enumerate-iam", "enumerate-iam", "tool"},
	}
	if len(cases) != 30 {
		t.Fatalf("expected 30 new signatures in this batch, have %d", len(cases))
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
