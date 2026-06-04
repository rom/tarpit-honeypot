package toolfp

import "testing"

// TestNewToolSignaturesBatch11 pins the eleventh batch of 50 HTTP UA
// fingerprints: banking-trojan/loader families, credential brute-force /
// stuffing / password-spray tools, web/API vuln scanners, and recon tooling.
func TestNewToolSignaturesBatch11(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// Banking-trojan / loader / RAT families -> "c2".
		{"Emotet", "emotet", "c2"},
		{"TrickBot", "trickbot", "c2"},
		{"Qakbot", "qakbot", "c2"},
		{"IcedID", "icedid", "c2"},
		{"Bumblebee", "bumblebee", "c2"},
		{"DarkGate", "darkgate", "c2"},
		{"Pikabot", "pikabot", "c2"},
		{"Latrodectus", "latrodectus", "c2"},
		// Credential brute-force / stuffing / password-spray -> "tool".
		{"OpenBullet", "openbullet", "tool"},
		{"SentryMBA", "sentry-mba", "tool"},
		{"SNIPR", "snipr", "tool"},
		{"SilverBullet", "silverbullet", "tool"},
		{"BlackBullet", "blackbullet", "tool"},
		{"Cr3dOv3r", "cr3dov3r", "tool"},
		{"CredMaster", "credmaster", "tool"},
		{"Spray365", "spray365", "tool"},
		{"MSOLSpray", "msolspray", "tool"},
		{"go365", "go365", "tool"},
		{"ruler", "ruler", "tool"},
		{"MailSniper", "mailsniper", "tool"},
		{"FireProx", "fireprox", "tool"},
		{"omnispray", "omnispray", "tool"},
		{"SmartBrute", "smartbrute", "tool"},
		{"legba", "legba", "tool"},
		{"cerbrutus", "cerbrutus", "tool"},
		// Web / API / injection vulnerability scanners -> "vuln-scanner".
		{"scan4all", "scan4all", "vuln-scanner"},
		{"dirmap", "dirmap", "vuln-scanner"},
		{"uniscan", "uniscan", "vuln-scanner"},
		{"webpwn3r", "webpwn3r", "vuln-scanner"},
		{"vulscan", "vulscan", "vuln-scanner"},
		{"jwtXploiter", "jwtxploiter", "vuln-scanner"},
		{"graphql-path-enum", "graphql-path-enum", "vuln-scanner"},
		{"batchql", "batchql", "vuln-scanner"},
		{"DSSS", "dsss", "vuln-scanner"},
		{"sqliv", "sqliv", "vuln-scanner"},
		// Recon / endpoint-discovery / secret-scraper tooling -> "tool".
		{"JSFinder", "jsfinder", "tool"},
		{"spyhunt", "spyhunt", "tool"},
		{"ReconCobra", "reconcobra", "tool"},
		{"sitedorks", "sitedorks", "tool"},
		{"TugaRecon", "tugarecon", "tool"},
		{"shhgit", "shhgit", "tool"},
		{"gitrob", "gitrob", "tool"},
		{"heritrix", "heritrix", "tool"},
		{"Nutch", "nutch", "tool"},
		{"webcopilot", "webcopilot", "tool"},
		{"urlhunter", "urlhunter", "tool"},
		{"porch-pirate", "porch-pirate", "tool"},
		{"swaggerhole", "swaggerhole", "tool"},
		{"APKHunt", "apkhunt", "tool"},
		{"githound", "githound", "tool"},
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
