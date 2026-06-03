package toolfp

import "testing"

// The 50+ new scanner / recon / brute-force / C2 fingerprints must be
// identified from the User-Agent, with the right category for the SOC pivot.
func TestNewToolSignatures(t *testing.T) {
	cases := []struct {
		ua, wantTool, wantCategory string
	}{
		{"wafw00f/2.2.0", "wafw00f", "vuln-scanner"},
		{"Mozilla/5.0 ssrfmap", "ssrfmap", "vuln-scanner"},
		{"routersploit", "routersploit", "vuln-scanner"},
		{"osmedeus-scanner", "osmedeus", "vuln-scanner"},
		{"garak/0.9 llm-scanner", "garak", "vuln-scanner"},
		{"trufflehog", "trufflehog", "tool"},
		{"netexec/1.1", "netexec", "tool"},
		{"crackmapexec", "crackmapexec", "tool"},
		{"chisel/1.9", "chisel", "tool"},
		{"gophish", "gophish", "tool"},
		{"evilginx2", "evilginx", "tool"},
		{"Merlin", "merlin", "c2"},
		{"Quasar Client", "quasar", "c2"},
		{"AsyncRAT", "asyncrat", "c2"},
		{"poshc2", "poshc2", "c2"},
		{"XMRig/6.21.0", "xmrig", "tool"},
		{"sublist3r", "sublist3r", "tool"},
		{"interactsh-client/1.0", "interactsh", "tool"},
	}
	for _, c := range cases {
		v := IdentifyHTTP(HTTPSignals{Method: "GET", Path: "/", UserAgent: c.ua})
		found := false
		for _, tl := range v.Tools {
			if tl == c.wantTool {
				found = true
			}
		}
		if !found {
			t.Errorf("UA %q: tool %q not identified (got %v)", c.ua, c.wantTool, v.Tools)
			continue
		}
		if v.Category != c.wantCategory {
			t.Errorf("UA %q: category = %q, want %q", c.ua, v.Category, c.wantCategory)
		}
		if !v.Automation {
			t.Errorf("UA %q: should be flagged automation", c.ua)
		}
	}
}
