package toolfp

import "testing"

// TestNewToolSignaturesBatch8 pins the eighth batch of 50 web-exploit / AD /
// cloud / OSINT / C2 fingerprints.
func TestNewToolSignaturesBatch8(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// Web injection / LFI / XXE / SQLi → "vuln-scanner".
		{"DotDotPwn", "dotdotpwn", "vuln-scanner"},
		{"panoptic", "panoptic", "vuln-scanner"},
		{"XXEinjector", "xxeinjector", "vuln-scanner"},
		{"blisqy", "blisqy", "vuln-scanner"},
		{"kadimus", "kadimus", "vuln-scanner"},
		{"liffy", "liffy", "vuln-scanner"},
		{"retireJS", "retirejs", "vuln-scanner"},
		// Proxies / fingerprint / panel + content discovery → "tool".
		{"Caido", "caido", "tool"},
		{"wappalyzer", "wappalyzer", "tool"},
		{"cangibrina", "cangibrina", "tool"},
		{"breacher", "breacher", "tool"},
		{"rustbuster", "rustbuster", "tool"},
		{"filebuster", "filebuster", "tool"},
		// .NET / secret cracking → "tool".
		{"viewgen", "viewgen", "tool"},
		{"badsecrets", "badsecrets", "tool"},
		{"blacklist3r", "blacklist3r", "tool"},
		// Kubernetes / container → "tool".
		{"kubeletctl", "kubeletctl", "tool"},
		{"peirates", "peirates", "tool"},
		{"kdigger", "kdigger", "tool"},
		{"amicontained", "amicontained", "tool"},
		{"deepce", "deepce", "tool"},
		// Cloud → "tool".
		{"cloudsplaining", "cloudsplaining", "tool"},
		{"PMapper", "pmapper", "tool"},
		{"stormspotter", "stormspotter", "tool"},
		{"AzureHound", "azurehound", "tool"},
		{"ROADrecon", "roadrecon", "tool"},
		{"o365spray", "o365spray", "tool"},
		{"TeamFiltration", "teamfiltration", "tool"},
		{"TREVORspray", "trevorspray", "tool"},
		// AD / LDAP / SMB → "tool".
		{"RustHound", "rusthound", "tool"},
		{"SOAPHound", "soaphound", "tool"},
		{"ldeep", "ldeep", "tool"},
		{"ManSpider", "manspider", "tool"},
		{"SMBeagle", "smbeagle", "tool"},
		{"Snaffler", "snaffler", "tool"},
		{"DFSCoerce", "dfscoerce", "tool"},
		{"pyWhisker", "pywhisker", "tool"},
		{"masky", "masky", "tool"},
		{"adidnsdump", "adidnsdump", "tool"},
		{"ldapnomnom", "ldapnomnom", "tool"},
		// OSINT / username / phone → "tool".
		{"reconspider", "reconspider", "tool"},
		{"FinalRecon", "finalrecon", "tool"},
		{"blackbird", "blackbird", "tool"},
		{"nexfil", "nexfil", "tool"},
		{"toutatis", "toutatis", "tool"},
		{"PhoneInfoga", "phoneinfoga", "tool"},
		// Phishing → "tool".
		{"evilgophish", "evilgophish", "tool"},
		// C2 → "c2".
		{"slackor", "slackor", "c2"},
		{"toxssin", "toxssin", "c2"},
		{"trevorc2", "trevorc2", "c2"},
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
