package toolfp

import "testing"

// TestNewToolSignaturesBatch10 pins the tenth batch of 100 fingerprints:
// C2/RAT/loader families, web/CMS/API/mobile vuln scanners, AD/Windows
// post-exploitation, cloud/k8s/IaC auditors, and OSINT/recon tooling.
func TestNewToolSignaturesBatch10(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// C2 / RAT / loader families -> "c2".
		{"Nighthawk", "nighthawk", "c2"},
		{"nuages", "nuages", "c2"},
		{"Remcos", "remcos", "c2"},
		{"DCRat", "dcrat", "c2"},
		{"VenomRAT", "venomrat", "c2"},
		{"XWorm", "xworm", "c2"},
		{"LimeRAT", "limerat", "c2"},
		{"RevengeRAT", "revengerat", "c2"},
		{"Warzone", "warzonerat", "c2"},
		{"NetWire", "netwire", "c2"},
		{"NanoCore", "nanocore", "c2"},
		{"Orcus", "orcus", "c2"},
		{"DarkComet", "darkcomet", "c2"},
		{"SpyNote", "spynote", "c2"},
		{"AgentTesla", "agenttesla", "c2"},
		{"FormBook", "formbook", "c2"},
		{"SmokeLoader", "smokeloader", "c2"},
		{"msfvenom", "metasploit", "c2"},
		// Web / CMS / API / mobile vulnerability + injection scanners -> "vuln-scanner".
		{"moodlescan", "moodlescan", "vuln-scanner"},
		{"CMSScan", "cmsscan", "vuln-scanner"},
		{"scant3r", "scant3r", "vuln-scanner"},
		{"403fuzzer", "403fuzzer", "vuln-scanner"},
		{"headerpwn", "headerpwn", "vuln-scanner"},
		{"smugglefuzz", "smugglefuzz", "vuln-scanner"},
		{"paramminer", "param-miner", "vuln-scanner"},
		{"spring4shell", "spring4shell-scan", "vuln-scanner"},
		{"fastjson-scan", "fastjson-scan", "vuln-scanner"},
		{"shiroscan", "shiro-scan", "vuln-scanner"},
		{"WPIntel", "wpintel", "vuln-scanner"},
		{"apkleaks", "apkleaks", "vuln-scanner"},
		{"MobSF", "mobsf", "vuln-scanner"},
		{"jwtcat", "jwtcat", "vuln-scanner"},
		{"ratproxy", "ratproxy", "vuln-scanner"},
		{"golismero", "golismero", "vuln-scanner"},
		{"wascan", "wascan", "vuln-scanner"},
		{"Striker", "striker", "vuln-scanner"},
		{"yukichan", "yuki-chan", "vuln-scanner"},
		{"spaghetti", "spaghetti", "vuln-scanner"},
		{"Taipan", "taipan", "vuln-scanner"},
		{"WPSeku", "wpseku", "vuln-scanner"},
		{"plecost", "plecost", "vuln-scanner"},
		{"Nettacker", "nettacker", "vuln-scanner"},
		{"BlackWidow", "blackwidow", "vuln-scanner"},
		{"V3n0M", "v3n0m", "vuln-scanner"},
		{"wpgarlic", "wpgarlic", "vuln-scanner"},
		{"ssrfire", "ssrfire", "vuln-scanner"},
		// Active Directory / Windows post-exploitation -> "tool".
		{"BOFHound", "bofhound", "tool"},
		{"ADCSPwn", "adcspwn", "tool"},
		{"PKINITtools", "pkinittools", "tool"},
		{"gMSADumper", "gmsadumper", "tool"},
		{"PowerView", "powerview", "tool"},
		{"PowerMad", "powermad", "tool"},
		{"SharpGPOAbuse", "sharpgpoabuse", "tool"},
		{"SweetPotato", "sweetpotato", "tool"},
		{"GodPotato", "godpotato", "tool"},
		{"JuicyPotato", "juicypotato", "tool"},
		{"PrintSpoofer", "printspoofer", "tool"},
		{"RoguePotato", "roguepotato", "tool"},
		{"SharpDPAPI", "sharpdpapi", "tool"},
		{"SharpSCCM", "sharpsccm", "tool"},
		{"SCCMHunter", "sccmhunter", "tool"},
		{"Group3r", "group3r", "tool"},
		{"dploot", "dploot", "tool"},
		{"hekatomb", "hekatomb", "tool"},
		{"scshell", "scshell", "tool"},
		{"atexec", "atexec", "tool"},
		{"dcomexec", "dcomexec", "tool"},
		{"rpcdump", "rpcdump", "tool"},
		{"samrdump", "samrdump", "tool"},
		{"lookupsid", "lookupsid", "tool"},
		{"PowerHuntShares", "powerhuntshares", "tool"},
		{"Orpheus", "orpheus", "tool"},
		{"krbjack", "krbjack", "tool"},
		{"ldapper", "ldapper", "tool"},
		// Cloud / Kubernetes / IaC audit + attack -> "tool".
		{"checkov", "checkov", "tool"},
		{"tfsec", "tfsec", "tool"},
		{"KICS", "kics", "tool"},
		{"Trivy", "trivy", "tool"},
		{"grype", "grype", "tool"},
		{"kube-bench", "kube-bench", "tool"},
		{"kubeaudit", "kubeaudit", "tool"},
		{"botb", "botb", "tool"},
		{"cloudquery", "cloudquery", "tool"},
		{"awspx", "awspx", "tool"},
		{"Cartography", "cartography", "tool"},
		// OSINT / recon / breach + exfil tooling -> "tool".
		{"nrich", "nrich", "tool"},
		{"mailcat", "mailcat", "tool"},
		{"gitfive", "gitfive", "tool"},
		{"zehef", "zehef", "tool"},
		{"ignorant", "ignorant", "tool"},
		{"waybackpy", "waybackpy", "tool"},
		{"linkedin2username", "linkedin2username", "tool"},
		{"CrossLinked", "crosslinked", "tool"},
		{"emailfinder", "emailfinder", "tool"},
		{"mosint", "mosint", "tool"},
		{"spoofcheck", "spoofcheck", "tool"},
		{"dnsdumpster", "dnsdumpster", "tool"},
		{"SubDomainizer", "subdomainizer", "tool"},
		{"subdominator", "subdominator", "tool"},
		{"egress-assess", "egress-assess", "tool"},
	}
	if len(cases) != 100 {
		t.Fatalf("expected 100 new signatures in this batch, have %d", len(cases))
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
