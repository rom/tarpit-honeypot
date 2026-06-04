package toolfp

import "testing"

// TestNewToolSignaturesBatch9 pins the ninth batch of 50 C2 / AD / cloud /
// OSINT / recon / DoS fingerprints (including Cobalt Strike cross-platform
// beacons).
func TestNewToolSignaturesBatch9(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		// Cobalt Strike beacons / proxies + other C2 -> "c2".
		{"geacon", "geacon", "c2"},
		{"CrossC2", "crossc2", "c2"},
		{"RedWarden", "redwarden", "c2"},
		{"Starkiller", "starkiller", "c2"},
		{"nimbo-c2", "nimbo-c2", "c2"},
		// Vuln / web scanners -> "vuln-scanner".
		{"vuls", "vuls", "vuln-scanner"},
		{"RapidScan", "rapidscan", "vuln-scanner"},
		{"sitadel", "sitadel", "vuln-scanner"},
		{"scanqli", "scanqli", "vuln-scanner"},
		{"dirhunt", "dirhunt", "vuln-scanner"},
		// AD -> "tool".
		{"Seatbelt", "seatbelt", "tool"},
		{"SharpUp", "sharpup", "tool"},
		{"PowerUp", "powerup", "tool"},
		{"Certify", "certify", "tool"},
		{"SharpView", "sharpview", "tool"},
		{"AdExplorer", "adexplorer", "tool"},
		{"godap", "godap", "tool"},
		// Cloud / CI -> "tool".
		{"gato", "gato", "tool"},
		{"PurplePanda", "purplepanda", "tool"},
		{"kubescape", "kubescape", "tool"},
		{"legitify", "legitify", "tool"},
		{"poutine", "poutine", "tool"},
		{"octoscan", "octoscan", "tool"},
		// OSINT -> "tool".
		{"osintgram", "osintgram", "tool"},
		{"twint", "twint", "tool"},
		{"instaloader", "instaloader", "tool"},
		{"socialscan", "socialscan", "tool"},
		// Recon / exploit search / screenshot -> "tool".
		{"sifter", "sifter", "tool"},
		{"pnscan", "pnscan", "tool"},
		{"Vajra", "vajra", "tool"},
		{"getsploit", "getsploit", "tool"},
		{"fuzzuli", "fuzzuli", "tool"},
		{"scrying", "scrying", "tool"},
		{"WitnessMe", "witnessme", "tool"},
		// Wordlist / cred generators -> "tool".
		{"cupp", "cupp", "tool"},
		{"psudohash", "psudohash", "tool"},
		{"username-anarchy", "username-anarchy", "tool"},
		// DoS / flood -> "tool".
		{"t50", "t50", "tool"},
		{"hyenae", "hyenae", "tool"},
		{"MHDDoS", "mhddos", "tool"},
		{"BoNeSi", "bonesi", "tool"},
		{"slowloris", "slowloris", "tool"},
		{"slowhttptest", "slowhttptest", "tool"},
		{"GoldenEye", "goldeneye", "tool"},
		{"hulk", "hulk", "tool"},
		{"torshammer", "torshammer", "tool"},
		{"XerXes", "xerxes", "tool"},
		{"PyLoris", "pyloris", "tool"},
		{"DAVOSET", "davoset", "tool"},
		{"saphyra", "saphyra", "tool"},
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
