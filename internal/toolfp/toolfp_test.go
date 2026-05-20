package toolfp

import "testing"

func has(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func TestUASignatures(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)": "nmap",
		"sqlmap/1.7.2#stable (https://sqlmap.org)":                                        "sqlmap",
		"Mozilla/5.00 (Nikto/2.1.6)":                                                      "nikto",
		"python-requests/2.31.0":                                                          "python-script",
		"curl/8.4.0":                                                                      "curl",
		"masscan/1.3":                                                                     "masscan",
		"Go-http-client/1.1":                                                              "go-scanner",
	}
	for ua, want := range cases {
		v := IdentifyHTTP(HTTPSignals{UserAgent: ua, Path: "/"})
		if !has(v.Tools, want) {
			t.Errorf("UA %q: tools=%v; want %q", ua, v.Tools, want)
		}
		if !v.Automation {
			t.Errorf("UA %q should be flagged automation", ua)
		}
	}
}

func TestPathSignatures(t *testing.T) {
	v := IdentifyHTTP(HTTPSignals{Path: "/nmaplowercheck1700000000", UserAgent: "Mozilla/5.0"})
	if !has(v.Tools, "nmap") {
		t.Errorf("nmap http-probe path not detected: %v", v.Tools)
	}
	v2 := IdentifyHTTP(HTTPSignals{Path: "/boaform/admin/formLogin", UserAgent: ""})
	if !has(v2.Tools, "router-exploit") {
		t.Errorf("router-exploit path not detected: %v", v2.Tools)
	}
}

func TestAutomationHeuristic(t *testing.T) {
	// Real browser: full UA + Accept headers -> not automation.
	browser := IdentifyHTTP(HTTPSignals{
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		Path:       "/",
		HeaderKeys: []string{"host", "user-agent", "accept", "accept-language", "accept-encoding"},
	})
	if browser.Automation {
		t.Errorf("real browser flagged as automation: %s", browser.Reason)
	}

	// No User-Agent at all -> automation.
	noUA := IdentifyHTTP(HTTPSignals{Path: "/", HeaderKeys: []string{"host"}})
	if !noUA.Automation {
		t.Errorf("missing UA should be automation")
	}

	// Browser UA but no Accept-* headers -> automation (impersonation).
	fake := IdentifyHTTP(HTTPSignals{
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		Path:       "/",
		HeaderKeys: []string{"host", "user-agent"},
	})
	if !fake.Automation {
		t.Errorf("browser UA without Accept headers should be automation")
	}
}

func TestIdentifyTLS(t *testing.T) {
	if IdentifyTLS("e7d705a3286e19ea42f587b344ee6865") != "go-tls" {
		t.Errorf("go-tls JA3 not mapped")
	}
	if IdentifyTLS("unknown") != "" {
		t.Errorf("unknown JA3 should map to empty")
	}
}
