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

func TestUASignaturesExpanded(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (compatible; Censys/...)":            "", // not a default UA
		"Mozilla/5.0 zgrab/0.x":                           "zgrab",
		"Burp Suite Professional":                         "burpsuite",
		"Mozilla/5.0 (compatible; LeakIX)":                "leakix",
		"Shodan":                                          "shodan",
		"ffuf/2.1.0":                                      "ffuf",
		"Mozilla/5.0 (compatible; Nuclei - Open-source) ": "nuclei",
		"WPScan v3.8.22":                                  "wpscan",
		"Hello, World":                                    "scanner-stub",
		"Java/1.8.0_181":                                  "java-http",
	}
	for ua, want := range cases {
		v := IdentifyHTTP(HTTPSignals{UserAgent: ua, Path: "/"})
		if want == "" {
			continue
		}
		if !has(v.Tools, want) {
			t.Errorf("UA %q: tools=%v; want %q", ua, v.Tools, want)
		}
	}
}

func TestPathSignaturesExpanded(t *testing.T) {
	cases := map[string]string{
		"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php": "cve-2017-9841",
		"/remote/fgt_lang?lang=/../../../..//////////dev/":    "cve-2018-13379",
		"/wls-wsat/CoordinatorPortType":                       "cve-2017-10271",
		"/.git/config":                                        "scanner-recon",
	}
	for p, want := range cases {
		v := IdentifyHTTP(HTTPSignals{Path: p, UserAgent: "Mozilla/5.0"})
		if !has(v.Tools, want) {
			t.Errorf("path %q: tools=%v; want %q", p, v.Tools, want)
		}
	}
}

func TestClientFrameworkSignatures(t *testing.T) {
	cases := map[string]string{
		"curl/8.4.0":                   "curl",
		"Wget/1.21.3":                  "wget",
		"python-urllib3/2.1.0":         "python-script",
		"PycURL/7.45.1":                "python-script",
		"libwww-perl/6.67":             "perl-script",
		"Mojolicious (Perl)":           "perl-script",
		"Go-http-client/2.0":           "go-scanner",
		"go-resty/2.7.0 (https://...)": "go-http",
		"fasthttp":                     "go-http",
		"Apache-HttpClient/4.5.13":     "java-http",
		"Jersey/3.1":                   "java-http",
		"okhttp/4.12.0":                "okhttp-script",
		"libcurl/8.4.0":                "c-http",
		"libsoup/3.4":                  "c-http",
		"RestSharp/108.0.0":            "dotnet-http",
		"System.Net.Http/8.0":          "dotnet-http",
		"reqwest/0.11":                 "rust-http",
		"ureq/2.9":                     "rust-http",
		"node-fetch/3.3":               "node-script",
	}
	for ua, want := range cases {
		v := IdentifyHTTP(HTTPSignals{UserAgent: ua, Path: "/"})
		if !has(v.Tools, want) {
			t.Errorf("UA %q: tools=%v; want %q", ua, v.Tools, want)
		}
		if !v.Automation {
			t.Errorf("UA %q should be automation", ua)
		}
	}
}

func TestIdentifySSH(t *testing.T) {
	cases := map[string][]string{
		"SSH-2.0-libssh2_1.10.0":       {"libssh2"},
		"SSH-2.0-libssh-0.9.6":         {"libssh"},
		"SSH-2.0-paramiko_2.11.0":      {"paramiko"},
		"SSH-2.0-Go":                   {"go-ssh"},
		"SSH-2.0-PuTTY_Release_0.78":   {"putty"},
		"SSH-2.0-OpenSSH_9.2p1 Debian": nil, // legit default — no tag
	}
	for id, want := range cases {
		got := IdentifySSH(id)
		if len(want) == 0 {
			if len(got) != 0 {
				t.Errorf("%q: got %v; want none", id, got)
			}
			continue
		}
		for _, w := range want {
			if !has(got, w) {
				t.Errorf("%q: got %v; want %q", id, got, w)
			}
		}
	}
	// libssh2 banner must not also tag plain "libssh".
	if g := IdentifySSH("SSH-2.0-libssh2_1.10.0"); has(g, "libssh") {
		t.Errorf("libssh2 banner double-tagged libssh: %v", g)
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
