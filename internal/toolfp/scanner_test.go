package toolfp

import (
	"slices"
	"testing"
)

func TestIdentifyVulnScanners(t *testing.T) {
	cases := []struct {
		ua   string
		tool string
	}{
		{"Nessus SOAP v0.0.1 (Nessus.org)", "nessus"},
		{"Mozilla/5.0 (compatible; Nexpose/1.0)", "nexpose"},
		{"OpenVAS", "openvas"},
		{"Mozilla/5.0 (compatible; Greenbone)", "openvas"},
		{"Mozilla/4.0 (compatible; Qualys)", "qualys"},
		{"Nuclei - github.com/projectdiscovery/nuclei", "nuclei"},
		{"sqlmap/1.7", "sqlmap"},
		{"Mozilla/5.0 (Nikto/2.5.0)", "nikto"},
		{"Acunetix Web Vulnerability Scanner", "acunetix"},
	}
	for _, c := range cases {
		v := IdentifyHTTP(HTTPSignals{UserAgent: c.ua, Path: "/"})
		if !slices.Contains(v.Tools, c.tool) {
			t.Errorf("UA %q: tools=%v; want %q", c.ua, v.Tools, c.tool)
		}
		if !v.Scanner {
			t.Errorf("UA %q: Scanner=false; want true (vuln scanner)", c.ua)
		}
		if !v.Automation {
			t.Errorf("UA %q: Automation=false; want true", c.ua)
		}
	}
}

func TestNonScannerNotFlagged(t *testing.T) {
	// A real browser must not be flagged as a vuln scanner.
	v := IdentifyHTTP(HTTPSignals{
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
		Path:       "/",
		HeaderKeys: []string{"accept", "accept-language", "accept-encoding"},
	})
	if v.Scanner {
		t.Errorf("browser flagged as scanner: %+v", v)
	}
	// curl is automation but not a vuln scanner.
	v = IdentifyHTTP(HTTPSignals{UserAgent: "curl/8.5.0", Path: "/"})
	if v.Scanner {
		t.Errorf("curl flagged as vuln scanner: %+v", v)
	}
}

func TestIsVulnScanner(t *testing.T) {
	for _, s := range []string{"nessus", "openvas", "qualys", "nexpose", "nuclei", "sqlmap"} {
		if !IsVulnScanner(s) {
			t.Errorf("%q should be a vuln scanner", s)
		}
	}
	for _, s := range []string{"nmap", "curl", "gobuster", "hydra", ""} {
		if IsVulnScanner(s) {
			t.Errorf("%q should not be classed as a vuln scanner", s)
		}
	}
}
