package toolfp

import "testing"

func TestNewToolSignaturesBatch2(t *testing.T) {
	cases := []struct{ ua, tool, cat string }{
		{"sn1per/9.0", "sn1per", "vuln-scanner"},
		{"afrog/3.0.0", "afrog", "vuln-scanner"},
		{"fscan", "fscan", "vuln-scanner"},
		{"xray", "xray", "vuln-scanner"},
		{"goby", "goby", "vuln-scanner"},
		{"Mozilla/5.0 dismap", "dismap", "vuln-scanner"},
		{"spiderfoot", "spiderfoot", "tool"},
		{"gowitness", "gowitness", "tool"},
		{"asnmap/1.0", "asnmap", "tool"},
		{"chaos-client/0.5", "chaos-client", "tool"},
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
