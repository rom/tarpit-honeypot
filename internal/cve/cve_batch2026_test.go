package cve

import (
	"testing"
)

// A representative sample of the 2026 batch must be present and actually fire
// through MatchPayload on a canonical exploit string.
func TestBatchKEV2026Detects(t *testing.T) {
	cases := []struct {
		id, service, payload string
	}{
		{"CVE-2025-64446", "fortinet", "GET /cgi-bin/fwbcgi HTTP/1.1\r\nX: /../../../../"},
		{"CVE-2024-45409", "http", "POST /users/auth/saml/callback HTTP/1.1\r\n\r\nSAMLResponse=<saml:assertion>...<signaturevalue>x"},
		{"CVE-2024-53677", "http", "POST /upload.action HTTP/1.1\r\n\r\ntop.UploadFileName=../../webapps/shell.jsp"},
		{"CVE-2022-47945", "http", "GET /index.php?lang=../../../../usr/local/lib/php/pearcmd HTTP/1.1"},
		{"CVE-2019-9621", "http", "GET /service/proxy?target=http://169.254.169.254 HTTP/1.1"},
		{"CVE-2024-7120", "http", "POST /vpn/list_base_config.php HTTP/1.1\r\n\r\ntemplate=`id`"},
		{"CVE-2023-47565", "http", "POST /cgi-bin/iptables.cgi HTTP/1.1\r\n\r\naction=set&x=`id`"},
		{"CVE-2023-39362", "http", "POST /host.php HTTP/1.1\r\n\r\nsnmp_community=`id`"},
	}
	for _, c := range cases {
		if _, ok := Lookup(c.id); !ok {
			t.Errorf("%s not in catalog", c.id)
			continue
		}
		hits := MatchPayload(c.service, c.payload)
		found := false
		for _, h := range hits {
			if h.ID == c.id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: MatchPayload(%q) did not flag it; got %v", c.id, c.service, hits)
		}
	}
}

// Every new batch record must carry at least one signature (advisory-only
// records belong in the main catalog, not this detection batch) and a service.
func TestBatchKEV2026WellFormed(t *testing.T) {
	for _, r := range cveBatchKEV2026 {
		if len(r.Signatures) == 0 {
			t.Errorf("%s: batch record has no signatures", r.ID)
		}
		if r.Service == "" || r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s: missing service/technique/tactic", r.ID)
		}
	}
}
