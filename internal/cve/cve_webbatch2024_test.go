package cve

import "testing"

func TestMatchPayloadWebBatch2024(t *testing.T) {
	cases := []struct{ name, handler, req, want string }{
		{"CyberPanel RCE", "http",
			"POST /dataBases/upgrademysqlstatus HTTP/1.1\r\n\r\n{\"statusfile\":\";id;\"}", "CVE-2024-51378"},
		{"SimpleHelp traversal", "http",
			"GET /toolbox-resource/serverdownload.exe?file=..%2f..%2f..%2f..%2fprogramdata HTTP/1.1\r\n\r\n", "CVE-2024-57727"},
		{"OFBiz ProgramExport", "http",
			"GET /webtools/control/main/programexport HTTP/1.1\r\n\r\n", "CVE-2024-32113"},
		{"Apache mod_rewrite traversal", "http",
			"GET /cgi-bin/%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1\r\n\r\n", "CVE-2024-38475"},
		{"Cisco SLU static cred", "http",
			"GET /cslu/v1/scheduler/jobs HTTP/1.1\r\n\r\n", "CVE-2024-20439"},
		{"ProjectSend auth bypass", "http",
			"POST /options.php?action=add_user HTTP/1.1\r\n\r\nuser=evil", "CVE-2024-11680"},
		{"MOVEit SFTP bypass", "https",
			"GET /api/v1/folders HTTP/1.1\r\n\r\n", "CVE-2024-5806"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.handler, c.req)
		found := false
		for _, h := range hits {
			if h.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected %s; got %+v", c.name, c.want, hits)
		}
	}
}

func TestWebBatch2024Advisories(t *testing.T) {
	for _, id := range []string{"CVE-2024-50623", "CVE-2024-12356", "CVE-2025-49144"} {
		r, ok := Lookup(id)
		if !ok {
			t.Errorf("%s missing", id)
			continue
		}
		if r.Detectable() {
			t.Errorf("%s should be advisory-only", id)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s missing ATT&CK mapping", id)
		}
	}
}
