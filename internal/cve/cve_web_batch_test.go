package cve

import "testing"

// Spot-check the 40-CVE web/http/smtp/ftp batch: each signature must be
// recognized by MatchPayload for its service (http records also cover https;
// smtp_recv covers smtps).
func TestWebBatchSignaturesMatch(t *testing.T) {
	cases := []struct {
		service, payload, want string
	}{
		{"http", "PUT /shell.jsp/ HTTP/1.1\r\n\r\n", "CVE-2017-12617"},
		{"https", "GET /console/consolejndi.portal HTTP/1.1\r\n\r\n", "CVE-2021-2109"},
		{"http", "POST /x HTTP/1.1\r\nspring.cloud.function.routing-expression: T(java.lang.Runtime)\r\n\r\n", "CVE-2022-22963"},
		{"http", "GET /api/timelion/run HTTP/1.1\r\n\r\n", "CVE-2019-7609"},
		{"http", "POST /?q=user/password HTTP/1.1\r\n\r\nname[0;update", "CVE-2014-3704"},
		{"http", "GET /api/index.php/v1/config/application?public=true HTTP/1.1\r\n\r\n", "CVE-2023-23752"},
		{"http", "GET / HTTP/1.1\r\nRange: bytes=0-18446744073709551615\r\n\r\n", "CVE-2015-1635"},
		{"http", "GET /public/plugins/alertlist/../../../../etc/passwd HTTP/1.1\r\n\r\n", "CVE-2021-43798"},
		{"http", "GET /goform/formSysCmd?sysCmd=id HTTP/1.1\r\n\r\n", "CVE-2021-35394"},
		{"http", "GET /api/geojson?url=file:///etc/passwd HTTP/1.1\r\n\r\n", "CVE-2021-41277"},
		{"smtp_recv", "mail from:<;sleep 5;>\r\n", "CVE-2020-7247"},
		{"smtps", "rcpt to:<${run{/bin/sh}}@x>\r\n", "CVE-2019-10149"},
		{"ftp", "SITE CPFR /etc/passwd\r\n", "CVE-2015-3306"},
		{"ftp", "USER hacker:)\r\n", "CVE-2011-2523"},
		{"ftp", "SITE EXEC %x%x%x\r\n", "CVE-2000-0573"},
	}
	for _, c := range cases {
		hits := MatchPayload(c.service, c.payload)
		found := false
		for _, h := range hits {
			if h.ID == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s payload should detect %s; got %v", c.service, c.want, ids(hits))
		}
	}
}

// A benign request must not trip the new high-signal signatures.
func TestWebBatchNoFalsePositive(t *testing.T) {
	for _, p := range []string{
		"GET /index.html HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1023\r\n\r\n",
		"mail from:<alice@example.com>\r\n",
		"USER anonymous\r\n",
	} {
		if hits := MatchPayload("http", p); len(hits) != 0 {
			t.Errorf("benign http %q matched %v", p, ids(hits))
		}
	}
}

func ids(rs []Record) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}
