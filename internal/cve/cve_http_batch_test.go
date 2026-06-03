package cve

import "testing"

// Spot-check the 75-CVE HTTP/HTTPS web-application batch: the signature must be
// recognized over http (and inherited by https).
func TestHTTPAppBatchMatch(t *testing.T) {
	cases := []struct{ payload, want string }{
		{"GET /ctc/servlet/com.sap.ctc.util.ConfigServlet?param=x HTTP/1.1\r\n\r\n", "CVE-2010-5326"},
		{"GET /?search=%00{.exec|cmd.} HTTP/1.1\r\n\r\n", "CVE-2014-6287"},
		{"POST /struts HTTP/1.1\r\n\r\nmethod:#_memberAccess", "CVE-2016-3081"},
		{"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n", "CVE-2017-16894"},
		{"POST /solr/x/select?q=1 HTTP/1.1\r\n\r\n{!xmlparser v='<!DOCTYPE'}", "CVE-2017-12629"},
		{"GET /cgi-bin/mainfunction.cgi?keyPath=;id HTTP/1.1\r\n\r\n", "CVE-2020-8515"},
		{"GET /cgi-bin/config.exp HTTP/1.1\r\n\r\n", "CVE-2019-1653"},
		{"GET /?unix:AAAA|http://169.254.169.254/ HTTP/1.1\r\n\r\n", "CVE-2021-40438"},
		{"GET /device.rsp?opt=user&cmd=list HTTP/1.1\r\n\r\n", "CVE-2018-9995"},
		{"GET /moveitisapi/moveitisapi.dll?action=m2 HTTP/1.1\r\n\r\n", "CVE-2023-36934"},
		{"POST /apisix/batch-requests HTTP/1.1\r\n\r\n{}", "CVE-2022-24112"},
		{"GET /sdk/webLanguage HTTP/1.1\r\n\r\n<language>$(id)</language>", "CVE-2021-36260"},
		{"GET /index.php?p=admin/actions/conditions/render HTTP/1.1\r\n\r\n", "CVE-2023-41892"},
		{"POST /access/set?param=enableapi&value=1 HTTP/1.1\r\n\r\n", "CVE-2024-1212"},
		{"GET /res/../admin/diagnostic.jsp HTTP/1.1\r\n\r\n", "CVE-2024-27199"},
	}
	for _, c := range cases {
		hits := MatchPayload("http", c.payload)
		ok := false
		for _, h := range hits {
			if h.ID == c.want {
				ok = true
			}
		}
		if !ok {
			t.Errorf("payload should detect %s; got %v", c.want, ids(hits))
		}
	}
	// All inherited over https.
	if len(MatchPayload("https", "GET /cgi-bin/config.exp HTTP/1.1\r\n\r\n")) == 0 {
		t.Error("https should inherit http CVE signatures")
	}
}
