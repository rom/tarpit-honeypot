package handler

import "testing"

// TestHTTPAttackClasses exercises the generic web-attack-class scanner added to
// the base HTTP handler (independent of the vulnweb emulation).
func TestHTTPAttackClasses(t *testing.T) {
	cases := []struct{ name, req, want string }{
		{"SSTI", "GET /?q={{7*7}} HTTP/1.1\r\nHost: x\r\n\r\n", "webapp:ssti"},
		{"XXE", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 60\r\n\r\n" +
			"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>", "webapp:xxe"},
		{"SSRF-metadata", "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n", "webapp:rfi_ssrf"},
		{"NoSQLi", "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 28\r\n\r\n{\"user\":{\"$ne\":null},\"p\":1}", "webapp:nosqli"},
		{"GraphQL", "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Length: 24\r\n\r\n{\"query\":\"{__schema{x}}\"}", "webapp:graphql-introspection"},
		{"JWT-none", "GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer eyJhbGciOiJub25lIn0.e30. \r\n\r\n", "webapp:jwt-none"},
		{"Java-deser", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nrO0ABXNyAAVk", "webapp:deserialize"},
	}
	for _, c := range cases {
		got := anomaliesOf(serveHTTPOnce(t, c.req))
		if !containsStr(got, c.want) {
			t.Errorf("%s: expected %q; anomalies=%v", c.name, c.want, got)
		}
	}
	// A benign request must not trip any webapp:* class.
	benign := anomaliesOf(serveHTTPOnce(t, "GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"))
	for _, a := range benign {
		if len(a) > 7 && a[:7] == "webapp:" {
			t.Errorf("benign request flagged %q", a)
		}
	}
}
