package handler

import "testing"

func TestExtractClientHints(t *testing.T) {
	h := map[string]string{
		"sec-ch-ua-platform":         `"Windows"`,
		"sec-ch-ua-platform-version": `"15.0.0"`,
		"sec-ch-ua-arch":             `"x86"`,
		"sec-ch-ua-bitness":          `"64"`,
		"sec-ch-ua-mobile":           "?0",
		"sec-ch-ua":                  `"Chromium";v="124", "Google Chrome";v="124"`,
	}
	ch := extractClientHints(h)
	if ch["os"] != "Windows" || ch["os_version"] != "15.0.0" || ch["arch"] != "x86" || ch["bitness"] != "64" {
		t.Errorf("client hints OS/arch wrong: %v", ch)
	}
	if ch["browser"] == "" {
		t.Errorf("browser brand list not captured: %v", ch)
	}
	if len(extractClientHints(map[string]string{"x": "y"})) != 0 {
		t.Error("no hints should yield empty map")
	}
}

func TestProxyChain(t *testing.T) {
	if got := proxyChain(map[string]string{"x-forwarded-for": "203.0.113.9, 10.0.0.1"}); got != "x-forwarded-for=203.0.113.9, 10.0.0.1" {
		t.Errorf("proxyChain = %q", got)
	}
	if proxyChain(map[string]string{"host": "x"}) != "" {
		t.Error("no proxy headers should yield empty")
	}
}

func TestHTTPClientHintsCaptured(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Sec-CH-UA-Platform: \"macOS\"\r\n" +
		"Sec-CH-UA-Platform-Version: \"14.5.0\"\r\n" +
		"X-Forwarded-For: 198.51.100.7\r\n" +
		"Accept-Language: sv-SE,sv;q=0.9\r\n\r\n"
	res := serveHTTPOnce(t, req)
	ch, _ := res.Meta["client_hints"].(map[string]string)
	if ch["os"] != "macOS" || ch["os_version"] != "14.5.0" {
		t.Errorf("client_hints not captured: %v", res.Meta["client_hints"])
	}
	if res.Meta["forwarded_for"] == nil {
		t.Errorf("forwarded_for not captured: %v", res.Meta)
	}
	if res.Meta["accept_language"] != "sv-SE,sv;q=0.9" {
		t.Errorf("accept_language = %v", res.Meta["accept_language"])
	}
}

func TestIMAPIDCaptured(t *testing.T) {
	res := runConn(t, &imap{}, "a1 ID (\"name\" \"Thunderbird\" \"version\" \"115.0\")\r\na2 LOGOUT\r\n")
	cid, _ := res.Meta["imap_client_id"].(string)
	if cid == "" || !containsStr([]string{cid}, cid) {
		t.Fatalf("imap_client_id not captured: %v", res.Meta["imap_client_id"])
	}
	if want := "Thunderbird"; !contains2(cid, want) {
		t.Errorf("imap_client_id = %q; want it to contain %q", cid, want)
	}
}

func contains2(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
