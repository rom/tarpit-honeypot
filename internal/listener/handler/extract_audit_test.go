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

func TestSNMPV3UserName(t *testing.T) {
	// SNMPv3: outer SEQ { version INT 3, globalData SEQ{}, secParams OCTET{
	// SEQ{ engineID OCTET, boots INT, time INT, userName OCTET "admin", auth
	// OCTET, priv OCTET } }, ... }.
	inner := func() []byte {
		b := []byte{0x30, 0x00} // placeholder, fill below
		body := []byte{}
		body = append(body, 0x04, 0x03, 'e', 'n', 'g')           // engineID
		body = append(body, 0x02, 0x01, 0x01)                    // boots
		body = append(body, 0x02, 0x01, 0x02)                    // time
		body = append(body, 0x04, 0x05, 'a', 'd', 'm', 'i', 'n') // userName
		body = append(body, 0x04, 0x00)                          // auth params
		body = append(body, 0x04, 0x00)                          // priv params
		b[1] = byte(len(body))
		return append(b[:2], body...)
	}()
	secOctet := append([]byte{0x04, byte(len(inner))}, inner...)
	global := []byte{0x30, 0x02, 0x02, 0x00} // tiny globalData SEQ
	ver := []byte{0x02, 0x01, 0x03}
	outerBody := append(append(append([]byte{}, ver...), global...), secOctet...)
	msg := append([]byte{0x30, byte(len(outerBody))}, outerBody...)

	if u := snmpV3UserName(msg); u != "admin" {
		t.Errorf("snmpV3UserName = %q; want admin", u)
	}
	if snmpV3UserName([]byte{0x30, 0x00}) != "" {
		t.Error("empty v3 message should yield no user")
	}
}

func TestStunSoftware(t *testing.T) {
	// STUN Binding Request header (20 bytes) + SOFTWARE attribute (0x8022).
	sw := "coturn-4.5.2"
	hdr := make([]byte, 20)
	hdr[0], hdr[1] = 0x00, 0x01 // Binding Request
	copy(hdr[4:8], []byte{0x21, 0x12, 0xA4, 0x42})
	attr := []byte{0x80, 0x22, 0x00, byte(len(sw))}
	attr = append(attr, []byte(sw)...)
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	pkt := append(hdr, attr...)
	// fix message length
	pkt[2] = byte(len(attr) >> 8)
	pkt[3] = byte(len(attr))
	if got := stunSoftware(pkt); got != sw {
		t.Errorf("stunSoftware = %q; want %q", got, sw)
	}
}
