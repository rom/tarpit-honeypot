package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// runDanfoss drives the danfoss handler over a pipe with a raw HTTP request and
// returns the server-side Result plus the bytes written back.
func runDanfoss(t *testing.T, req string) (Result, string) {
	t.Helper()
	client, server := pipePair(t)
	h := &danfoss{vuln: true}
	cfg := config.Listener{Handler: h.Name(), ReadTimeout: time.Second}
	done := make(chan struct{})
	var res Result
	go func() {
		defer close(done)
		res, _ = h.Handle(context.Background(), server, cfg)
	}()
	_, _ = client.Write([]byte(req))
	buf := make([]byte, 2048)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	client.Close()
	<-done
	return res, string(buf[:n])
}

func danfossAnoms(res Result) []string {
	a, _ := res.Meta["anomalies"].([]string)
	return a
}

func httpPost(path, ctype, body string) string {
	return "POST " + path + " HTTP/1.1\r\nHost: sm\r\nContent-Type: " + ctype +
		"\r\nContent-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

func TestDanfossLandingFingerprint(t *testing.T) {
	res, reply := runDanfoss(t, "GET / HTTP/1.1\r\nHost: sm\r\n\r\n")
	if !strings.Contains(reply, "StoreView") {
		t.Errorf("landing reply did not fingerprint StoreView: %q", reply)
	}
	if !containsStr(danfossAnoms(res), "danfoss-aksm-access") {
		t.Errorf("anomalies = %v; want danfoss-aksm-access", danfossAnoms(res))
	}
}

func TestDanfossEmbeddedAssets(t *testing.T) {
	// Byte-exact captures from the live AK-SM StoreView device.
	if got := len(danfossFavicon); got != 1150 {
		t.Errorf("favicon.ico = %d bytes; want 1150", got)
	}
	if got := len(danfossLogo); got != 6655 {
		t.Errorf("logo.png = %d bytes; want 6655", got)
	}
	if !strings.HasPrefix(danfossLogo, "\x89PNG\r\n\x1a\n") {
		t.Error("logo.png is missing the PNG signature")
	}
	if got := len(danfossWordmark); got != 66561 {
		t.Errorf("Danfoss-logo.png = %d bytes; want 66561", got)
	}
	if !strings.HasPrefix(danfossWordmark, "\x89PNG\r\n\x1a\n") {
		t.Error("Danfoss-logo.png is missing the PNG signature")
	}
	// The landing page visually replicates the real "System Manager 800A" login
	// and keeps the device fingerprint (title, favicon/logo refs) — but it must
	// NOT reference the Angular bundles (which a honeypot can't serve, leaving
	// the real shell blank).
	for _, want := range []string{
		"<title>Danfoss StoreView</title>",
		`href="favicon.ico"`,
		`src="assets/images/Danfoss-logo.png"`,
		"System Manager 800A",
		"SVB501.0.156",
		`value="Sign In"`,
		`action="xml.cgi?action=getauth"`,
	} {
		if !strings.Contains(danfossIndexHTML, want) {
			t.Errorf("landing page missing %q", want)
		}
	}
	for _, bundle := range []string{"<app-root", "main.49c617", "styles.5d1276", "runtime.a4d6ab", ".js\""} {
		if strings.Contains(danfossIndexHTML, bundle) {
			t.Errorf("landing page still references the Angular SPA bundle %q (renders blank)", bundle)
		}
	}
}

func TestDanfossFormLoginCaptured(t *testing.T) {
	// The served HTML login form posts url-encoded user/pwd fields; those must be
	// captured, not just the device's getauth XML.
	res, _ := runDanfoss(t, httpPost("/xml.cgi?action=getauth", "application/x-www-form-urlencoded", "user=operator&pwd=Winter2026"))
	if res.Meta["login_user"] != "operator" || res.Meta["login_pass"] != "Winter2026" {
		t.Errorf("user/pwd form login not captured: user=%v pass=%v", res.Meta["login_user"], res.Meta["login_pass"])
	}
	if containsStr(danfossAnoms(res), "danfoss-aksm-auth-bypass") {
		t.Errorf("plain form login wrongly flagged as bypass: %v", danfossAnoms(res))
	}
	// The username/password aliases must also work (other tools / the XML path).
	res2, _ := runDanfoss(t, httpPost("/xml.cgi?action=getauth", "application/x-www-form-urlencoded", "username=svc&password=hunter2"))
	if res2.Meta["login_user"] != "svc" || res2.Meta["login_pass"] != "hunter2" {
		t.Errorf("username/password form login not captured: user=%v pass=%v", res2.Meta["login_user"], res2.Meta["login_pass"])
	}
}

func TestDanfossRealHeadersAndAssets(t *testing.T) {
	// Landing serves the genuine Angular shell under the device's header set.
	_, reply := runDanfoss(t, "GET / HTTP/1.1\r\nHost: sm\r\n\r\n")
	for _, want := range []string{
		"Server: nginx",
		"Access-Control-Allow-Headers: aksm-auth,",
		"Access-Control-Allow-Origin: *",
		"Cache-Control: no-store, no-cache",
		"Content-Type: text/html\r\n",
		"<title>Danfoss StoreView</title>",
		`href="favicon.ico"`,
	} {
		if !strings.Contains(reply, want) {
			t.Errorf("landing reply missing %q", want)
		}
	}
	// The blank-rendering Angular shell must be gone (checked near the response
	// start, so unaffected by the test's single-read window).
	if strings.Contains(reply, "<app-root") {
		t.Error("landing reply still serves the Angular SPA shell (renders blank)")
	}
	// The fabricated X-Danfoss-Device/X-Firmware tells must be gone.
	if strings.Contains(reply, "X-Danfoss-Device") || strings.Contains(reply, "X-Firmware") {
		t.Error("landing reply still emits fabricated X-Danfoss-* headers")
	}

	// favicon.ico / logo.png route to the embedded bytes (assert on the response
	// headers, which fit the test's read window).
	res, fav := runDanfoss(t, "GET /favicon.ico HTTP/1.1\r\nHost: sm\r\n\r\n")
	if !strings.Contains(fav, "Content-Type: image/x-icon") || !strings.Contains(fav, "Content-Length: 1150") {
		t.Errorf("favicon reply headers wrong: %.120q", fav)
	}
	if res.Meta["asset_served"] != "favicon.ico" {
		t.Errorf("asset_served = %v; want favicon.ico", res.Meta["asset_served"])
	}
	_, logo := runDanfoss(t, "GET /assets/images/logo.png HTTP/1.1\r\nHost: sm\r\n\r\n")
	if !strings.Contains(logo, "Content-Type: image/png") || !strings.Contains(logo, "Content-Length: 6655") {
		t.Errorf("logo reply headers wrong: %.120q", logo)
	}
}

func TestDanfossAuthBypassExtraAttr(t *testing.T) {
	// A getauth request carrying an attribute beyond username/password is the
	// documented code-of-the-day bypass shape (CVE-2025-41450).
	body := `<?xml version="1.0"?><request><username>admin</username><password>147456</password><codeofday>1</codeofday></request>`
	res, _ := runDanfoss(t, httpPost("/xml.cgi?action=getauth", "text/xml", body))
	if !containsStr(danfossAnoms(res), "danfoss-aksm-auth-bypass") {
		t.Errorf("anomalies = %v; want danfoss-aksm-auth-bypass", danfossAnoms(res))
	}
	if !containsStr(res.CVEHits, "CVE-2025-41450") {
		t.Errorf("CVEHits = %v; want CVE-2025-41450", res.CVEHits)
	}
}

func TestDanfossAuthNormalLoginNotBypass(t *testing.T) {
	// A plain username/password login must NOT be flagged as a bypass.
	body := `<?xml version="1.0"?><request><username>admin</username><password>Sup3rSecret!</password></request>`
	res, _ := runDanfoss(t, httpPost("/xml.cgi?action=getauth", "text/xml", body))
	if containsStr(danfossAnoms(res), "danfoss-aksm-auth-bypass") {
		t.Errorf("normal login wrongly flagged as bypass: %v", danfossAnoms(res))
	}
	if !containsStr(danfossAnoms(res), "danfoss-aksm-login-attempt") {
		t.Errorf("anomalies = %v; want danfoss-aksm-login-attempt", danfossAnoms(res))
	}
}

func TestDanfossCommandInjection(t *testing.T) {
	// Shell metacharacters in the SMTP password item 0x1be1 (CVE-2025-41451).
	body := "smtp_server=smtp.test&item_0x1be1=x%27%3B+id+%23&alarm_to_mail_enabled=1"
	res, _ := runDanfoss(t, httpPost("/xml.cgi?action=set_email_config", "application/x-www-form-urlencoded", body))
	if !containsStr(danfossAnoms(res), "danfoss-aksm-cmd-injection") {
		t.Errorf("anomalies = %v; want danfoss-aksm-cmd-injection", danfossAnoms(res))
	}
	if !containsStr(res.CVEHits, "CVE-2025-41451") {
		t.Errorf("CVEHits = %v; want CVE-2025-41451", res.CVEHits)
	}
}

func TestDanfossNginxHeadersInjection(t *testing.T) {
	body := "------b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"headers.conf\"\r\n\r\nadd_header X-x y;\r\n------b--\r\n"
	res, _ := runDanfoss(t, httpPost("/xml.cgi?action=load_nginx_headers", "multipart/form-data; boundary=----b", body))
	if !containsStr(danfossAnoms(res), "danfoss-aksm-nginx-config-injection") {
		t.Errorf("anomalies = %v; want danfoss-aksm-nginx-config-injection", danfossAnoms(res))
	}
	if !containsStr(res.CVEHits, "CVE-2025-41452") {
		t.Errorf("CVEHits = %v; want CVE-2025-41452", res.CVEHits)
	}
}

func TestDanfossXMLTraversal(t *testing.T) {
	res, _ := runDanfoss(t, "GET /xml.cgi?action=../../../../etc/passwd HTTP/1.1\r\nHost: sm\r\n\r\n")
	if !containsStr(danfossAnoms(res), "danfoss-aksm-xml-traversal") {
		t.Errorf("anomalies = %v; want danfoss-aksm-xml-traversal", danfossAnoms(res))
	}
	if !containsStr(res.CVEHits, "CVE-2023-25914") {
		t.Errorf("CVEHits = %v; want CVE-2023-25914", res.CVEHits)
	}
}

func TestDanfossEngineeringInterface(t *testing.T) {
	res, _ := runDanfoss(t, "GET /service/debug HTTP/1.1\r\nHost: sm\r\n\r\n")
	if !containsStr(danfossAnoms(res), "danfoss-engineering-interface-access") {
		t.Errorf("anomalies = %v; want danfoss-engineering-interface-access", danfossAnoms(res))
	}
	if !containsStr(res.CVEHits, "CVE-2026-15203") {
		t.Errorf("CVEHits = %v; want CVE-2026-15203", res.CVEHits)
	}
}
