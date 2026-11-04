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
