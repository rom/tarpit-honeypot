package handler

import (
	"io"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// serveHTTPOnce drives serveHTTP over net.Pipe with a single request and
// returns the captured Result.
func serveHTTPOnce(t *testing.T, req string) Result {
	t.Helper()
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second, ReadBytes: 8192}
	var res Result
	done := make(chan struct{})
	go func() { defer close(done); res, _ = serveHTTP(server, cfg, nil, nil, nil, false) }()
	go func() { _, _ = io.Copy(io.Discard, client) }()
	_, _ = io.WriteString(client, req)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveHTTP did not return")
	}
	return res
}

func anomaliesOf(res Result) []string {
	a, _ := res.Meta["anomalies"].([]string)
	return a
}

func TestHTTPImpossibleBrowser(t *testing.T) {
	// Full browser UA but no Accept-* headers at all → impossible.
	req := "GET / HTTP/1.1\r\nHost: x\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36\r\n\r\n"
	if !containsStr(anomaliesOf(serveHTTPOnce(t, req)), "http-impossible-browser") {
		t.Errorf("spoofed browser UA not flagged")
	}

	// A genuine browser request must NOT be flagged.
	real := "GET / HTTP/1.1\r\nHost: x\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36\r\n" +
		"Accept: text/html\r\nAccept-Language: en-US\r\nAccept-Encoding: gzip\r\n\r\n"
	if containsStr(anomaliesOf(serveHTTPOnce(t, real)), "http-impossible-browser") {
		t.Errorf("genuine browser falsely flagged impossible")
	}
}

func TestHTTPMalformedAndDuplicateHost(t *testing.T) {
	// A header line with no colon is malformed.
	req := "GET / HTTP/1.1\r\nHost: x\r\nThisIsNotAHeader\r\n\r\n"
	if !containsStr(anomaliesOf(serveHTTPOnce(t, req)), "http-malformed-header") {
		t.Errorf("colon-less header not flagged malformed")
	}
	// Duplicate Host = smuggling tell.
	req = "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"
	if !containsStr(anomaliesOf(serveHTTPOnce(t, req)), "http-duplicate-host") {
		t.Errorf("duplicate Host not flagged")
	}
}

func TestImpossibleBrowserHelper(t *testing.T) {
	full := []string{"accept", "accept-language", "accept-encoding"}
	if impossibleBrowser("Mozilla/5.0 Chrome/120", full) {
		t.Errorf("browser with full Accept-* set wrongly flagged")
	}
	if !impossibleBrowser("Mozilla/5.0 Chrome/120", []string{"host"}) {
		t.Errorf("browser UA with no Accept-* not flagged")
	}
	if impossibleBrowser("curl/8.5.0", []string{"host"}) {
		t.Errorf("non-browser UA must not be flagged impossible-browser")
	}
}

func TestHTTPDoHStillDetected(t *testing.T) {
	// Regression: the DoH path detection coexists with the new header checks.
	req := "POST /dns-query HTTP/1.1\r\nHost: x\r\nContent-Type: application/dns-message\r\nContent-Length: 0\r\n\r\n"
	if !containsStr(anomaliesOf(serveHTTPOnce(t, req)), "dns-over-https") {
		t.Errorf("DoH not detected: %v", anomaliesOf(serveHTTPOnce(t, req)))
	}
}
