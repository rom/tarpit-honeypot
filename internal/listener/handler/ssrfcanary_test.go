package handler

import (
	"bytes"
	"strings"
	"testing"
)

func TestSSRFCanaryServerSideFetchFlagged(t *testing.T) {
	resp, res := roundTrip(t, &ssrfCanary{},
		"GET /ssrf/deadbeefcafe-prod HTTP/1.1\r\nHost: oob.canary.example.com\r\n"+
			"User-Agent: python-requests/2.31.0\r\nX-Forwarded-For: 10.1.2.3\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200, got %q", resp[:min2(30, len(resp))])
	}
	if !strings.Contains(resp, "Content-Type: image/gif") {
		t.Errorf("expected gif response, got headers: %q", resp)
	}
	if res.Meta["ssrf_token"] != "deadbeefcafe-prod" {
		t.Errorf("ssrf_token = %v, want deadbeefcafe-prod", res.Meta["ssrf_token"])
	}
	if res.Meta["x_forwarded_for"] != "10.1.2.3" {
		t.Errorf("x_forwarded_for not captured: %v", res.Meta["x_forwarded_for"])
	}
	if !hasAnomaly(res, "ssrf-callback") {
		t.Errorf("ssrf-callback not flagged: %v", anomaliesOf(res))
	}
	if !hasAnomaly(res, "ssrf-server-side-fetch") {
		t.Errorf("server-side fetch (python-requests) not flagged: %v", anomaliesOf(res))
	}
}

func TestSSRFCanaryBrowserNotServerSide(t *testing.T) {
	_, res := roundTrip(t, &ssrfCanary{},
		"GET /ssrf/tok HTTP/1.1\r\nHost: x\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36\r\n\r\n")
	if !hasAnomaly(res, "ssrf-callback") {
		t.Errorf("every callback must flag ssrf-callback")
	}
	if hasAnomaly(res, "ssrf-server-side-fetch") {
		t.Errorf("a real browser UA should not be flagged server-side")
	}
}

func TestSSRFCanaryReturnsValidGIF(t *testing.T) {
	resp, _ := roundTrip(t, &ssrfCanary{}, "GET /ssrf/x HTTP/1.1\r\nHost: x\r\n\r\n")
	i := strings.Index(resp, "\r\n\r\n")
	if i < 0 {
		t.Fatal("no body separator")
	}
	body := []byte(resp[i+4:])
	if !bytes.HasPrefix(body, []byte("GIF89a")) {
		t.Errorf("body is not a GIF89a image: % x", body[:min2(6, len(body))])
	}
}

func TestSSRFToken(t *testing.T) {
	cases := map[string]string{
		"/ssrf/abc":        "abc",
		"/ssrf/abc?x=1":    "abc",
		"/a/b/c":           "c",
		"/tok/":            "tok",
		"/":                "",
		"":                 "",
		"/deep/path/token": "token",
	}
	for in, want := range cases {
		if got := ssrfToken(in); got != want {
			t.Errorf("ssrfToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksServerSideFetcher(t *testing.T) {
	server := []string{"", "curl/8.0", "python-requests/2.31", "Go-http-client/1.1", "Java/17"}
	for _, ua := range server {
		if !looksServerSideFetcher(ua) {
			t.Errorf("%q should be detected as server-side", ua)
		}
	}
	browser := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
	if looksServerSideFetcher(browser) {
		t.Errorf("browser UA wrongly flagged server-side")
	}
}
