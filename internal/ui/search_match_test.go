package ui

import (
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// The full-text search must cover every field an operator can see — including
// the decoded payload bytes, the request line, nested HTTP headers (keys and
// values), and flattened meta — not just a few SQL columns.
func TestMatchesTextCoversAllFields(t *testing.T) {
	ev := &event.Event{
		RuleID:     "tcp:ssh",
		Handler:    "ssh",
		Proto:      "tcp",
		BannerSent: "SSH-2.0-OpenSSH_8.9",
		Anomalies:  []string{"tool:hydra"},
		Meta: map[string]any{
			"user_attempt": "root", "tools": []any{"hydra"},
			"request_line": "GET /admin HTTP/1.1",
			"http_headers": map[string]any{"X-Forwarded-For": "8.8.8.8", "User-Agent": "sqlmap/1.7"},
		},
		// payload contains a string that is NOT in any column or meta value
		PayloadBase64: base64.StdEncoding.EncodeToString([]byte("PASSWORD=Sup3rSecret!")),
	}
	ev.Source.IP = "203.0.113.7"
	ev.Dest.IP = "10.0.0.2"

	mustMatch := func(term string) bool {
		re := regexp.MustCompile("(?i)" + term)
		return matchesText(ev, re)
	}
	for _, term := range []string{
		"203\\.0\\.113",     // source IP (regex)
		"10\\.0\\.0\\.2",    // dest IP
		"ssh",               // handler / banner
		"hydra",             // anomaly + meta tools
		"root",              // meta value
		"sup3rsecret",       // decoded payload (case-insensitive)
		"password=sup3r",    // payload substring
		"GET /admin",        // request line (nested meta string)
		"x-forwarded-for",   // HTTP header NAME (nested map key)
		"8\\.8\\.8\\.8",     // HTTP header value
		"sqlmap",            // header value
		"^203|nowhere-too$", // alternation regex hits source IP
	} {
		if !mustMatch(term) {
			t.Errorf("matchesText should find %q", term)
		}
	}
	if mustMatch("this-string-appears-nowhere") {
		t.Error("matchesText false positive")
	}
}

func TestEventHasCVEandFingerprint(t *testing.T) {
	ev := &event.Event{RuleID: "cve:CVE-2021-44228", Meta: map[string]any{"ja3": "769,47-53,0-10"}}
	if !eventHasCVE(ev) {
		t.Error("should detect CVE rule")
	}
	if !matchesFingerprint(ev, "769,47") {
		t.Error("should match ja3 fingerprint substring")
	}
}
