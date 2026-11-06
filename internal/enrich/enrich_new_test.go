package enrich

import (
	"context"
	"testing"
	"time"
)

// TestReputationConfidence covers the cross-feed corroboration count and its
// low/medium/high label: one list -> low, two lists -> medium, plus an external
// feed -> high. A clean IP gets neither field.
func TestReputationConfidence(t *testing.T) {
	l1 := writeList(t, "a.txt", "203.0.113.9\n198.51.100.5\n")
	l2 := writeList(t, "b.txt", "203.0.113.9\n")
	e, err := New(Config{ThreatLists: []ThreatList{{Label: "feedA", File: l1}, {Label: "feedB", File: l2}}})
	if err != nil {
		t.Fatal(err)
	}

	// On one list only -> count 1 -> low.
	ev := evt("198.51.100.5")
	e.Decorate(ev)
	if ev.Meta["threat_intel_count"] != 1 || ev.Meta["threat_confidence"] != "low" {
		t.Errorf("one list: count=%v confidence=%v; want 1/low (%v)", ev.Meta["threat_intel_count"], ev.Meta["threat_confidence"], ev.Meta)
	}

	// On two lists -> count 2 -> medium.
	ev = evt("203.0.113.9")
	e.Decorate(ev)
	if ev.Meta["threat_intel_count"] != 2 || ev.Meta["threat_confidence"] != "medium" {
		t.Errorf("two lists: count=%v confidence=%v; want 2/medium (%v)", ev.Meta["threat_intel_count"], ev.Meta["threat_confidence"], ev.Meta)
	}

	// Two lists + an external-feed hit -> count 3 -> high.
	e.SetExternalIntel(map[string]string{"203.0.113.9": "greynoise"})
	ev = evt("203.0.113.9")
	e.Decorate(ev)
	if ev.Meta["threat_intel_count"] != 3 || ev.Meta["threat_confidence"] != "high" {
		t.Errorf("two lists + external: count=%v confidence=%v; want 3/high (%v)", ev.Meta["threat_intel_count"], ev.Meta["threat_confidence"], ev.Meta)
	}

	// A clean IP: no confidence fields at all.
	ev = evt("1.1.1.1")
	e.Decorate(ev)
	if _, ok := ev.Meta["threat_intel_count"]; ok {
		t.Errorf("clean IP got a confidence count: %v", ev.Meta)
	}
}

// TestFCrDNSCrawlerVerification covers forward-confirmed reverse DNS: a PTR that
// claims a well-known crawler is forward-confirmed (verified), one that fails
// confirmation is flagged spoofed, and a non-crawler PTR is left unverified.
func TestFCrDNSCrawlerVerification(t *testing.T) {
	e, err := New(Config{RDNSEnabled: true, RDNSTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e.rdns.lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		switch ip {
		case "66.249.66.1":
			return []string{"crawl-66-249-66-1.googlebot.com."}, nil // real googlebot
		case "1.2.3.4":
			return []string{"fake-crawler.googlebot.com."}, nil // claims googlebot
		case "9.9.9.9":
			return []string{"dns.quad9.net."}, nil // ordinary PTR, no crawler claim
		}
		return nil, nil
	}
	e.rdns.lookupHost = func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "crawl-66-249-66-1.googlebot.com":
			return []string{"66.249.66.1"}, nil // forward-confirms
		case "fake-crawler.googlebot.com":
			return []string{"203.0.113.50"}, nil // resolves elsewhere -> spoofed
		}
		return nil, nil
	}

	// decorateUntil re-decorates a fresh event for ip until check passes (the
	// first sighting kicks off the async resolve; a later one picks up the result).
	decorateUntil := func(ip string, desc string, check func(m map[string]any) bool) {
		t.Helper()
		var last map[string]any
		ok := waitFor(2*time.Second, func() bool {
			ev := evt(ip)
			e.Decorate(ev)
			last = ev.Meta
			return check(ev.Meta)
		})
		if !ok {
			t.Errorf("%s: meta never satisfied: %v", desc, last)
		}
	}

	decorateUntil("66.249.66.1", "verified googlebot", func(m map[string]any) bool {
		return m["rdns_verified"] == true && m["verified_crawler"] == "googlebot"
	})
	decorateUntil("1.2.3.4", "spoofed googlebot", func(m map[string]any) bool {
		return m["spoofed_ptr"] == true && m["spoofed_crawler"] == "googlebot" && m["rdns_verified"] == false
	})
	decorateUntil("9.9.9.9", "non-crawler PTR", func(m map[string]any) bool {
		_, verified := m["rdns_verified"]
		return m["rdns"] == "dns.quad9.net" && !verified
	})
}

// TestCrawlerClaim covers the PTR-suffix matcher directly.
func TestCrawlerClaim(t *testing.T) {
	cases := map[string]string{
		"crawl-1.googlebot.com":      "googlebot",
		"msnbot-1.search.msn.com":    "bingbot",
		"1.2.3.4.crawl.baidu.com":    "baidu",
		"spider.yandex.com.":         "yandex", // trailing dot tolerated
		"host.example.com":           "",
		"googlebot.com.evil.example": "", // suffix must actually end the name
	}
	for in, want := range cases {
		if got := crawlerClaim(in); got != want {
			t.Errorf("crawlerClaim(%q) = %q; want %q", in, got, want)
		}
	}
}
