package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestEventsCloudFilter(t *testing.T) {
	s := fleetTestServer(t) // store + templates
	ctx := context.Background()
	ins := func(id, ip, cloud string) {
		ev := &event.Event{ID: id, Time: time.Now().UTC(), RuleID: "listener:http",
			Severity: event.SeverityLow, Source: event.Endpoint{IP: ip}, Meta: map[string]any{}}
		if cloud != "" {
			ev.Meta["cloud_provider"] = cloud
		}
		if err := s.store.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	ins("a", "203.0.113.1", "aws")
	ins("b", "198.51.100.2", "") // residential, no cloud tag

	w := httptest.NewRecorder()
	s.handleEvents(w, httptest.NewRequest(http.MethodGet, "/events?cloud=aws", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "203.0.113.1") {
		t.Error("aws-tagged event missing under ?cloud=aws")
	}
	if strings.Contains(body, "198.51.100.2") {
		t.Error("non-cloud event leaked into ?cloud=aws")
	}
}

func TestEventHasFlagCloudHosting(t *testing.T) {
	cloud := &event.Event{Meta: map[string]any{"cloud_provider": "aws"}}
	host := &event.Event{Meta: map[string]any{"net_class": "hosting"}}
	resid := &event.Event{Meta: map[string]any{"geo_country": "US"}}

	if !eventHasFlag(cloud, "cloud") || !eventHasFlag(cloud, "hosting") {
		t.Error("cloud_provider event should match flag=cloud and flag=hosting")
	}
	if eventHasFlag(host, "cloud") {
		t.Error("net_class=hosting (no cloud_provider) must not match flag=cloud")
	}
	if !eventHasFlag(host, "hosting") {
		t.Error("net_class=hosting should match flag=hosting")
	}
	if eventHasFlag(resid, "cloud") || eventHasFlag(resid, "hosting") {
		t.Error("residential event should match neither cloud nor hosting")
	}
}

func TestPageRange(t *testing.T) {
	// Default (no param) -> 24h, active chip is 24h, link to bare base.
	dur, key, label, links := pageRange(httptest.NewRequest("GET", "/tunnels", nil), "/tunnels")
	if key != "24h" || label != "last 24 hours" || dur != 24*time.Hour {
		t.Errorf("default range: dur=%v key=%q label=%q", dur, key, label)
	}
	if len(links) != len(summaryRanges) || !links[0].Active || links[0].Href != "/tunnels" {
		t.Errorf("default links wrong: %+v", links)
	}
	// ?range=7d -> ~7d window, the 7d chip active and others linkable.
	dur, key, _, links = pageRange(httptest.NewRequest("GET", "/correlation?range=7d", nil), "/correlation")
	if key != "7d" || dur != 7*24*time.Hour {
		t.Errorf("7d range: dur=%v key=%q", dur, key)
	}
	var sevenActive bool
	for _, l := range links {
		if l.Label == "7d" {
			sevenActive = l.Active
		}
		if l.Label == "31d" && l.Href != "/correlation?range=31d" {
			t.Errorf("31d chip href = %q", l.Href)
		}
	}
	if !sevenActive {
		t.Error("7d chip should be active for ?range=7d")
	}
	// Unknown range falls back to 24h.
	_, key, _, _ = pageRange(httptest.NewRequest("GET", "/attack?range=bogus", nil), "/attack")
	if key != "24h" {
		t.Errorf("unknown range should fall back to 24h, got %q", key)
	}
	// Other filters are preserved on the chips (e.g. the /iocs ?type= filter).
	_, _, _, links = pageRange(httptest.NewRequest("GET", "/iocs?type=ja4&range=7d", nil), "/iocs")
	for _, l := range links {
		if l.Label == "31d" && !strings.Contains(l.Href, "type=ja4") {
			t.Errorf("31d chip dropped the type filter: %q", l.Href)
		}
		if l.Label == "24h" && l.Href != "/iocs?type=ja4" {
			t.Errorf("24h chip should be the bare filtered path, got %q", l.Href)
		}
	}
}

func TestCountryFlag(t *testing.T) {
	cases := map[string]string{"US": "🇺🇸", "JP": "🇯🇵", "us": "🇺🇸", "": "", "USA": "", "1A": ""}
	for in, want := range cases {
		if got := countryFlag(in); got != want {
			t.Errorf("countryFlag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSourceBadges(t *testing.T) {
	html := string(sourceBadges(map[string]any{
		"threat_intel": []any{"firehol", "spamhaus"},
		"tor_exit":     true,
	}))
	if !strings.Contains(html, "blacklist") || !strings.Contains(html, "tor") {
		t.Errorf("badges missing blacklist/tor: %q", html)
	}
	if !strings.Contains(html, "firehol") { // labels carried in the title attr
		t.Errorf("badge title should name the list: %q", html)
	}

	// Known scanner via enrichment.
	if h := string(sourceBadges(map[string]any{"known_scanner": "censys"})); !strings.Contains(h, "scanner:censys") {
		t.Errorf("known_scanner badge missing: %q", h)
	}
	// Known scanner via self-identified tool.
	if h := string(sourceBadges(map[string]any{"tools": []any{"shodan"}})); !strings.Contains(h, "scanner:shodan") {
		t.Errorf("scanner-tool badge missing: %q", h)
	}
	// Cloud-provider CIDR tagging surfaces a per-provider badge linking to the
	// per-provider events filter.
	if h := string(sourceBadges(map[string]any{"cloud_provider": "aws"})); !strings.Contains(h, "cloud:aws") || !strings.Contains(h, `href="/events?cloud=aws"`) {
		t.Errorf("cloud_provider badge/href missing: %q", h)
	}
	// net_class hosting badge when there's no more-specific cloud provider.
	if h := string(sourceBadges(map[string]any{"net_class": "hosting"})); !strings.Contains(h, "hosting") {
		t.Errorf("hosting badge missing: %q", h)
	}
	// cloud_provider takes precedence over the generic hosting badge.
	if h := string(sourceBadges(map[string]any{"cloud_provider": "gcp", "net_class": "hosting"})); strings.Contains(h, ">hosting<") {
		t.Errorf("hosting badge should be suppressed when cloud_provider is set: %q", h)
	}
	// No reputation → no badges.
	if h := string(sourceBadges(map[string]any{"geo_country": "US"})); h != "" {
		t.Errorf("benign meta should yield no badges, got %q", h)
	}
	// HTML-escaping of a hostile label value.
	if h := string(sourceBadges(map[string]any{"external_intel": "<script>"})); strings.Contains(h, "<script>") {
		t.Errorf("external_intel label not escaped: %q", h)
	}
}
