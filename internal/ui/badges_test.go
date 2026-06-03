package ui

import (
	"strings"
	"testing"
)

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
	// No reputation → no badges.
	if h := string(sourceBadges(map[string]any{"geo_country": "US"})); h != "" {
		t.Errorf("benign meta should yield no badges, got %q", h)
	}
	// HTML-escaping of a hostile label value.
	if h := string(sourceBadges(map[string]any{"external_intel": "<script>"})); strings.Contains(h, "<script>") {
		t.Errorf("external_intel label not escaped: %q", h)
	}
}
