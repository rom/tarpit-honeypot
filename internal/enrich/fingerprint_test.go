package enrich

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

func TestDecorateFingerprintToolsSpoofedUA(t *testing.T) {
	// A browser User-Agent riding a no-ALPN (non-browser) JA4 → spoofed UA.
	ev := &event.Event{Meta: map[string]any{
		"ja4":        "t13d150600_abcdef012345_012345abcdef",
		"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/121.0",
	}}
	decorateFingerprintTools(ev)
	if sp, _ := ev.Meta["spoofed_ua"].(bool); !sp {
		t.Error("browser UA on non-browser JA4 should set spoofed_ua")
	}
	if ev.Meta["tls_automation"] == nil {
		t.Error("non-browser JA4 should set tls_automation")
	}
	if !containsStr(ev.Anomalies, "spoofed-user-agent") {
		t.Errorf("expected spoofed-user-agent anomaly, got %v", ev.Anomalies)
	}
}

func TestDecorateFingerprintToolsNoFalsePositive(t *testing.T) {
	// A browser-shaped JA4 (ALPN h2) must NOT be flagged.
	ev := &event.Event{Meta: map[string]any{
		"ja4":        "t13d1516h2_8daaf6152771_02713d6af862",
		"user_agent": "Mozilla/5.0 Chrome/121.0",
	}}
	decorateFingerprintTools(ev)
	if _, ok := ev.Meta["spoofed_ua"]; ok {
		t.Error("browser-shaped JA4 must not be flagged as spoofed")
	}
	if _, ok := ev.Meta["tls_automation"]; ok {
		t.Error("browser-shaped JA4 must not set tls_automation")
	}
	// An event with no fingerprints is untouched.
	empty := &event.Event{Meta: map[string]any{"user_agent": "x"}}
	decorateFingerprintTools(empty)
	if len(empty.Meta) != 1 {
		t.Errorf("event without fingerprints must be untouched, got %v", empty.Meta)
	}
}

// (containsStr is shared with feeds_test.go in this package.)

func TestDecorateFingerprintToolsPreservesTools(t *testing.T) {
	// Automation alone (no signature-map hit) must not set fp_tool or disturb an
	// existing UA-derived tools list — fp_tool means a fingerprint *named* a tool.
	ev := &event.Event{Meta: map[string]any{
		"ja4":   "t13d150600_abcdef012345_012345abcdef", // no-ALPN automation
		"tools": []string{"curl"},
	}}
	decorateFingerprintTools(ev)
	if _, ok := ev.Meta["fp_tool"]; ok {
		t.Error("automation without a signature match must not set fp_tool")
	}
	got, _ := ev.Meta["tools"].([]string)
	if len(got) != 1 || got[0] != "curl" {
		t.Errorf("existing tools must be preserved, got %v", got)
	}
	// IdentifyJA4 is the live attribution path; an unseeded value yields nothing.
	if toolfp.IdentifyJA4("t13d150600_abcdef012345_012345abcdef") != "" {
		t.Error("unseeded JA4 should not attribute a tool")
	}
}
