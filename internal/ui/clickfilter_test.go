package ui

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func evWithMeta(m map[string]any) *event.Event {
	return &event.Event{Meta: m}
}

func TestEventHasIntent(t *testing.T) {
	ev := evWithMeta(map[string]any{"intent": "DNS amplification — staging a DRDoS reflector"})
	if !eventHasIntent(ev, "DNS amplification — staging a DRDoS reflector") {
		t.Error("exact intent should match")
	}
	if !eventHasIntent(ev, "dns amplification — STAGING a DRDoS reflector") {
		t.Error("intent match should be case-insensitive")
	}
	if eventHasIntent(ev, "port scan") {
		t.Error("different intent must not match")
	}
	if eventHasIntent(ev, "") {
		t.Error("empty intent must not match")
	}
	if eventHasIntent(evWithMeta(map[string]any{}), "x") {
		t.Error("no intent meta must not match")
	}
}

func TestEventHasLabel(t *testing.T) {
	ev := evWithMeta(map[string]any{"labels": []string{"meta:ot-recon", "meta:corroborated-threat"}})
	for _, name := range []string{"ot-recon", "OT-RECON", "meta:ot-recon", "corroborated-threat"} {
		if !eventHasLabel(ev, name) {
			t.Errorf("label %q should match", name)
		}
	}
	if eventHasLabel(ev, "targeted-recon") {
		t.Error("absent label must not match")
	}
	if eventHasLabel(ev, "") {
		t.Error("empty label must not match")
	}
}

func TestEventHasFlagNewCases(t *testing.T) {
	if !eventHasFlag(evWithMeta(map[string]any{"backscatter_kind": "syn-ack"}), "backscatter") {
		t.Error("backscatter_kind should satisfy flag=backscatter")
	}
	if !eventHasFlag(evWithMeta(map[string]any{"agent_leak_api_key": "sk-x"}), "counter-exfil") {
		t.Error("agent_leak_api_key should satisfy flag=counter-exfil")
	}
	if !eventHasFlag(evWithMeta(map[string]any{"agent_leak_system_prompt": "you are"}), "counter-exfil") {
		t.Error("agent_leak_system_prompt should satisfy flag=counter-exfil")
	}
	if !eventHasFlag(evWithMeta(map[string]any{"threat_confidence": "high"}), "threat-conf") {
		t.Error("threat_confidence should satisfy flag=threat-conf")
	}
	if eventHasFlag(evWithMeta(map[string]any{}), "backscatter") {
		t.Error("no meta must not satisfy a flag")
	}
}

func TestIntentLinkRendersFilterAnchor(t *testing.T) {
	h := string(intentLink("DNS amplification — staging a DRDoS reflector"))
	if !strings.Contains(h, `href="/events?intent=`) {
		t.Errorf("intentLink should link to the intent filter: %s", h)
	}
	if !strings.Contains(h, "DRDoS reflector") {
		t.Errorf("intentLink should show the intent text: %s", h)
	}
	if intentLink("") != "" {
		t.Error("empty intent should render nothing")
	}
}

func TestFingerprintBadgesAndFlags(t *testing.T) {
	// Spoofed-UA (browser UA on non-browser TLS) renders a clickable badge.
	h := string(sourceBadges(map[string]any{"spoofed_ua": true}))
	if !strings.Contains(h, `href="/events?flag=spoofed-ua"`) {
		t.Errorf("spoofed_ua should render a clickable badge: %s", h)
	}
	// tls_automation (no spoofed UA) renders its own badge.
	h2 := string(sourceBadges(map[string]any{"tls_automation": "non-browser TLS (no ALPN)"}))
	if !strings.Contains(h2, `href="/events?flag=tls-automation"`) {
		t.Errorf("tls_automation should render a clickable badge: %s", h2)
	}
	// The new flags resolve in eventHasFlag so the badge click filters correctly.
	if !eventHasFlag(evWithMeta(map[string]any{"spoofed_ua": true}), "spoofed-ua") {
		t.Error("spoofed_ua should satisfy flag=spoofed-ua")
	}
	if !eventHasFlag(evWithMeta(map[string]any{"tls_automation": "x"}), "tls-automation") {
		t.Error("tls_automation should satisfy flag=tls-automation")
	}
	if !eventHasFlag(evWithMeta(map[string]any{"fp_tool": true}), "fp-tool") {
		t.Error("fp_tool should satisfy flag=fp-tool")
	}
}

func TestSourceBadgesCompositeLabelIsClickable(t *testing.T) {
	h := string(sourceBadges(map[string]any{"labels": []string{"meta:ot-recon"}}))
	if !strings.Contains(h, `href="/events?label=ot-recon"`) {
		t.Errorf("composite recognition label should link to the label filter: %s", h)
	}
	// c2 framework badge links to the c2 pivot.
	h2 := string(sourceBadges(map[string]any{"c2_framework": "Cobalt Strike"}))
	if !strings.Contains(h2, `href="/events?c2=`) {
		t.Errorf("c2 badge should be clickable: %s", h2)
	}
}
