package ui

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestBuildProfileForensicObservables verifies the profile surfaces the
// captured artifacts, harvested URLs, requested domains/SNIs, and the
// honeytoken-reuse compromise signal — not just high-level counts.
func TestBuildProfileForensicObservables(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "malware:capture", Severity: event.SeverityHigh,
			Handler: "http", Source: event.Endpoint{IP: "7.7.7.7"}, Dest: event.Endpoint{Port: 80},
			Meta: map[string]any{
				"payload_artifacts": []any{"elf:deadbeef -> /tmp/x"},
				"harvested_urls":    []any{"http://evil.test/bot.sh"},
				"qname":             "c2.example.org", "sni": "vpn.corp",
				"ja4t": "64240_2-4",
			},
		},
		{
			ID: "2", Time: now.Add(time.Minute), RuleID: "canary:token_used", Severity: event.SeverityCritical,
			Handler: "vault", Source: event.Endpoint{IP: "7.7.7.7"},
			Meta: map[string]any{"reused_cred_key": "vault_token"},
		},
	}
	p := buildProfile("7.7.7.7", evs)

	if !p.TokenReuse {
		t.Error("expected TokenReuse=true after canary:token_used")
	}
	if p.Classification != "confirmed compromise — honeytoken reuse" {
		t.Errorf("classification = %q; want confirmed-compromise", p.Classification)
	}
	if !hasStr(p.Artifacts, "elf:deadbeef -> /tmp/x") {
		t.Errorf("artifacts missing: %v", p.Artifacts)
	}
	if !hasStr(p.URLs, "http://evil.test/bot.sh") {
		t.Errorf("harvested URLs missing: %v", p.URLs)
	}
	if !hasStr(p.Domains, "c2.example.org") || !hasStr(p.Domains, "vpn.corp") {
		t.Errorf("domains/SNIs missing: %v", p.Domains)
	}
	if p.Fingerprints["ja4t"] == "" {
		t.Errorf("ja4t fingerprint not captured: %v", p.Fingerprints)
	}
}
