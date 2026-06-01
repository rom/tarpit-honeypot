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

// TestBuildProfileNewSignals checks the SSH keys, SMTP senders, and
// web-attack-class surfacing added in the second depth pass.
func TestBuildProfileNewSignals(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{
			ID: "1", Time: now, RuleID: "listener:ssh", Severity: event.SeverityMedium,
			Handler: "ssh", Source: event.Endpoint{IP: "8.8.8.8"}, Dest: event.Endpoint{Port: 22},
			Meta: map[string]any{"ssh_pubkey_fps": []string{"ssh-rsa:SHA256:aaa", "ssh-ed25519:SHA256:bbb"}},
		},
		{
			ID: "2", Time: now, RuleID: "listener:smtp", Severity: event.SeverityLow,
			Handler: "smtp_recv", Source: event.Endpoint{IP: "8.8.8.8"}, Dest: event.Endpoint{Port: 25},
			Meta: map[string]any{"mail_from": "<spammer@evil.test>"},
		},
		{
			ID: "3", Time: now, RuleID: "listener:http", Severity: event.SeverityHigh,
			Handler: "http", Source: event.Endpoint{IP: "8.8.8.8"}, Dest: event.Endpoint{Port: 80},
			Anomalies: []string{"webapp:ssti", "webapp:xxe", "webapp:nosqli"},
		},
	}
	p := buildProfile("8.8.8.8", evs)

	if len(p.SSHKeys) != 2 {
		t.Errorf("ssh keys = %v; want 2", p.SSHKeys)
	}
	if !hasStr(p.Emails, "spammer@evil.test") {
		t.Errorf("emails missing sender: %v", p.Emails)
	}
	if len(p.AttackClasses) != 3 {
		t.Errorf("attack classes = %v; want 3", p.AttackClasses)
	}
	// 3+ distinct web-attack classes => web application attack.
	if p.Classification != "web application attack" {
		t.Errorf("classification = %q; want web application attack", p.Classification)
	}
}
