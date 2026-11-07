package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildHandlerView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		// A benign banner-grab (not an attack), earliest.
		{Handler: "ssh_interactive", Time: now.Add(-3 * time.Hour), Severity: event.SeverityLow,
			Source: event.Endpoint{IP: "1.1.1.1"}, Meta: map[string]any{"rdns": "scan.example"}},
		// A real attack: oversized password, high sev, with an anomaly + intent.
		{Handler: "ssh_interactive", RuleID: "ssh-oversized-password", Time: now.Add(-2 * time.Hour),
			Severity: event.SeverityHigh, Source: event.Endpoint{IP: "1.1.1.1"},
			Anomalies: []string{"ssh-oversized-password"},
			Meta:      map[string]any{"intent": "SSH oversized password", "tools": []string{"hydra"}, "rdns": "scan.example"}},
		// A successful engagement from an IPv6 attacker (shell session).
		{Handler: "ssh_interactive", Time: now.Add(-1 * time.Hour), Severity: event.SeverityCritical,
			Source:    event.Endpoint{IP: "2001:db8::1"},
			Anomalies: []string{"shell-reverse"},
			Meta:      map[string]any{"accepted_user": "root", "shell_commands": []string{"id", "wget evil"}}},
		// Noise from a different handler — must be excluded.
		{Handler: "http", Time: now, Severity: event.SeverityHigh, Source: event.Endpoint{IP: "9.9.9.9"}},
	}
	v := buildHandlerView("ssh_interactive", evs)

	if v.Attempts != 3 {
		t.Errorf("attempts = %d; want 3 (http excluded)", v.Attempts)
	}
	if v.Attacks != 2 {
		t.Errorf("attacks = %d; want 2", v.Attacks)
	}
	if v.Successful != 1 {
		t.Errorf("successful = %d; want 1", v.Successful)
	}
	if v.Sources != 2 {
		t.Errorf("sources = %d; want 2", v.Sources)
	}
	if v.FirstAttempt != now.Add(-3*time.Hour) {
		t.Errorf("first attempt wrong: %v", v.FirstAttempt)
	}
	if !v.HasAttack || v.FirstAttack != now.Add(-2*time.Hour) {
		t.Errorf("first attack wrong: %v (hasAttack=%v)", v.FirstAttack, v.HasAttack)
	}
	// IPv4 / IPv6 split.
	if len(v.IPv4) != 1 || v.IPv4[0].IP != "1.1.1.1" || v.IPv4[0].RDNS != "scan.example" {
		t.Errorf("IPv4 rows wrong: %+v", v.IPv4)
	}
	if len(v.IPv6) != 1 || v.IPv6[0].IP != "2001:db8::1" {
		t.Errorf("IPv6 rows wrong: %+v", v.IPv6)
	}
	// Intents + tools surfaced.
	var hasIntent bool
	for _, b := range v.Intents {
		if b.Label == "SSH oversized password" {
			hasIntent = true
		}
	}
	if !hasIntent {
		t.Errorf("intent not aggregated: %+v", v.Intents)
	}
	if len(v.Tools) != 1 || v.Tools[0] != "hydra" {
		t.Errorf("tools wrong: %v", v.Tools)
	}

	// Template renders without error.
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "handlerview", v); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"ssh_interactive", "attempts", "successful", "scan.example", "2001:db8::1", "/events?handler=ssh_interactive"} {
		if !strings.Contains(out, want) {
			t.Errorf("handlerview page missing %q", want)
		}
	}
}
