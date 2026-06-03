package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildCorrelationView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{RuleID: "listener:tls", Handler: "https", Severity: event.SeverityHigh,
			Source: event.Endpoint{IP: "9.9.9.9"}, Time: now,
			Meta: map[string]any{"ja4": "t13d", "user_agent": "sqlmap/1.7", "geo_country": "RU",
				"asn": 64500, "asn_org": "EvilNet", "tools": []any{"sqlmap"}}},
		{RuleID: "listener:ssh", Handler: "ssh", Severity: event.SeverityCritical,
			Source: event.Endpoint{IP: "9.9.9.9"}, Time: now,
			Meta: map[string]any{"auth_user": "root", "auth_pass": "toor"}},
	}
	v := buildCorrelationView(now.Add(-time.Hour), evs)
	if len(v.Sources) != 1 {
		t.Fatalf("want 1 source, got %d", len(v.Sources))
	}
	s := v.Sources[0]
	if s.IP != "9.9.9.9" || s.MaxSev != "critical" {
		t.Errorf("source wrong: %+v", s)
	}
	if len(s.FPs) != 1 || s.FPs[0].Kind != "ja4" {
		t.Errorf("fingerprint chain wrong: %+v", s.FPs)
	}
	if !containsStr3(s.Tools, "sqlmap") || !containsStr3(s.Creds, "root : toor") {
		t.Errorf("tools/creds chain wrong: tools=%v creds=%v", s.Tools, s.Creds)
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "correlation", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"correlation", "9.9.9.9", `/fingerprints/ja4/t13d`, "sqlmap", "root : toor"} {
		if !strings.Contains(html, want) {
			t.Errorf("correlation page missing %q", want)
		}
	}
}

func TestBuildTunnelsView(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{RuleID: "sniffer:encapsulation", Source: event.Endpoint{IP: "1.1.1.1"}, Time: now,
			Meta: map[string]any{"encap_type": "6to4"}},
		{RuleID: "listener:dns", Handler: "dns", Source: event.Endpoint{IP: "2.2.2.2"}, Time: now,
			Meta: map[string]any{"anomalies": []any{"dns-tunnel-suspected"}, "qname": "x.exfil.example"}},
		{RuleID: "listener:auto", Handler: "auto", Source: event.Endpoint{IP: "3.3.3.3"}, Time: now,
			Meta: map[string]any{"protocol_guess": "quic"}},
	}
	v := buildTunnelsView(now.Add(-time.Hour), evs)
	kinds := map[string]bool{}
	for _, b := range v.Types {
		kinds[b.Label] = true
	}
	for _, want := range []string{"encapsulation", "dns-tunnel", "quic"} {
		if !kinds[want] {
			t.Errorf("tunnel type %q missing: %+v", want, v.Types)
		}
	}
	if len(v.Recent) != 3 {
		t.Errorf("want 3 recent hits, got %d", len(v.Recent))
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "tunnels", v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "detections, not established tunnels") {
		t.Error("tunnels page should carry the honesty disclaimer")
	}
}

func TestSearchViewRenders(t *testing.T) {
	// Form-only render (no search executed).
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "search", searchView{Q: searchQuery{}}); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"advanced search", "ATT&amp;CK tactic", "decoded payload", "has credential", "fingerprint",
		`name="after"`, `name="before"`, `name="on"`, "regular expressions"} {
		if !strings.Contains(html, want) {
			t.Errorf("search form missing %q", want)
		}
	}
}

func TestSearchQueryEmpty(t *testing.T) {
	if !(searchQuery{}).empty() {
		t.Error("zero query should be empty")
	}
	if (searchQuery{Tool: "nmap"}).empty() {
		t.Error("query with a field set is not empty")
	}
}

func containsStr3(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
