package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// handlerLink / protoTag turn a handler / transport into a clickable pivot.
func TestHandlerLinkAndProtoTag(t *testing.T) {
	h := string(handlerLink("ftp_files"))
	if !strings.Contains(h, `href="/events?handler=ftp_files"`) || !strings.Contains(h, ">ftp_files<") {
		t.Errorf("handlerLink wrong: %q", h)
	}
	if got := string(handlerLink("")); got != "—" {
		t.Errorf("empty handlerLink = %q; want dash", got)
	}
	p := string(protoTag("TCP"))
	if !strings.Contains(p, `href="/events?proto=tcp"`) || !strings.Contains(p, "proto-tcp") || !strings.Contains(p, ">tcp<") {
		t.Errorf("protoTag wrong: %q", p)
	}
	if string(protoTag("")) != "" {
		t.Error("empty protoTag should be empty")
	}
}

// sourceBadges must now emit links: scanner -> tool filter, the reputation
// flags -> the events flag filter.
func TestSourceBadgesAreLinks(t *testing.T) {
	html := string(sourceBadges(map[string]any{
		"threat_intel":  []string{"abuseipdb"},
		"tor_exit":      true,
		"known_scanner": "censys",
		"net_class":     "bogon",
	}))
	for _, want := range []string{
		`href="/events?flag=blacklist"`, ">blacklist<",
		`href="/events?flag=tor"`, ">tor<",
		`href="/events?tool=censys"`, "scanner:censys",
		`href="/events?flag=bogon"`, ">bogon<",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("sourceBadges missing %q in %q", want, html)
		}
	}
	if sourceBadges(nil) != "" {
		t.Error("empty meta should yield no badges")
	}
}

// eventHasFlag mirrors the badge logic so a badge click lists exactly its events.
func TestEventHasFlag(t *testing.T) {
	ev := &event.Event{Meta: map[string]any{
		"threat_intel": []string{"spamhaus"}, "tor_exit": true,
		"net_class": "bogon", "known_scanner": "shodan", "external_intel": "greynoise",
	}}
	for _, f := range []string{"blacklist", "tor", "bogon", "scanner", "intel"} {
		if !eventHasFlag(ev, f) {
			t.Errorf("eventHasFlag(%q) = false; want true", f)
		}
	}
	clean := &event.Event{Meta: map[string]any{}}
	if eventHasFlag(clean, "blacklist") || eventHasFlag(clean, "tor") || eventHasFlag(ev, "nonsense") {
		t.Error("eventHasFlag should be false for clean event / unknown flag")
	}
}

func TestEventCVEsAndTechName(t *testing.T) {
	ev := &event.Event{
		RuleID:    "cve:CVE-2021-44228",
		Anomalies: []string{"cve:CVE-2021-44228", "http-method-unknown"},
		Meta:      map[string]any{"emulated_vuln_cves": []string{"CVE-2024-4040"}},
	}
	got := eventCVEs(ev)
	if len(got) != 2 {
		t.Fatalf("eventCVEs = %v; want 2 distinct", got)
	}
	seen := map[string]bool{}
	for _, c := range got {
		seen[c] = true
	}
	if !seen["CVE-2021-44228"] || !seen["CVE-2024-4040"] {
		t.Errorf("eventCVEs missing expected ids: %v", got)
	}
	// A non-CVE event yields nothing.
	if len(eventCVEs(&event.Event{RuleID: "ssh-brute-force"})) != 0 {
		t.Error("non-CVE event should yield no CVEs")
	}
	if n := techShortName("T1595"); n != "Active Scanning" {
		t.Errorf("techShortName(T1595) = %q; want Active Scanning", n)
	}
}

// enrichDashboard must populate the two new top lists distinctly: Attacks from
// ATT&CK techniques, CVEs from vulnerability markers.
func TestEnrichDashboardAttacksAndCVEs(t *testing.T) {
	evs := []*event.Event{
		{Handler: "ssh", RuleID: "ssh-brute-force", Meta: map[string]any{}},
		{Handler: "http", RuleID: "cve:CVE-2021-44228", Anomalies: []string{"cve:CVE-2021-44228"}, Meta: map[string]any{}},
		{Handler: "http", RuleID: "cve:CVE-2021-44228", Anomalies: []string{"cve:CVE-2021-44228"}, Meta: map[string]any{}},
	}
	var d dashboard
	enrichDashboard(&d, evs)

	if len(d.CVEs) == 0 {
		t.Fatal("expected at least one top vulnerability")
	}
	if d.CVEs[0].Label != "CVE-2021-44228" || d.CVEs[0].Count != 2 {
		t.Errorf("top CVE = %+v; want CVE-2021-44228 x2", d.CVEs[0])
	}
	if !strings.HasPrefix(d.CVEs[0].Href, "/search?q=CVE-2021-44228") {
		t.Errorf("CVE href = %q", d.CVEs[0].Href)
	}
	if len(d.Attacks) == 0 {
		t.Fatal("expected at least one top attack (technique)")
	}
	for _, a := range d.Attacks {
		if !strings.HasPrefix(a.Href, "/attack/technique?id=") {
			t.Errorf("attack href = %q; want technique drill-down", a.Href)
		}
	}
}

// The summary page renders the two new sections, and a CVE label links to its
// search.
func TestSummaryShowsAttacksAndVulns(t *testing.T) {
	tmpl := uiTmpl(t)
	d := buildDashboard(store.Summary{Total: 1, BySeverity: map[string]int{"high": 1}}, []store.HourBucket{{Hour: time.Now(), Count: 1}}, time.Hour)
	d.RangeLabel = "last 24 hours"
	d.RangeLinks = summaryRangeLinks("24h")
	d.Attacks = []barRow{{Label: "T1190 · Exploit Public-Facing App", Count: 4, Pct: 100, Href: "/attack/technique?id=T1190"}}
	d.CVEs = []barRow{{Label: "CVE-2021-44228", Count: 3, Pct: 100, Href: "/search?q=CVE-2021-44228"}}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "index", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"top attacks", "top vulnerabilities", "/attack/technique?id=T1190", "/search?q=CVE-2021-44228", "CVE-2021-44228"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q", want)
		}
	}
}
