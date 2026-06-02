package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestBuildDashboard(t *testing.T) {
	sum := store.Summary{
		Since:      time.Now().Add(-24 * time.Hour),
		Total:      10,
		BySeverity: map[string]int{"low": 2, "high": 6, "critical": 2},
		ByRule:     map[string]int{"r1": 7, "r2": 3},
		TopSources: []store.SourceCount{{IP: "1.2.3.4", Count: 8}, {IP: "5.6.7.8", Count: 2}},
	}
	hours := []store.HourBucket{{Hour: time.Now().Add(-time.Hour), Count: 4}, {Hour: time.Now(), Count: 6}}
	d := buildDashboard(sum, hours)

	if len(d.Severity) != 3 {
		t.Errorf("severity bars = %d; want 3", len(d.Severity))
	}
	// "high" has the max severity count (6) → 100%.
	for _, b := range d.Severity {
		if b.Label == "high" && b.Pct != 100 {
			t.Errorf("high bar pct = %d; want 100", b.Pct)
		}
		if b.Label == "critical" && b.Class != "sev-critical" {
			t.Errorf("critical bar class = %q", b.Class)
		}
	}
	if len(d.Rules) != 2 || d.Rules[0].Label != "r1" {
		t.Errorf("rules bars wrong: %+v", d.Rules)
	}
	// Sources link to the profile page.
	if len(d.Sources) == 0 || d.Sources[0].Href != "/profiles/1.2.3.4" {
		t.Errorf("source href wrong: %+v", d.Sources)
	}
	if len(d.Trend) != 2 || d.Trend[1].Pct != 100 {
		t.Errorf("trend wrong: %+v", d.Trend)
	}
}

func TestHexDump(t *testing.T) {
	// base64 of "AB\x00\xff" → offset, hex, ascii with non-printables as '.'
	got := hexDump("QUL/AA==") // "AB\xff\x00"
	if !strings.Contains(got, "00000000") || !strings.Contains(got, "41 42") {
		t.Errorf("hexdump missing offset/hex: %q", got)
	}
	if !strings.Contains(got, "|AB") {
		t.Errorf("hexdump missing ascii: %q", got)
	}
	if hexDump("") != "" || hexDump("!!!not base64") != "" {
		t.Error("hexdump should return empty on empty / bad input")
	}
}

func TestDashboardTemplateRenders(t *testing.T) {
	tmpl := uiTmpl(t)
	d := buildDashboard(store.Summary{
		Total: 3, BySeverity: map[string]int{"high": 3}, ByRule: map[string]int{"webapp:sqli": 3},
		TopSources: []store.SourceCount{{IP: "9.9.9.9", Count: 3}},
	}, []store.HourBucket{{Hour: time.Now(), Count: 3}})
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "index", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "events per hour") || !strings.Contains(out, "class=\"bar") || !strings.Contains(out, "/profiles/9.9.9.9") {
		t.Errorf("dashboard missing charts: %q", out)
	}
}

func TestSummaryCountersRender(t *testing.T) {
	tmpl := uiTmpl(t)
	d := buildDashboard(store.Summary{Total: 5, ByProto: map[string]int{"tcp": 3, "udp": 2}}, nil)
	d.Counters = []counter{{Label: "events", Value: 5}, {Label: "TCP", Value: 3}, {Label: "UDP", Value: 2}}
	d.HasFrames = true
	d.Frames = []counter{{Label: "received", Value: 100}, {Label: "ARP", Value: 10}, {Label: "TCP", Value: 60}}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "index", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`class="counters"`, ">events<", ">TCP<", "L2 frames (sniffer)", ">received<", ">100<"} {
		if !strings.Contains(out, want) {
			t.Errorf("counters strip missing %q", want)
		}
	}
}

func TestEventDetailHexRenders(t *testing.T) {
	tmpl := uiTmpl(t)
	ev := &event.Event{ID: "x", RuleID: "r", Severity: event.SeverityHigh, Time: time.Now(),
		PayloadBase64: "QUJD", PayloadLen: 3, Meta: map[string]any{}}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, "event", ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "41 42 43") || !strings.Contains(b.String(), "|ABC|") {
		t.Errorf("event hex view missing: %q", b.String())
	}
}
