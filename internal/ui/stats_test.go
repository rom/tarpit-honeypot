package ui

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestHumanInt(t *testing.T) {
	cases := map[int]string{0: "0", 42: "42", 999: "999", 1000: "1,000", 12345: "12,345", 1234567: "1,234,567"}
	for n, want := range cases {
		if got := humanInt(n); got != want {
			t.Errorf("humanInt(%d) = %q; want %q", n, got, want)
		}
	}
}

func TestBuildStatsView(t *testing.T) {
	sum := store.Summary{
		Total:      1000,
		BySeverity: map[string]int{"high": 200, "critical": 50, "low": 750},
		ByProto:    map[string]int{"tcp": 800, "udp": 200},
		TopSources: []store.SourceCount{{IP: "10.0.0.1", Count: 300}, {IP: "10.0.0.2", Count: 100}},
	}
	d := dashboard{Sum: sum}
	v := buildStatsView(d, sum, summaryRange("24h"))
	if len(v.Headline) == 0 {
		t.Fatal("no headline metrics")
	}
	// First headline is the authoritative event total.
	if v.Headline[0].Value != "1,000" {
		t.Errorf("event total = %q; want 1,000", v.Headline[0].Value)
	}
	// High+Critical = 250 = 25%.
	if v.Headline[1].Value != "250" || !strings.Contains(v.Headline[1].Sub, "25%") {
		t.Errorf("high+crit metric = %+v", v.Headline[1])
	}
	// Protocol + source blocks must be present and ranked.
	var protoRows, srcRows []barRow
	for _, b := range v.Blocks {
		if b.Title == "Transport / protocol" {
			protoRows = b.Rows
		}
		if b.Title == "Top attacker sources" {
			srcRows = b.Rows
		}
	}
	if len(protoRows) == 0 || protoRows[0].Label != "tcp" {
		t.Errorf("proto block not ranked tcp-first: %+v", protoRows)
	}
	if len(srcRows) == 0 || srcRows[0].Label != "10.0.0.1" {
		t.Errorf("source block not ranked: %+v", srcRows)
	}
}

func TestAnnotateToolVendors(t *testing.T) {
	rows := annotateToolVendors([]barRow{{Label: "nuclei", Count: 5}, {Label: "unknowntool", Count: 1}})
	if !strings.Contains(rows[0].Label, "ProjectDiscovery") {
		t.Errorf("nuclei vendor not annotated: %q", rows[0].Label)
	}
	if rows[1].Label != "unknowntool" {
		t.Errorf("unknown tool should be unchanged: %q", rows[1].Label)
	}
}
