package config

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestCompileSeverityOverridesExactAndPrefix(t *testing.T) {
	set, err := CompileSeverityOverrides([]SeverityOverride{
		{Rule: "cve:*", Severity: "high"},
		{Rule: "cve:CVE-2021-44228", Severity: "critical"},
		{Rule: "correlate:port_scan", Severity: "medium"},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if set.Len() != 3 {
		t.Errorf("Len = %d; want 3", set.Len())
	}
	// Exact wins over prefix.
	if sev, match, ok := set.Apply("cve:CVE-2021-44228"); !ok || sev != event.SeverityCritical || match != "cve:CVE-2021-44228" {
		t.Errorf("exact: got %v %q %v", sev, match, ok)
	}
	// Prefix matches other cve ids.
	if sev, match, ok := set.Apply("cve:CVE-2024-1709"); !ok || sev != event.SeverityHigh || match != "cve:*" {
		t.Errorf("prefix: got %v %q %v", sev, match, ok)
	}
	// Exact non-cve.
	if sev, _, ok := set.Apply("correlate:port_scan"); !ok || sev != event.SeverityMedium {
		t.Errorf("exact correlate: got %v %v", sev, ok)
	}
	// No match.
	if _, _, ok := set.Apply("listener:ssh-bait"); ok {
		t.Errorf("unexpected match for unrelated rule")
	}
}

func TestCompileSeverityOverridesLongestPrefixWins(t *testing.T) {
	set, _ := CompileSeverityOverrides([]SeverityOverride{
		{Rule: "correlate:*", Severity: "low"},
		{Rule: "correlate:ot_*", Severity: "critical"},
	})
	if sev, match, _ := set.Apply("correlate:ot_kill_chain"); sev != event.SeverityCritical || match != "correlate:ot_*" {
		t.Errorf("longest prefix should win: got %v %q", sev, match)
	}
	if sev, _, _ := set.Apply("correlate:port_scan"); sev != event.SeverityLow {
		t.Errorf("shorter prefix should match the rest: got %v", sev)
	}
}

func TestCompileSeverityOverridesErrors(t *testing.T) {
	if _, err := CompileSeverityOverrides([]SeverityOverride{{Rule: "x", Severity: "bogus"}}); err == nil {
		t.Error("bad severity should error")
	}
	if _, err := CompileSeverityOverrides([]SeverityOverride{{Rule: "", Severity: "low"}}); err == nil {
		t.Error("empty rule should error")
	}
}

func TestValidateRejectsBadOverride(t *testing.T) {
	c := &Config{SeverityOverrides: []SeverityOverride{{Rule: "cve:*", Severity: "nope"}}}
	if err := c.Validate(); err == nil {
		t.Error("Validate should reject an unparseable override severity")
	}
}

func TestNilOverrideSetSafe(t *testing.T) {
	var set *SeverityOverrideSet
	if !set.Empty() || set.Len() != 0 {
		t.Error("nil set should be empty")
	}
	if _, _, ok := set.Apply("anything"); ok {
		t.Error("nil set should not match")
	}
}
