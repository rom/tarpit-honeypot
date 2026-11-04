package sensor

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestRuleKind(t *testing.T) {
	cases := map[string]string{
		"cve:CVE-2021-44228": "cve",
		"listener:ssh":       "listener",
		"canary:token_used":  "canary",
		"portscan":           "portscan", // no prefix → whole id
		"":                   "other",
	}
	for in, want := range cases {
		if got := ruleKind(in); got != want {
			t.Errorf("ruleKind(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSensorMetricsRecord(t *testing.T) {
	m := newSensorMetrics()
	m.record(&event.Event{Severity: event.SeverityHigh, RuleID: "cve:CVE-1"})
	m.record(&event.Event{Severity: event.SeverityHigh, RuleID: "cve:CVE-2"})
	m.record(&event.Event{Severity: event.SeverityCritical, RuleID: "canary:token_used"})
	m.record(nil) // ignored, no panic

	var mnil *sensorMetrics
	mnil.record(&event.Event{Severity: event.SeverityLow, RuleID: "x"}) // nil-safe
	if total, _, _ := mnil.snapshot(); total != 0 {
		t.Errorf("nil metrics snapshot total = %d; want 0", total)
	}

	total, sev, kind := m.snapshot()
	if total != 3 {
		t.Errorf("total = %d; want 3", total)
	}
	if sev["high"] != 2 || sev["critical"] != 1 {
		t.Errorf("severity counts wrong: %v", sev)
	}
	if kind["cve"] != 2 || kind["canary"] != 1 {
		t.Errorf("kind counts wrong: %v", kind)
	}

	// snapshot returns copies — mutating the result must not corrupt state.
	sev["high"] = 999
	if _, sev2, _ := m.snapshot(); sev2["high"] != 2 {
		t.Errorf("snapshot not isolated: got %v", sev2)
	}
}
