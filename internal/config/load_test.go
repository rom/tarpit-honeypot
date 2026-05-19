package config

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestSeverityMatches(t *testing.T) {
	cases := []struct {
		spec string
		sev  event.Severity
		want bool
	}{
		{"", event.SeverityLow, true},
		{"=low", event.SeverityLow, true},
		{"=low", event.SeverityHigh, false},
		{">=medium", event.SeverityMedium, true},
		{">=medium", event.SeverityHigh, true},
		{">=medium", event.SeverityLow, false},
		{">high", event.SeverityCritical, true},
		{">high", event.SeverityHigh, false},
		{"<high", event.SeverityMedium, true},
		{"<=medium", event.SeverityMedium, true},
		{"<=medium", event.SeverityHigh, false},
	}
	for _, c := range cases {
		got, err := SeverityMatches(c.spec, c.sev)
		if err != nil {
			t.Errorf("SeverityMatches(%q, %v) errored: %v", c.spec, c.sev, err)
			continue
		}
		if got != c.want {
			t.Errorf("SeverityMatches(%q, %v) = %v, want %v", c.spec, c.sev, got, c.want)
		}
	}
}

func TestSeverityMatchesBadSpec(t *testing.T) {
	if _, err := SeverityMatches(">=banana", event.SeverityLow); err == nil {
		t.Error("expected error on bad spec")
	}
}
