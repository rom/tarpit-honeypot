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

func TestValidateTarpitStrategies(t *testing.T) {
	mk := func(mut func(*Listener)) *Config {
		l := baseListener()
		l.Proto = "tcp"
		l.Mode = "tarpit"
		l.Handler = "raw"
		mut(&l)
		c := &Config{Listeners: []Listener{l}}
		ApplyDefaults(c)
		return c
	}

	accepted := []string{
		"sticky", "trickle", "keepalive", "jitter", "backoff",
		"ssh_banner", "http_headers", "http_chunked", "echo", "babble",
	}
	for _, s := range accepted {
		c := mk(func(l *Listener) {
			l.Tarpit.Strategy = s
			if s == "trickle" {
				l.Tarpit.Trickle.Text = "x"
			}
		})
		if err := Validate(c); err != nil {
			t.Errorf("strategy %q should validate, got: %v", s, err)
		}
	}

	if err := Validate(mk(func(l *Listener) { l.Tarpit.Strategy = "bogus" })); err == nil {
		t.Error("unknown strategy should be rejected")
	}
	if err := Validate(mk(func(l *Listener) {
		l.Tarpit.Strategy = "backoff"
		l.Tarpit.Backoff.Factor = 0.5
	})); err == nil {
		t.Error("backoff factor < 1 should be rejected")
	}
	if err := Validate(mk(func(l *Listener) {
		l.Tarpit.Strategy = "jitter"
		l.Tarpit.Jitter.MinInterval = 5_000_000_000 // 5s
		l.Tarpit.Jitter.MaxInterval = 1_000_000_000 // 1s
	})); err == nil {
		t.Error("jitter max < min should be rejected")
	}
}
