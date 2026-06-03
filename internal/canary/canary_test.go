package canary

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestFanotifyTargets(t *testing.T) {
	w := New([]config.Canary{
		{ID: "ssh-key", Path: "/home/bait/.ssh/id_rsa", Severity: "critical"},
		{ID: "passwd", Path: "/etc/bait-passwd", Severity: "high"},
		{ID: "bad-sev", Path: "/tmp/x", Severity: "not-a-severity"}, // dropped
	}, "test-sensor")

	got := w.fanotifyTargets()
	if len(got) != 2 {
		t.Fatalf("fanotifyTargets returned %d, want 2 (invalid severity dropped)", len(got))
	}
	if got[0].id != "ssh-key" || got[0].path != "/home/bait/.ssh/id_rsa" || got[0].sev != event.SeverityCritical {
		t.Errorf("first target = %+v", got[0])
	}
	if got[1].sev != event.SeverityHigh {
		t.Errorf("second target severity = %v, want high", got[1].sev)
	}
}

func TestNewEmpty(t *testing.T) {
	if got := New(nil, "s").fanotifyTargets(); len(got) != 0 {
		t.Errorf("empty config should yield no targets, got %d", len(got))
	}
}
