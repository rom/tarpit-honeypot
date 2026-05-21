package sensor

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDeviceAttrsLearnsOSGuess(t *testing.T) {
	ev := &event.Event{
		Handler: "tcp",
		Meta: map[string]any{
			"os_guess":   "linux/unix",
			"ip_ttl":     57,
			"user_agent": "curl/8.5.0",
		},
	}
	attrs := deviceAttrsFromEvent(ev)
	if attrs["os_guess"] != "linux/unix" {
		t.Errorf("os_guess not learned: %v", attrs)
	}
	if attrs["ua"] != "curl/8.5.0" {
		t.Errorf("ua not learned: %v", attrs)
	}
}

func TestDeviceAttrsEmptyWhenNoSignals(t *testing.T) {
	ev := &event.Event{Meta: map[string]any{"unrelated": 42}}
	if attrs := deviceAttrsFromEvent(ev); attrs != nil {
		t.Errorf("expected nil attrs for signal-free event, got %v", attrs)
	}
}
