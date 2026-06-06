package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// buildCredentials must add a "by service" comparison chart so an operator can
// see how many captured logins came from ssh vs ftp vs telnet.
func TestCredentialsByServiceChart(t *testing.T) {
	now := time.Now()
	mk := func(handler, user, pass string) *event.Event {
		return &event.Event{Time: now, Source: event.Endpoint{IP: "5.5.5.5"}, Handler: handler,
			Meta: map[string]any{"username": user, "password": pass}}
	}
	evs := []*event.Event{
		mk("ssh", "root", "a"), mk("ssh", "admin", "b"), mk("ssh", "test", "c"),
		mk("ftp", "anonymous", "x"),
		mk("telnet", "root", "y"), mk("telnet", "admin", "z"),
	}
	v := buildCredentials(evs)
	var found bool
	for _, f := range v.Figs {
		if strings.Contains(f.Title, "Credential captures by service") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'Credential captures by service' figure; got %d figs", len(v.Figs))
	}
}

// markCanvasActivity must tint exactly the service cards that saw events.
func TestMarkCanvasActivity(t *testing.T) {
	cv := configCanvas{Listeners: []portCard{{Port: 22}, {Port: 80}, {Port: 3389}}}
	evs := []*event.Event{
		{Dest: event.Endpoint{Port: 22}},
		{Dest: event.Endpoint{Port: 22}},
		{Dest: event.Endpoint{Port: 80}},
		{Dest: event.Endpoint{Port: 9999}}, // not a listed service
	}
	markCanvasActivity(&cv, evs)
	hits := map[int]int{}
	for _, l := range cv.Listeners {
		if l.Hit {
			hits[l.Port] = l.Hits
		}
	}
	if hits[22] != 2 || hits[80] != 1 {
		t.Errorf("hit counts wrong: %v", hits)
	}
	if _, ok := hits[3389]; ok {
		t.Error("port 3389 saw no events and must not be marked hit")
	}
}
