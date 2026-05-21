package config

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archeservice"
)

// loadArche builds + defaults + validates a config that has one
// archeservice, returning the expanded config.
func archeConfig(t *testing.T, as Archeservice) *Config {
	t.Helper()
	c := &Config{
		Sensor:        Sensor{Name: "t", DataDir: "/tmp/x"},
		Archeservices: []Archeservice{as},
		Channels:      []Channel{{ID: "log", Type: "stdout"}},
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return c
}

func TestArcheserviceExpandsWebserver(t *testing.T) {
	c := archeConfig(t, Archeservice{ID: "web", Role: "webserver", Archetype: "debian-12", Bind: "0.0.0.0"})
	got := map[string]Listener{}
	for _, l := range c.Listeners {
		got[l.Bind] = l
	}
	for _, want := range []struct {
		bind, handler string
	}{
		{"0.0.0.0:80", "http"},
		{"0.0.0.0:443", "https"},
	} {
		l, ok := got[want.bind]
		if !ok {
			t.Fatalf("expected a listener on %s", want.bind)
		}
		if l.Handler != want.handler {
			t.Errorf("%s handler = %q; want %q", want.bind, l.Handler, want.handler)
		}
		if l.Archetype != "debian-12" {
			t.Errorf("%s archetype not propagated: %q", want.bind, l.Archetype)
		}
		if l.Mode != "banner" {
			t.Errorf("%s default mode = %q; want banner", want.bind, l.Mode)
		}
	}
}

func TestArcheserviceExpandsADServer(t *testing.T) {
	c := archeConfig(t, Archeservice{ID: "dc", Role: "adserver", Archetype: "active-directory", Bind: "10.0.0.5"})
	svcs, _ := archeservice.Lookup("adserver")
	if len(c.Listeners) != len(svcs) {
		t.Fatalf("adserver expanded to %d listeners; want %d", len(c.Listeners), len(svcs))
	}
	// Spot-check Kerberos + LDAP + a UDP DNS listener.
	want := map[string]bool{"10.0.0.5:88": false, "10.0.0.5:389": false, "10.0.0.5:53": false}
	for _, l := range c.Listeners {
		if _, ok := want[l.Bind]; ok {
			want[l.Bind] = true
		}
	}
	for bind, ok := range want {
		if !ok {
			t.Errorf("adserver missing expected listener %s", bind)
		}
	}
}

func TestArcheserviceRejectsUnknownRole(t *testing.T) {
	c := &Config{Sensor: Sensor{DataDir: "/tmp/x"}, Archeservices: []Archeservice{{ID: "x", Role: "bogus", Bind: "0.0.0.0"}}, Channels: []Channel{{ID: "l", Type: "stdout"}}}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error for unknown role")
	}
}

func TestArcheserviceRejectsBindWithPort(t *testing.T) {
	c := &Config{Sensor: Sensor{DataDir: "/tmp/x"}, Archeservices: []Archeservice{{ID: "x", Role: "webserver", Bind: "0.0.0.0:80"}}, Channels: []Channel{{ID: "l", Type: "stdout"}}}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error for bind with port")
	}
}

func TestArcheserviceRejectsUnknownArchetype(t *testing.T) {
	c := &Config{Sensor: Sensor{DataDir: "/tmp/x"}, Archeservices: []Archeservice{{ID: "x", Role: "webserver", Archetype: "no-such-os", Bind: "0.0.0.0"}}, Channels: []Channel{{ID: "l", Type: "stdout"}}}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("expected error for unknown archetype")
	}
}

func TestArcheserviceExpandIdempotent(t *testing.T) {
	c := &Config{Sensor: Sensor{DataDir: "/tmp/x"}, Archeservices: []Archeservice{{ID: "web", Role: "webserver", Bind: "0.0.0.0"}}, Channels: []Channel{{ID: "l", Type: "stdout"}}}
	c.applyDefaults()
	n := len(c.Listeners)
	c.applyDefaults() // second call must not double-expand
	if len(c.Listeners) != n {
		t.Errorf("re-expansion duplicated listeners: %d -> %d", n, len(c.Listeners))
	}
}

// Coherence: every handler named by every archeservice role must be a real
// handler accepted on its protocol — otherwise an expanded listener would
// fail validation and the role would be unusable.
func TestArcheserviceHandlersValid(t *testing.T) {
	tcp := map[string]bool{}
	for _, h := range TCPHandlerNames() {
		tcp[h] = true
	}
	udp := map[string]bool{}
	for _, h := range UDPHandlerNames() {
		udp[h] = true
	}
	for _, role := range archeservice.Names() {
		svcs, _ := archeservice.Lookup(role)
		for _, s := range svcs {
			ok := false
			switch s.Proto {
			case "tcp":
				ok = tcp[s.Handler]
			case "udp":
				ok = udp[s.Handler]
			}
			if !ok {
				t.Errorf("role %q service %s/:%d uses handler %q not valid for %s", role, s.Proto, s.Port, s.Handler, s.Proto)
			}
		}
	}
}
