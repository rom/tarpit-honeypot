package config

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// TestArchetypeDefaultServiceHandlersValid ensures every handler named in
// an archetype's default-service map is a real, accepted handler — so a
// typo (or a service pointing at a handler we deleted) is caught at test
// time rather than when an operator expands honeynet hosts from the
// archetype. Sourced from the same whitelist Validate enforces.
func TestArchetypeDefaultServiceHandlersValid(t *testing.T) {
	valid := map[string]bool{}
	for _, h := range TCPHandlerNames() {
		valid[h] = true
	}
	for _, h := range UDPHandlerNames() {
		valid[h] = true
	}
	for _, p := range archetype.All() {
		for _, s := range p.DefaultServices() {
			if !valid[s.Handler] {
				t.Errorf("archetype %q service :%d uses unknown handler %q", p.Name, s.Port, s.Handler)
			}
		}
	}
}
