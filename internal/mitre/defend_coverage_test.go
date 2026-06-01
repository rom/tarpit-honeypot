package mitre

import (
	"strings"
	"testing"
)

// TestEveryD3FENDIDHasName: every countermeasure id in the d3fend map must
// have a human-readable name, so the CLI / UI never renders a bare id.
func TestEveryD3FENDIDHasName(t *testing.T) {
	for tech, ids := range d3fend {
		for _, id := range ids {
			if !strings.HasPrefix(id, "D3-") {
				t.Errorf("%s: malformed D3FEND id %q", tech, id)
			}
			if DefenseName(id) == "" {
				t.Errorf("%s: D3FEND id %q has no name in d3fendNames", tech, id)
			}
		}
	}
}

// TestEveryReferencedTechniqueHasDefense: every ATT&CK technique the sensor
// can emit (across rules, handlers, anomalies) should map to at least one
// D3FEND countermeasure, so an operator always sees the paired control.
func TestEveryReferencedTechniqueHasDefense(t *testing.T) {
	base := func(x string) string {
		if i := strings.IndexByte(x, '.'); i > 0 {
			return x[:i]
		}
		return x
	}
	for _, m := range []map[string]Tag{exactRules, handlerTags, anomalyTags} {
		for key, tag := range m {
			for _, tech := range tag.Techniques {
				if len(d3fend[base(tech)]) == 0 {
					t.Errorf("technique %s (from %q) has no D3FEND mapping", tech, key)
				}
			}
		}
	}
}

// TestDefenseCatalogCopy: DefenseCatalog returns a usable, non-empty copy.
func TestDefenseCatalogCopy(t *testing.T) {
	c := DefenseCatalog()
	if c["D3-MFA"] != "Multi-factor Authentication" {
		t.Errorf("catalog missing D3-MFA name: %v", c["D3-MFA"])
	}
	c["D3-MFA"] = "mutated"
	if DefenseName("D3-MFA") != "Multi-factor Authentication" {
		t.Error("DefenseCatalog must return a copy (mutation leaked)")
	}
}
