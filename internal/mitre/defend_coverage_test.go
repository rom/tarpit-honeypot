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

// TestLuaMarkerTagging: the lua: prefix family classifies dynamic-script flags
// into the right ATT&CK class so the 80+ service scripts contribute coverage.
func TestLuaMarkerTagging(t *testing.T) {
	cases := []struct {
		marker, wantTech string
	}{
		{"lua:thinkphp-rce-attempt", "T1190"},
		{"lua:geoserver-jxpath-rce", "T1190"},
		{"lua:nodered-code-injection", "T1190"},
		{"lua:zabbix-command-exec", "T1190"},
		{"lua:metabase-setup-token-abuse", "T1190"},
		{"lua:grafana-path-traversal", "T1083"},
		{"lua:adminer-ssrf-attempt", "T1190"},
		{"lua:phpmyadmin-login-attempt", "T1110.001"},
		{"lua:rancher-api-token-use", "T1078"},
		{"lua:rancher-cluster-enum", "T1046"},
		{"lua:ollama-inference-abuse", "T1496"},
		{"lua:some-unknown-marker", "T1592"},
	}
	for _, c := range cases {
		tag := AnomalyTag(c.marker)
		found := false
		for _, tech := range tag.Techniques {
			if tech == c.wantTech {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected technique %s; got %v", c.marker, c.wantTech, tag.Techniques)
		}
		// Every classified technique must carry a description + a D3FEND control.
		for _, tech := range tag.Techniques {
			if Describe(tech) == "" {
				t.Errorf("%s: technique %s has no description", c.marker, tech)
			}
			if len(DefensesFor([]string{tech})) == 0 {
				t.Errorf("%s: technique %s has no D3FEND mapping", c.marker, tech)
			}
		}
	}
}
