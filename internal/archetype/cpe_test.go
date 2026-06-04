package archetype

import (
	"regexp"
	"testing"
)

// Every archetype must expose a well-formed CPE 2.3 string.
func TestEveryArchetypeHasWellFormedCPE(t *testing.T) {
	re := regexp.MustCompile(`^cpe:2\.3:[hoa]:[a-z0-9._-]+:[a-z0-9._-]+:[^:]+(:[^:]*){7}$`)
	for _, p := range All() {
		cpe := p.CPE()
		if cpe == "" {
			t.Errorf("%s: empty CPE", p.Name)
			continue
		}
		if !re.MatchString(cpe) {
			t.Errorf("%s: malformed CPE %q", p.Name, cpe)
		}
	}
}

// Spot-check that derivation yields canonical CPEs for the headline families.
func TestDerivedCPESpotChecks(t *testing.T) {
	want := map[string]string{
		"debian-12":  "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*",
		"freebsd-13": "cpe:2.3:o:freebsd:freebsd:13:*:*:*:*:*:*:*",
		"pfsense":    "cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*",
	}
	for name, exp := range want {
		p := Lookup(name)
		if p == nil {
			t.Errorf("archetype %q not found", name)
			continue
		}
		if got := p.CPE(); got != exp {
			t.Errorf("%s CPE = %q; want %q", name, got, exp)
		}
	}
}

// An explicit cpe override must win over derivation.
func TestExplicitCPEOverride(t *testing.T) {
	p := &Profile{Name: "x", Family: "debian", cpe: "cpe:2.3:o:debian:debian_linux:11:*:*:*:*:*:*:*"}
	if p.CPE() != "cpe:2.3:o:debian:debian_linux:11:*:*:*:*:*:*:*" {
		t.Errorf("override not honored: %q", p.CPE())
	}
}
