package archetype

import (
	"sort"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/cve"
)

// TestFindRoundTrips guards the CLI-facing resolver: every archetype must
// be reachable by both its canonical Name and its pretty DisplayName (this
// is what `tarpit-honeypot list-archetypes <name>` relies on).
func TestFindRoundTrips(t *testing.T) {
	for _, p := range All() {
		if got := Find(p.Name); got == nil || got.DisplayName != p.DisplayName {
			t.Errorf("Find(%q) did not resolve to %q", p.Name, p.DisplayName)
		}
		if got := Find(p.DisplayName); got == nil || got.Name != p.Name {
			t.Errorf("Find(%q) did not resolve to %q", p.DisplayName, p.Name)
		}
	}
}

// TestAllSortedAndDeduped: All() must be sorted by DisplayName with no
// duplicate display names, and agree with Names().
func TestAllSortedAndDeduped(t *testing.T) {
	all := All()
	names := make([]string, len(all))
	seen := map[string]bool{}
	for i, p := range all {
		names[i] = p.DisplayName
		if seen[p.DisplayName] {
			t.Errorf("duplicate DisplayName %q in All()", p.DisplayName)
		}
		seen[p.DisplayName] = true
	}
	if !sort.StringsAreSorted(names) {
		t.Error("All() is not sorted by DisplayName")
	}
	if len(all) != len(Names()) {
		t.Errorf("All()=%d but Names()=%d", len(all), len(Names()))
	}
}

// TestAdvertisedCVEsExist: every CVE an archetype advertises must exist in
// the catalog, so list-archetypes / vuln-emulation never reference a
// dangling id.
func TestAdvertisedCVEsExist(t *testing.T) {
	for _, p := range All() {
		for _, id := range p.VulnCVEs() {
			if _, ok := cve.Lookup(id); !ok {
				t.Errorf("archetype %q advertises unknown CVE %q", p.Name, id)
			}
		}
	}
}

// TestProfileBasics: every archetype has the minimum coherent identity.
func TestProfileBasics(t *testing.T) {
	for _, p := range All() {
		if p.Name == "" || p.DisplayName == "" || p.Family == "" {
			t.Errorf("archetype %+v missing Name/DisplayName/Family", p)
		}
	}
}
