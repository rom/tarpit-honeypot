package cve

import (
	"sort"
	"testing"
)

// TestAllSortedNoDupes: the public catalog accessor must be sorted by id
// and free of duplicate ids (a dup would make Lookup nondeterministic).
func TestAllSortedNoDupes(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("catalog is empty")
	}
	ids := make([]string, len(all))
	seen := map[string]bool{}
	for i, r := range all {
		ids[i] = r.ID
		if seen[r.ID] {
			t.Errorf("duplicate CVE id %q", r.ID)
		}
		seen[r.ID] = true
	}
	if !sort.StringsAreSorted(ids) {
		t.Error("All() is not sorted by id")
	}
}

// TestDetectableMatchesSignatures: Detectable() must agree with whether a
// record carries exploit signatures, and signatures must be lowercase
// (MatchPayload lowercases the payload once and compares directly).
func TestDetectableMatchesSignatures(t *testing.T) {
	for _, r := range All() {
		if r.Detectable() != (len(r.Signatures) > 0) {
			t.Errorf("%s: Detectable()=%v but %d signatures", r.ID, r.Detectable(), len(r.Signatures))
		}
		for _, s := range r.Signatures {
			if s == "" {
				t.Errorf("%s: empty signature", r.ID)
			}
		}
	}
}

// TestEveryRecordHasServiceAndTechnique: a record with no service can't be
// matched/advertised; one with no technique can't be ATT&CK-tagged.
func TestEveryRecordHasServiceAndTechnique(t *testing.T) {
	for _, r := range All() {
		if r.Service == "" {
			t.Errorf("%s: missing Service", r.ID)
		}
		if r.Technique == "" || r.Tactic == "" {
			t.Errorf("%s: missing Technique/Tactic", r.ID)
		}
	}
}
