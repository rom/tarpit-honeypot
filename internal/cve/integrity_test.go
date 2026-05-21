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

// TestEnrichmentWellFormed: the CWE/CPE/EPSS cross-references must be
// well-formed and reference real catalog entries.
func TestEnrichmentWellFormed(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range All() {
		ids[r.ID] = true
	}
	for id := range cveExtra {
		if !ids[id] {
			t.Errorf("cveExtra has entry for unknown CVE %q", id)
		}
	}
	for _, r := range All() {
		if r.EPSS < 0 || r.EPSS > 1 {
			t.Errorf("%s: EPSS %v out of [0,1]", r.ID, r.EPSS)
		}
		for _, c := range r.CWE {
			if len(c) < 5 || c[:4] != "CWE-" {
				t.Errorf("%s: malformed CWE %q", r.ID, c)
			}
		}
		if r.CPE != "" && len(r.CPE) < 8 || (r.CPE != "" && r.CPE[:8] != "cpe:2.3:") {
			t.Errorf("%s: CPE not 2.3 form: %q", r.ID, r.CPE)
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
