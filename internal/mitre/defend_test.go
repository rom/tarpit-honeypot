package mitre

import "testing"

func TestDefensesForMapsAndDedups(t *testing.T) {
	// T1110.001 inherits T1110's mapping; combined with T1190 the set
	// should dedup D3-DE which both produce.
	got := DefensesFor([]string{"T1110.001", "T1190"})
	want := map[string]bool{"D3-MFA": true, "D3-DUC": true, "D3-DE": true, "D3-NTA": true, "D3-ITF": true, "D3-CH": true}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected defense %q", d)
		}
		delete(want, d)
	}
	if len(want) != 0 {
		t.Errorf("missing defenses: %v", want)
	}
	// dedup: D3-DE must appear exactly once.
	count := 0
	for _, d := range got {
		if d == "D3-DE" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("D3-DE appeared %d times; want 1", count)
	}
}

func TestDefensesForEmpty(t *testing.T) {
	if d := DefensesFor(nil); len(d) != 0 {
		t.Errorf("no techniques should yield no defenses; got %v", d)
	}
	if d := DefensesFor([]string{"T9999"}); len(d) != 0 {
		t.Errorf("unknown technique should yield no defenses; got %v", d)
	}
}

func TestLookupCVERule(t *testing.T) {
	tag := Lookup("cve:CVE-2021-44228", "http")
	if len(tag.Techniques) == 0 || tag.Techniques[0] != "T1190" {
		t.Errorf("cve rule should map to T1190; got %+v", tag)
	}
	// Unknown CVE id falls back to T1190.
	if tag := Lookup("cve:CVE-0000-0000", ""); len(tag.Techniques) == 0 {
		t.Error("unknown cve should still map to a technique")
	}
}
