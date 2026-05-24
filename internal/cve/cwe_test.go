package cve

import "testing"

func TestCWENameKnown(t *testing.T) {
	cases := map[string]string{
		"CWE-89":  "SQL Injection",
		"CWE-502": "Deserialization of Untrusted Data",
		"CWE-918": "Server-Side Request Forgery (SSRF)",
	}
	for id, want := range cases {
		if got := CWEName(id); got != want {
			t.Errorf("CWEName(%q) = %q; want %q", id, got, want)
		}
	}
	if CWEName("CWE-000000") != "" {
		t.Error("unknown CWE should return empty name")
	}
}

// Every CWE the catalog references must have a human-readable name, so the
// CLI / UI / docs never show a bare id.
func TestEveryReferencedCWEHasName(t *testing.T) {
	for _, r := range All() {
		for _, c := range r.CWE {
			if CWEName(c) == "" {
				t.Errorf("CVE %s references %s which has no name in the CWE catalog", r.ID, c)
			}
		}
	}
}

func TestCWEsSurface(t *testing.T) {
	cwes := CWEs()
	if len(cwes) == 0 {
		t.Fatal("CWEs() returned nothing")
	}
	for i := 1; i < len(cwes); i++ {
		if cwes[i-1].Count < cwes[i].Count {
			t.Errorf("CWEs() not sorted by count desc at %d", i)
		}
	}
	for _, c := range cwes {
		if c.Name == "" {
			t.Errorf("CWE %s in CWEs() has no name", c.ID)
		}
	}
}
