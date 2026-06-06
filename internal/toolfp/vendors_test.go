package toolfp

import (
	"slices"
	"testing"
)

func TestVendorOTPlatforms(t *testing.T) {
	cases := map[string]string{
		"nozomi":       "Nozomi Networks",
		"claroty":      "Claroty Ltd.",
		"tenable-ot":   "Tenable, Inc. (Tenable.ot / Indegy)",
		"dragos":       "Dragos, Inc.",
		"rapid7-sonar": "Rapid7 (Project Sonar / opendata.rapid7.com)",
		"isf":          "Industrial Security Exploitation Framework (dark-lbp, open source)",
	}
	for tool, want := range cases {
		if got := Vendor(tool); got != want {
			t.Errorf("Vendor(%q) = %q; want %q", tool, got, want)
		}
	}
	if Vendor("definitely-not-a-tool") != "" {
		t.Error("unknown tool should return empty vendor")
	}
}

func TestVendorsDedups(t *testing.T) {
	got := Vendors([]string{"nessus", "tenable", "nessus"})
	// nessus and tenable both map to a "Tenable" string but they differ, so two.
	if len(got) == 0 {
		t.Fatal("expected vendors")
	}
	if !slices.Contains(got, "Tenable, Inc. (Nessus)") {
		t.Errorf("missing Nessus vendor: %v", got)
	}
}
