package toolfp

import "testing"

func TestCobaltStrikeStager(t *testing.T) {
	// Known default Cobalt Strike checksum8 staging URIs.
	// "aab9": 97+97+98+57 = 349; 349 % 256 = 93 -> x64.
	if arch, ok := CobaltStrikeStager("/aab9"); !ok || arch != "x64" {
		t.Errorf("/aab9 => %q,%v; want x64,true", arch, ok)
	}
	// Verify a computed x86 (sum%256==92) URI: "aaa8": 97*3+56=347; 347%256=91. no.
	// Build one: need sum%256==92. "aab8": 97+97+98+56=348 -> 92 -> x86.
	if arch, ok := CobaltStrikeStager("/aab8"); !ok || arch != "x86" {
		t.Errorf("/aab8 => %q,%v; want x86,true", arch, ok)
	}
	// Non-matching paths.
	for _, p := range []string{"/", "/index.html", "/aaaa", "/ab", "/aab9/x", "/aab9.js", "/login"} {
		if _, ok := CobaltStrikeStager(p); ok {
			t.Errorf("%q should not match CS stager", p)
		}
	}
	// IdentifyHTTP must classify a stager hit as c2 (tool cobaltstrike).
	v := IdentifyHTTP(HTTPSignals{Method: "GET", Path: "/aab9"})
	if v.Category != "c2" {
		t.Errorf("stager category = %q; want c2 (%v)", v.Category, v.Tools)
	}
	found := false
	for _, tl := range v.Tools {
		if tl == "cobaltstrike" {
			found = true
		}
	}
	if !found {
		t.Errorf("stager not identified as cobaltstrike: %v", v.Tools)
	}
}
