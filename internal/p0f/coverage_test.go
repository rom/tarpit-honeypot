package p0f

import "testing"

// TestSignatureString covers Signature.String()'s canonical-form rendering,
// including the wildcard window-scale, absent-MSS, and payload-class branches.
func TestSignatureString(t *testing.T) {
	// WScale -1 -> "*", MSS 0 -> "*", PClass 0 -> "0".
	a := Signature{
		Version: 4, ITTL: 64, OptLen: 0, MSS: 0, WSize: 65535, WScale: -1,
		Layout: []string{"mss", "sok", "ts"}, Quirks: []string{"df"}, PClass: 0,
	}
	if got, want := a.String(), "4:64:0:*:65535,*:mss,sok,ts:df:0"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	// WScale >=0, MSS >0, PClass !=0 -> "+".
	b := Signature{
		Version: 4, ITTL: 128, OptLen: 0, MSS: 1460, WSize: 8192, WScale: 8,
		Layout: []string{"mss", "nop", "ws"}, Quirks: nil, PClass: 1,
	}
	if got, want := b.String(), "4:128:0:1460:8192,8:mss,nop,ws::+"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

// TestBucketTTL covers every band of the TTL bucketing convention.
func TestBucketTTL(t *testing.T) {
	cases := map[byte]int{0: 0, 20: 32, 32: 32, 50: 64, 64: 64, 100: 128, 128: 128, 200: 255, 255: 255}
	for ttl, want := range cases {
		if got := bucketTTL(ttl); got != want {
			t.Errorf("bucketTTL(%d) = %d; want %d", ttl, got, want)
		}
	}
}

// TestEqStrings covers the length-mismatch and element-mismatch branches.
func TestEqStrings(t *testing.T) {
	if eqStrings([]string{"a"}, []string{"a", "b"}) {
		t.Error("eqStrings: different lengths should be unequal")
	}
	if eqStrings([]string{"a"}, []string{"b"}) {
		t.Error("eqStrings: different elements should be unequal")
	}
	if !eqStrings([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("eqStrings: identical slices should be equal")
	}
}

// TestQuirksMatch covers the length-mismatch and missing-element branches.
func TestQuirksMatch(t *testing.T) {
	want := map[string]struct{}{"df": {}, "id+": {}}
	if !quirksMatch(want, []string{"df", "id+"}) {
		t.Error("quirksMatch: exact set should match (order-independent)")
	}
	if quirksMatch(want, []string{"df"}) {
		t.Error("quirksMatch: fewer quirks should not match")
	}
	if quirksMatch(want, []string{"df", "ecn"}) {
		t.Error("quirksMatch: an unexpected quirk should not match")
	}
}
