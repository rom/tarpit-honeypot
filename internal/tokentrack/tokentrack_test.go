package tokentrack

import (
	"testing"
	"time"
)

func TestRecordAndCheck(t *testing.T) {
	tr := New(0)
	now := time.Now()
	tr.Record("Kp9mZq3vR7wLs1xN", "vault", "vault", "10.0.0.1", now)

	m, ok := tr.Check("Kp9mZq3vR7wLs1xN")
	if !ok {
		t.Fatal("served token not found on Check")
	}
	if m.Handler != "vault" || m.SrcIP != "10.0.0.1" {
		t.Errorf("mint context wrong: %+v", m)
	}
	if _, ok := tr.Check("never-served-value"); ok {
		t.Error("unserved value should not match")
	}
}

func TestShortValuesIgnored(t *testing.T) {
	tr := New(0)
	tr.Record("root", "x", "y", "1.2.3.4", time.Now()) // < minTokenLen
	if tr.Len() != 0 {
		t.Errorf("short value should not be tracked; len=%d", tr.Len())
	}
	if _, ok := tr.Check("root"); ok {
		t.Error("short value should never match (avoid 'root'/'admin' FPs)")
	}
}

func TestEvictionBounded(t *testing.T) {
	tr := New(3)
	now := time.Now()
	for _, v := range []string{"tokenAAAA", "tokenBBBB", "tokenCCCC", "tokenDDDD"} {
		tr.Record(v, "h", "r", "1.1.1.1", now)
	}
	if tr.Len() != 3 {
		t.Fatalf("cap not enforced: len=%d, want 3", tr.Len())
	}
	// Oldest (tokenAAAA) should have been evicted; newest retained.
	if _, ok := tr.Check("tokenAAAA"); ok {
		t.Error("oldest token should have been evicted")
	}
	if _, ok := tr.Check("tokenDDDD"); !ok {
		t.Error("newest token should be retained")
	}
}

func TestRecordKeepsOriginalMintContext(t *testing.T) {
	tr := New(0)
	t0 := time.Now()
	tr.Record("stabletoken123", "vault", "vault", "10.0.0.1", t0)
	// Re-serving the same value (e.g. a second read) must keep the first mint.
	tr.Record("stabletoken123", "etcd", "etcd", "10.0.0.2", t0.Add(time.Hour))
	m, _ := tr.Check("stabletoken123")
	if m.Handler != "vault" || m.SrcIP != "10.0.0.1" {
		t.Errorf("re-serve overwrote original mint context: %+v", m)
	}
}

func TestNilTrackerSafe(t *testing.T) {
	var tr *Tracker
	tr.Record("x", "h", "r", "ip", time.Now()) // must not panic
	if _, ok := tr.Check("x"); ok {
		t.Error("nil tracker should never match")
	}
	if tr.Len() != 0 {
		t.Error("nil tracker len should be 0")
	}
}
