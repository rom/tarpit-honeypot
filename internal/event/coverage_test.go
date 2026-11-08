package event

import (
	"encoding/json"
	"testing"
)

// TestNewIDUniqueness covers NewID: it must return a 24-char hex id and not
// collide across a batch.
func TestNewIDUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if len(id) != 24 {
			t.Fatalf("NewID len = %d, want 24 (%q)", len(id), id)
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("NewID %q has non-hex char %q", id, c)
			}
		}
		if seen[id] {
			t.Fatalf("NewID collision at %d: %q", i, id)
		}
		seen[id] = true
	}
}

// TestSeverityStringAll covers every Severity.String() branch, including the
// unknown fallback.
func TestSeverityStringAll(t *testing.T) {
	cases := map[Severity]string{
		SeverityLow: "low", SeverityMedium: "medium", SeverityHigh: "high",
		SeverityCritical: "critical", Severity(99): "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestSeverityParseAndUnmarshal covers ParseSeverity aliases and
// UnmarshalJSON's string, numeric and error branches.
func TestSeverityParseAndUnmarshal(t *testing.T) {
	for _, in := range []string{"med", "crit", "low", "medium", "high", "critical"} {
		if _, err := ParseSeverity(in); err != nil {
			t.Errorf("ParseSeverity(%q) err: %v", in, err)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("ParseSeverity(bogus) should error")
	}

	var s Severity
	// string form
	if err := json.Unmarshal([]byte(`"high"`), &s); err != nil || s != SeverityHigh {
		t.Errorf("unmarshal string: s=%v err=%v", s, err)
	}
	// numeric form
	if err := json.Unmarshal([]byte(`4`), &s); err != nil || s != Severity(4) {
		t.Errorf("unmarshal numeric: s=%v err=%v", s, err)
	}
	// invalid string
	if err := json.Unmarshal([]byte(`"nope"`), &s); err == nil {
		t.Error("unmarshal invalid string should error")
	}
	// invalid numeric/garbage
	if err := json.Unmarshal([]byte(`1x`), &s); err == nil {
		t.Error("unmarshal garbage should error")
	}
	// round-trip via MarshalJSON
	b, err := json.Marshal(SeverityCritical)
	if err != nil || string(b) != `"critical"` {
		t.Errorf("marshal critical = %s err=%v", b, err)
	}
}
