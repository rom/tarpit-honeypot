package event

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if back != s {
			t.Errorf("round-trip mismatch: got %v want %v (json=%s)", back, s, b)
		}
	}
}

func TestSeverityUnmarshalNumeric(t *testing.T) {
	var s Severity
	if err := json.Unmarshal([]byte("3"), &s); err != nil {
		t.Fatalf("unmarshal numeric: %v", err)
	}
	if s != SeverityHigh {
		t.Errorf("want %v got %v", SeverityHigh, s)
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"low":      SeverityLow,
		"medium":   SeverityMedium,
		"med":      SeverityMedium,
		"high":     SeverityHigh,
		"critical": SeverityCritical,
		"crit":     SeverityCritical,
	}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = (%v, %v), want (%v, nil)", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Errorf("ParseSeverity(bogus) should error")
	}
}

func TestEventJSONShape(t *testing.T) {
	ev := &Event{
		ID:       "abc",
		Time:     time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		Severity: SeverityHigh,
		Source:   Endpoint{IP: "1.2.3.4", Port: 1234},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `"severity":"high"`
	if !contains(string(b), want) {
		t.Errorf("event JSON missing %s; got %s", want, b)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
