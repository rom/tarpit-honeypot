package safe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSanitizeMetaStrings exercises the central event-meta sanitizer across
// every value shape it recurses into — a bare string, []string, []byte, a
// nested map, a slice of maps, and a mixed []any — and confirms non-string
// scalars are left untouched. This is the single enforcement point that keeps
// attacker-supplied capture fields escape-safe before they reach any sink, so
// its branches must stay covered.
func TestSanitizeMetaStrings(t *testing.T) {
	meta := map[string]any{
		"line":   "GET /\r\n\x1bX",                // CRLF + ESC → escaped
		"list":   []string{"a\nb", "ok"},          // []string
		"raw":    []byte("bin\x00ary"),            // []byte → escaped string
		"nested": map[string]any{"pw": "p\twd"},   // map[string]any (recurse)
		"rows":   []map[string]any{{"u": "x\ry"}}, // []map[string]any
		"mixed":  []any{"e\nf", map[string]any{"k": "v\x1b"}, 42},
		"count":  7,    // non-string scalar → untouched
		"flag":   true, // ditto
	}
	SanitizeMetaStrings(meta)

	if got := meta["line"].(string); strings.ContainsAny(got, "\r\n\x1b") {
		t.Errorf("line not sanitized: %q", got)
	}
	if got := meta["list"].([]string); strings.Contains(got[0], "\n") {
		t.Errorf("[]string not sanitized: %q", got)
	}
	if got := meta["raw"].(string); strings.Contains(got, "\x00") {
		t.Errorf("[]byte not sanitized: %q", got)
	}
	if got := meta["nested"].(map[string]any)["pw"].(string); strings.Contains(got, "\t") {
		t.Errorf("nested map not sanitized: %q", got)
	}
	if got := meta["rows"].([]map[string]any)[0]["u"].(string); strings.Contains(got, "\r") {
		t.Errorf("[]map not sanitized: %q", got)
	}
	mixed := meta["mixed"].([]any)
	if strings.Contains(mixed[0].(string), "\n") {
		t.Errorf("[]any string not sanitized: %q", mixed[0])
	}
	if strings.Contains(mixed[1].(map[string]any)["k"].(string), "\x1b") {
		t.Errorf("[]any nested map not sanitized: %q", mixed[1])
	}
	if mixed[2].(int) != 42 {
		t.Errorf("[]any int mutated: %v", mixed[2])
	}
	if meta["count"].(int) != 7 || meta["flag"].(bool) != true {
		t.Errorf("non-string scalars mutated: count=%v flag=%v", meta["count"], meta["flag"])
	}
}

// TestSanitizeUTF8TruncatesOnRuneBoundary feeds a valid-UTF-8 string longer than
// MaxLogLength whose cut point lands mid-rune, exercising truncateUTF8's
// walk-back to a rune boundary — the result must stay valid UTF-8.
func TestSanitizeUTF8TruncatesOnRuneBoundary(t *testing.T) {
	// 1400 × 3-byte runes = 4200 bytes > MaxLogLength (4096); byte 4096 is a
	// continuation byte, so the boundary walk-back runs.
	in := strings.Repeat("世", 1400)
	if len(in) <= MaxLogLength {
		t.Fatalf("test input too short: %d", len(in))
	}
	out := SanitizeUTF8ForLog(in)
	if !strings.HasSuffix(out, "...[truncated]") {
		t.Errorf("expected truncation marker, got suffix %q", out[len(out)-20:])
	}
	trimmed := strings.TrimSuffix(out, "...[truncated]")
	if !utf8.ValidString(trimmed) {
		t.Error("truncated output is not valid UTF-8 (cut mid-rune)")
	}
	if len(trimmed) > MaxLogLength {
		t.Errorf("truncated length %d exceeds cap %d", len(trimmed), MaxLogLength)
	}
}
