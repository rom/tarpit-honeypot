package ui

import (
	"strings"
	"testing"
)

// highlightYAML computed match offsets on a strings.ToLower copy and sliced the
// original — a panic when a growing rune ('Ⱥ'→'ⱥ') made the copy longer. These
// inputs panicked before foldIndex (original-offset search) replaced it.
func TestHighlightYAMLFoldNoPanic(t *testing.T) {
	grow := "Ⱥ" // U+023A → U+2C65 grows 2→3 bytes under ToLower
	for _, body := range []string{grow + "key: value", "key: " + grow + "SECRET", grow + grow + "token"} {
		_, _ = highlightYAML(body, "secret", false)
		_, _ = highlightYAML(body, "key", true)
		_, _ = highlightYAML(body, grow, false)
	}
	// Correct, case-insensitive highlight on normal input.
	out, n := highlightYAML("listener: SSH\nhandler: ssh", "ssh", false)
	if n != 2 {
		t.Errorf("match count = %d; want 2", n)
	}
	if !strings.Contains(string(out), "<mark>SSH</mark>") || !strings.Contains(string(out), "<mark>ssh</mark>") {
		t.Errorf("highlight wrong: %s", out)
	}
	// foldIndex returns offsets valid in the original.
	if foldIndex("abcXYz", "xy") != 3 || foldIndex("abc", "zz") != -1 {
		t.Error("foldIndex offset/none wrong")
	}
}
