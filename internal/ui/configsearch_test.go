package ui

import (
	"strings"
	"testing"
)

func TestHighlightYAMLEmptyQueryReturnsEscaped(t *testing.T) {
	body, n := highlightYAML("listen: 0.0.0.0\nfoo: <bar>\n", "", false)
	if n != 0 {
		t.Errorf("count = %d; want 0 on empty query", n)
	}
	if !strings.Contains(string(body), "&lt;bar&gt;") {
		t.Errorf("body should be HTML-escaped: %q", body)
	}
	if strings.Contains(string(body), "<mark>") {
		t.Errorf("empty query should not emit <mark>")
	}
}

func TestHighlightYAMLWrapsCaseInsensitiveMatches(t *testing.T) {
	yaml := "sensor:\n  name: TARPIT-NODE\n  tarpit_enabled: true\n  port: 22\n"
	body, n := highlightYAML(yaml, "tarpit", false)
	if n != 2 {
		t.Errorf("count = %d; want 2 (one upper, one lower)", n)
	}
	s := string(body)
	// Both the upper-case and lower-case matches are highlighted, preserving
	// the original casing of the text inside the <mark> wrap.
	if !strings.Contains(s, "<mark>TARPIT</mark>") {
		t.Errorf("upper-case match not wrapped: %q", s)
	}
	if !strings.Contains(s, "<mark>tarpit</mark>") {
		t.Errorf("lower-case match not wrapped: %q", s)
	}
}

func TestHighlightYAMLLinesOnlyDropsNonMatches(t *testing.T) {
	yaml := "a: 1\nb: 2\nfleet: on\nc: 3\n"
	full, _ := highlightYAML(yaml, "fleet", false)
	if !strings.Contains(string(full), "a: 1") || !strings.Contains(string(full), "c: 3") {
		t.Errorf("full mode should keep non-matching lines: %q", full)
	}
	only, n := highlightYAML(yaml, "fleet", true)
	if n != 1 {
		t.Errorf("count = %d; want 1", n)
	}
	if strings.Contains(string(only), "a: 1") || strings.Contains(string(only), "c: 3") {
		t.Errorf("lines-only mode should drop non-matching lines: %q", only)
	}
	if !strings.Contains(string(only), "<mark>fleet</mark>") {
		t.Errorf("lines-only mode should still highlight the match: %q", only)
	}
}

func TestHighlightYAMLEscapesAroundMatch(t *testing.T) {
	// Defense in depth: a match boundary must not split an HTML entity. The
	// query itself contains `<`, and the line has `&` before it.
	yaml := "raw: a&b<c>d\n"
	body, n := highlightYAML(yaml, "<c>", false)
	if n != 1 {
		t.Errorf("count = %d; want 1", n)
	}
	if !strings.Contains(string(body), "<mark>&lt;c&gt;</mark>") {
		t.Errorf("match should be escaped inside <mark>: %q", body)
	}
	if !strings.Contains(string(body), "a&amp;b") {
		t.Errorf("pre-match content should be escaped: %q", body)
	}
}

func TestHighlightYAMLMultipleMatchesOnOneLine(t *testing.T) {
	yaml := "tag: tarpit tarpit-honeypot tarpit\n"
	_, n := highlightYAML(yaml, "tarpit", false)
	if n != 3 {
		t.Errorf("count = %d; want 3", n)
	}
}
