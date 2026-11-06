package ui

import (
	"html"
	"html/template"
	"strings"
)

// highlightYAML wraps every case-insensitive occurrence of q in <mark>…</mark>
// against an HTML-escaped rendering of the YAML body. When linesOnly is true
// it drops lines that don't match, so an operator can pull the YAML down to
// the relevant blocks for a long config. Returns the rendered HTML and the
// match count for the "N match" indicator on the page.
//
// The query is treated as a literal substring (case-insensitive); offsets are
// computed on the raw YAML so we never break HTML escaping by slicing across
// an entity. q must be non-empty — callers pass through a plain escape when q
// is empty.
func highlightYAML(yamlStr, q string, linesOnly bool) (template.HTML, int) {
	if q == "" {
		return template.HTML(html.EscapeString(yamlStr)), 0
	}
	qlen := len(q)
	matches := 0
	var b strings.Builder
	b.Grow(len(yamlStr) + 64)
	lines := strings.Split(yamlStr, "\n")
	for i, line := range lines {
		idx := foldIndex(line, q)
		if idx < 0 {
			if !linesOnly {
				b.WriteString(html.EscapeString(line))
				if i < len(lines)-1 {
					b.WriteByte('\n')
				}
			}
			continue
		}
		// Splice: escaped pre + <mark>escaped match</mark> + repeat.
		cursor := 0
		for idx >= 0 {
			abs := cursor + idx
			b.WriteString(html.EscapeString(line[cursor:abs]))
			b.WriteString("<mark>")
			b.WriteString(html.EscapeString(line[abs : abs+qlen]))
			b.WriteString("</mark>")
			matches++
			cursor = abs + qlen
			if cursor >= len(line) {
				break
			}
			rel := foldIndex(line[cursor:], q)
			if rel < 0 {
				break
			}
			idx = rel
		}
		if cursor < len(line) {
			b.WriteString(html.EscapeString(line[cursor:]))
		}
		// Keep line breaks; linesOnly mode collapses the gaps between hits.
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return template.HTML(b.String()), matches
}

// foldIndex is a case-insensitive strings.Index whose returned offset is valid
// in the ORIGINAL s. It searches the raw bytes rather than indexing a
// strings.ToLower copy, because ToLower is not length-preserving (e.g.
// 'Ⱥ' U+023A → 'ⱥ' U+2C65 grows 2→3 bytes): an offset taken from a lowercased
// copy can mis-align or run past the end of s and panic a later s[i:j] slice.
// sub is matched ASCII-case-insensitively (the YAML query); a match is exactly
// len(sub) bytes of s, so callers can slice s[idx:idx+len(sub)] safely.
func foldIndex(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	lower := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + ('a' - 'A')
		}
		return c
	}
	for i := 0; i+n <= len(s); i++ {
		ok := true
		for j := 0; j < n; j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
