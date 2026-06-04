// Package artifactscan performs CGO-free static analysis on captured
// artifacts (dropped/uploaded malware, shellcode, archives): executable
// format/section/import parsing via the Go standard library (debug/elf,
// debug/pe, debug/macho, archive/zip), Shannon-entropy + packer heuristics,
// ASCII/UTF-16 string and IOC extraction, and a YARA-style rule engine
// (built-in rules plus a practical subset loaded from .yar files).
//
// It is detection + classification only: nothing is ever executed. The
// engine is pure Go so it stays inside the project's no-CGO constraint
// (unlike libyara bindings), at the cost of supporting only the common
// YARA rule shape — see yarparse.go for the accepted subset.
package artifactscan

import (
	"bytes"
	"regexp"
	"strings"
)

// Rule is one compiled detection rule: a set of named string atoms plus a
// boolean condition over which of them matched.
type Rule struct {
	Name      string
	Tags      []string
	Meta      map[string]string
	Strings   []ruleString
	Condition condExpr
}

// ruleString is one $id atom. Exactly one of lit/hex/re is set.
type ruleString struct {
	id  string
	lit *litAtom
	hex []hexByte // nil unless a hex pattern
	re  *regexp.Regexp
}

// litAtom is a text string atom with YARA modifiers.
type litAtom struct {
	text     string
	nocase   bool
	wide     bool // also match UTF-16LE
	ascii    bool // match ASCII (default true unless only wide given)
	fullword bool
}

// hexByte is one token of a hex pattern: a concrete byte or a wildcard.
type hexByte struct {
	val      byte
	wildcard bool // ?? — matches any byte
}

// Match reports a rule firing against a buffer.
type Match struct {
	Rule    string            `json:"rule"`
	Tags    []string          `json:"tags,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
	Strings []string          `json:"strings,omitempty"` // which $ids matched
}

// matchStrings returns the set of string ids that occur in data.
func (r *Rule) matchStrings(data, lower []byte) map[string]bool {
	hit := make(map[string]bool, len(r.Strings))
	for _, s := range r.Strings {
		if s.matches(data, lower) {
			hit[s.id] = true
		}
	}
	return hit
}

// eval runs the rule against data and returns a Match if the condition holds.
func (r *Rule) eval(data, lower []byte) (Match, bool) {
	hit := r.matchStrings(data, lower)
	if !r.Condition.eval(hit, r) {
		return Match{}, false
	}
	ids := make([]string, 0, len(hit))
	for id := range hit {
		ids = append(ids, id)
	}
	return Match{Rule: r.Name, Tags: r.Tags, Meta: r.Meta, Strings: ids}, true
}

func (s ruleString) matches(data, lower []byte) bool {
	switch {
	case s.lit != nil:
		return s.lit.matches(data, lower)
	case s.hex != nil:
		return hexSearch(data, s.hex)
	case s.re != nil:
		return s.re.Match(data)
	}
	return false
}

func (a litAtom) matches(data, lower []byte) bool {
	if a.ascii || !a.wide {
		needle := []byte(a.text)
		hay := data
		if a.nocase {
			hay = lower
			needle = bytes.ToLower(needle)
		}
		if a.fullword {
			if fullwordSearch(hay, needle) {
				return true
			}
		} else if bytes.Contains(hay, needle) {
			return true
		}
	}
	if a.wide {
		w := toWide(a.text)
		if a.nocase {
			if bytes.Contains(bytes.ToLower(data), bytes.ToLower(w)) {
				return true
			}
		} else if bytes.Contains(data, w) {
			return true
		}
	}
	return false
}

// toWide renders s as UTF-16LE (each ASCII byte followed by 0x00) — the
// common YARA `wide` representation for BMP ASCII strings.
func toWide(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0x00)
	}
	return out
}

// fullwordSearch reports whether needle occurs in hay bounded by non-word
// bytes (YARA `fullword`).
func fullwordSearch(hay, needle []byte) bool {
	from := 0
	for {
		i := bytes.Index(hay[from:], needle)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(needle)
		leftOK := start == 0 || !isWordByte(hay[start-1])
		rightOK := end == len(hay) || !isWordByte(hay[end])
		if leftOK && rightOK {
			return true
		}
		from = start + 1
	}
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// hexSearch scans data for the hex pattern (with ?? wildcards).
func hexSearch(data []byte, pat []hexByte) bool {
	if len(pat) == 0 || len(data) < len(pat) {
		return false
	}
	last := len(data) - len(pat)
	for i := 0; i <= last; i++ {
		ok := true
		for j, hb := range pat {
			if !hb.wildcard && data[i+j] != hb.val {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// --- condition AST ---------------------------------------------------------

// condExpr is a boolean expression node evaluated against the set of matched
// string ids.
type condExpr interface {
	eval(hit map[string]bool, r *Rule) bool
}

type condBool struct{ v bool }

func (c condBool) eval(map[string]bool, *Rule) bool { return c.v }

// condID is true when a specific $id matched.
type condID struct{ id string }

func (c condID) eval(hit map[string]bool, _ *Rule) bool { return hit[c.id] }

type condNot struct{ x condExpr }

func (c condNot) eval(hit map[string]bool, r *Rule) bool { return !c.x.eval(hit, r) }

type condAnd struct{ a, b condExpr }

func (c condAnd) eval(hit map[string]bool, r *Rule) bool {
	return c.a.eval(hit, r) && c.b.eval(hit, r)
}

type condOr struct{ a, b condExpr }

func (c condOr) eval(hit map[string]bool, r *Rule) bool {
	return c.a.eval(hit, r) || c.b.eval(hit, r)
}

// condOf is `N of (set)` / `any of (set)` / `all of (set)`. n<0 means "all",
// n==0 means "any" (i.e. >=1). set is a list of id globs ("$a*", "them").
type condOf struct {
	n   int
	set []string // resolved at eval against the rule's string ids
}

func (c condOf) eval(hit map[string]bool, r *Rule) bool {
	ids := resolveSet(c.set, r)
	matched := 0
	for _, id := range ids {
		if hit[id] {
			matched++
		}
	}
	switch {
	case c.n < 0: // all
		return matched == len(ids) && len(ids) > 0
	case c.n == 0: // any (>=1)
		return matched >= 1
	default:
		return matched >= c.n
	}
}

// resolveSet expands id globs against the rule's declared strings. "them"
// (or "$*") means every string.
func resolveSet(set []string, r *Rule) []string {
	var out []string
	for _, sel := range set {
		if sel == "them" || sel == "$*" {
			for _, s := range r.Strings {
				out = append(out, s.id)
			}
			continue
		}
		if strings.HasSuffix(sel, "*") {
			pre := strings.TrimSuffix(sel, "*")
			for _, s := range r.Strings {
				if strings.HasPrefix(s.id, pre) {
					out = append(out, s.id)
				}
			}
			continue
		}
		out = append(out, sel)
	}
	return out
}
