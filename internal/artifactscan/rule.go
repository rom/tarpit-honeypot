// Package artifactscan performs CGO-free static analysis on captured
// artifacts (dropped/uploaded malware, shellcode, archives): executable
// format/section/import parsing via the Go standard library (debug/elf,
// debug/pe, debug/macho, archive/zip), Shannon-entropy + packer heuristics,
// ASCII/UTF-16 string and IOC extraction, and a YARA-style rule engine
// (built-in rules plus a practical subset loaded from .yar files).
//
// The condition language supports string atoms ($id, hex, regex with
// nocase/wide/ascii/fullword), boolean logic, N/any/all-of sets, and a
// practical slice of the YARA module surface backed by the same std-lib
// parsers used above: filesize, the integer readers uintN/intN(offset),
// arithmetic + comparison operators, and the pe / elf / math / hash modules
// (pe.imports, pe.entry_point, pe.is_dll, elf.type, math.entropy, hash.sha256,
// …). See condition.go for the accepted grammar and module.go for the modules.
//
// It is detection + classification only: nothing is ever executed. The
// engine is pure Go so it stays inside the project's no-CGO constraint
// (unlike libyara bindings), at the cost of supporting only the common
// YARA rule shape — rules using unsupported constructs are skipped, not
// fatal, so a real-world .yar collection still loads whatever is expressible.
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

// evalCtx carries everything a condition expression needs while evaluating one
// rule against one artifact: the raw + lowercased bytes, the set of matched
// string ids, the rule (for `N of them` set resolution), and the lazily-parsed
// module facts (shared across rules via Engine.Scan).
type evalCtx struct {
	data  []byte
	lower []byte
	hit   map[string]bool
	rule  *Rule
	mod   *moduleData
}

// eval runs the rule against data and returns a Match if the condition holds.
// It builds a fresh module context; Engine.Scan uses evalWith to share one
// module parse across all rules.
func (r *Rule) eval(data, lower []byte) (Match, bool) {
	return r.evalWith(&evalCtx{data: data, lower: lower, mod: newModuleData(data)})
}

func (r *Rule) evalWith(ctx *evalCtx) (Match, bool) {
	ctx.rule = r
	ctx.hit = r.matchStrings(ctx.data, ctx.lower)
	if !r.Condition.eval(ctx).truthy() {
		return Match{}, false
	}
	ids := make([]string, 0, len(ctx.hit))
	for id := range ctx.hit {
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

// condExpr is one node of a compiled condition. It evaluates to a typed value
// against an evalCtx; the rule fires when its top-level node is truthy. Boolean
// nodes return bool values; module / arithmetic nodes (module.go) return
// int/float/string/undefined.
type condExpr interface {
	eval(ctx *evalCtx) value
}

type condBool struct{ v bool }

func (c condBool) eval(*evalCtx) value { return boolVal(c.v) }

// condID is true when a specific $id matched.
type condID struct{ id string }

func (c condID) eval(ctx *evalCtx) value { return boolVal(ctx.hit[c.id]) }

type condNot struct{ x condExpr }

func (c condNot) eval(ctx *evalCtx) value { return boolVal(!c.x.eval(ctx).truthy()) }

type condAnd struct{ a, b condExpr }

func (c condAnd) eval(ctx *evalCtx) value {
	return boolVal(c.a.eval(ctx).truthy() && c.b.eval(ctx).truthy())
}

type condOr struct{ a, b condExpr }

func (c condOr) eval(ctx *evalCtx) value {
	return boolVal(c.a.eval(ctx).truthy() || c.b.eval(ctx).truthy())
}

// condOf is `N of (set)` / `any of (set)` / `all of (set)`. n<0 means "all",
// n==0 means "any" (i.e. >=1). set is a list of id globs ("$a*", "them").
type condOf struct {
	n   int
	set []string // resolved at eval against the rule's string ids
}

func (c condOf) eval(ctx *evalCtx) value {
	ids := resolveSet(c.set, ctx.rule)
	matched := 0
	for _, id := range ids {
		if ctx.hit[id] {
			matched++
		}
	}
	switch {
	case c.n < 0: // all
		return boolVal(matched == len(ids) && len(ids) > 0)
	case c.n == 0: // any (>=1)
		return boolVal(matched >= 1)
	default:
		return boolVal(matched >= c.n)
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
