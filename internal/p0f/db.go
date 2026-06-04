package p0f

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// rule is one compiled database signature with its OS label.
type rule struct {
	label  string
	ittl   int // 0 = wildcard
	olen   int // -1 = wildcard
	mss    int // -1 = wildcard
	wsize  wsizeExpr
	wscale int // -2 = wildcard
	layout []string
	quirks map[string]struct{}
	pclass int // -1 = wildcard (*), 0 = none, 1 = payload
}

// wsizeExpr is a p0f window-size match expression.
type wsizeExpr struct {
	kind string // "any" | "exact" | "mss" | "mtu" | "mod"
	val  int
}

// DB is a set of compiled p0f signatures.
type DB struct {
	rules []rule
}

// New returns a DB seeded with the embedded curated signature set.
func New() *DB {
	db := &DB{}
	db.loadText(builtinSignatures)
	return db
}

// Count returns the number of compiled signatures.
func (d *DB) Count() int {
	if d == nil {
		return 0
	}
	return len(d.rules)
}

// LoadFile parses a p0f.fp file (the `[tcp:request]` / `[tcp:response]`
// sections) and adds its signatures. Returns the number added. Other sections
// (mtu, http) are ignored. Unparseable lines are skipped.
func (d *DB) LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var label string
	inTCP := false
	added := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inTCP = strings.HasPrefix(line, "[tcp:")
			continue
		}
		if !inTCP {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "label":
			label = v
		case "sig":
			if r, ok := parseSig(label, v); ok {
				d.rules = append(d.rules, r)
				added++
			}
		}
	}
	return added, sc.Err()
}

// loadText parses an embedded p0f.fp-format string (no file I/O).
func (d *DB) loadText(text string) {
	var label string
	inTCP := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inTCP = strings.HasPrefix(line, "[tcp:")
			continue
		}
		if !inTCP {
			continue
		}
		if k, v, ok := splitKV(line); ok {
			switch k {
			case "label":
				label = v
			case "sig":
				if r, ok := parseSig(label, v); ok {
					d.rules = append(d.rules, r)
				}
			}
		}
	}
}

func splitKV(line string) (k, v string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// parseSig compiles a p0f signature string into a rule.
func parseSig(label, sig string) (rule, bool) {
	f := strings.Split(sig, ":")
	if len(f) != 8 {
		return rule{}, false
	}
	r := rule{label: label, quirks: map[string]struct{}{}}
	r.ittl = atoiWild(strings.TrimSuffix(f[1], "-"), 0) // ignore the "-" observed-below marker
	r.olen = atoiWild(f[2], -1)
	r.mss = atoiWild(f[3], -1)
	// wsize,wscale
	wparts := strings.SplitN(f[4], ",", 2)
	r.wsize = parseWsize(wparts[0])
	r.wscale = -2
	if len(wparts) == 2 {
		r.wscale = atoiWild(wparts[1], -2)
	}
	if f[5] != "" && f[5] != "*" {
		r.layout = strings.Split(f[5], ",")
	}
	if f[6] != "" && f[6] != "*" {
		for _, q := range strings.Split(f[6], ",") {
			r.quirks[q] = struct{}{}
		}
	}
	switch f[7] {
	case "*":
		r.pclass = -1
	case "+":
		r.pclass = 1
	default:
		r.pclass = 0
	}
	return r, true
}

func parseWsize(s string) wsizeExpr {
	switch {
	case s == "*":
		return wsizeExpr{kind: "any"}
	case strings.HasPrefix(s, "mss*"):
		return wsizeExpr{kind: "mss", val: atoiWild(s[4:], 0)}
	case strings.HasPrefix(s, "mtu*"):
		return wsizeExpr{kind: "mtu", val: atoiWild(s[4:], 0)}
	case strings.HasPrefix(s, "%"):
		return wsizeExpr{kind: "mod", val: atoiWild(s[1:], 0)}
	default:
		return wsizeExpr{kind: "exact", val: atoiWild(s, 0)}
	}
}

// atoiWild parses n, returning wild for "*" or a parse error.
func atoiWild(s string, wild int) int {
	if s == "*" || s == "" {
		return wild
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return wild
	}
	return n
}

// Match returns the label of the first signature that matches s, or "".
func (d *DB) Match(s Signature) string {
	if d == nil {
		return ""
	}
	for i := range d.rules {
		if d.rules[i].matches(s) {
			return d.rules[i].label
		}
	}
	return ""
}

func (r *rule) matches(s Signature) bool {
	if r.ittl != 0 && r.ittl != s.ITTL {
		return false
	}
	if r.olen != -1 && r.olen != s.OptLen {
		return false
	}
	if r.mss != -1 && r.mss != s.MSS {
		return false
	}
	if r.wscale != -2 && r.wscale != s.WScale {
		return false
	}
	if !r.wsize.matches(s) {
		return false
	}
	if r.pclass != -1 && r.pclass != s.PClass {
		return false
	}
	if r.layout != nil && !eqStrings(r.layout, s.Layout) {
		return false
	}
	if len(r.quirks) > 0 && !quirksMatch(r.quirks, s.Quirks) {
		return false
	}
	return true
}

func (w wsizeExpr) matches(s Signature) bool {
	switch w.kind {
	case "any", "":
		return true
	case "exact":
		return s.WSize == w.val
	case "mss":
		return s.MSS > 0 && s.WSize == s.MSS*w.val
	case "mtu":
		return s.MSS > 0 && s.WSize == (s.MSS+40)*w.val
	case "mod":
		return w.val != 0 && s.WSize%w.val == 0
	}
	return false
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func quirksMatch(want map[string]struct{}, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	for _, q := range got {
		if _, ok := want[q]; !ok {
			return false
		}
	}
	return true
}
