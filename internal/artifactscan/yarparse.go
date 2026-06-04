package artifactscan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseRules parses YARA-subset source into compiled rules. It is permissive:
// a rule that uses a construct outside the supported subset is skipped (with
// an error collected) rather than failing the whole file, so dropping a
// real-world .yar collection in still loads whatever is expressible.
//
// Supported subset:
//   - rule Name (: tag1 tag2)? { ... }
//   - meta:    key = "string" | number | true/false
//   - strings: $id = "text" [nocase wide ascii fullword]
//     $id = { 4D 5A ?? ?? }          (?? wildcard bytes)
//     $id = /regex/ [i] [s]          (RE2 syntax)
//   - condition: $a, and, or, not, ( ), all|any|<N> of (them | $a*, $b)
//
// Unsupported (rule skipped): hex jumps [n-m] / alternations, uintXX(),
// filesize, entrypoint, arithmetic / comparison operators, for..of loops.
func ParseRules(src string) ([]Rule, []error) {
	src = stripComments(src)
	var rules []Rule
	var errs []error
	for _, block := range splitRules(src) {
		r, err := parseRule(block)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, r)
	}
	return rules, errs
}

// stripComments removes // line comments and /* block */ comments while
// preserving string literals.
func stripComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			// Copy a string literal verbatim so // and /* inside it survive.
			b.WriteByte(c)
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i])
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// splitRules returns the source of each top-level `rule ... { ... }` block by
// matching braces (respecting string literals).
func splitRules(s string) []string {
	var out []string
	i := 0
	for {
		idx := indexRuleKeyword(s, i)
		if idx < 0 {
			break
		}
		brace := strings.IndexByte(s[idx:], '{')
		if brace < 0 {
			break
		}
		start := idx
		j := idx + brace
		depth := 0
		for j < len(s) {
			switch s[j] {
			case '"':
				j++
				for j < len(s) && s[j] != '"' {
					if s[j] == '\\' {
						j++
					}
					j++
				}
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					out = append(out, s[start:j+1])
					j++
					goto next
				}
			}
			j++
		}
	next:
		i = j
		if i <= start {
			i = start + 1
		}
	}
	return out
}

// indexRuleKeyword finds the next "rule" keyword at a word boundary from pos.
func indexRuleKeyword(s string, pos int) int {
	for {
		i := strings.Index(s[pos:], "rule")
		if i < 0 {
			return -1
		}
		at := pos + i
		leftOK := at == 0 || !isWordByte(s[at-1])
		rightOK := at+4 < len(s) && (s[at+4] == ' ' || s[at+4] == '\t' || s[at+4] == '\n' || s[at+4] == '\r')
		if leftOK && rightOK {
			return at
		}
		pos = at + 4
	}
}

var reRuleHeader = regexp.MustCompile(`(?s)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(:\s*([A-Za-z0-9_\s]+?))?\s*\{`)

func parseRule(block string) (Rule, error) {
	m := reRuleHeader.FindStringSubmatch(block)
	if m == nil {
		return Rule{}, fmt.Errorf("artifactscan: malformed rule header")
	}
	r := Rule{Name: m[1]}
	if strings.TrimSpace(m[3]) != "" {
		r.Tags = strings.Fields(m[3])
	}
	body := block[strings.Index(block, "{")+1 : strings.LastIndex(block, "}")]

	metaSrc, stringsSrc, condSrc := splitSections(body)
	r.Meta = parseMeta(metaSrc)
	strs, err := parseStrings(stringsSrc)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %s: %w", r.Name, err)
	}
	r.Strings = strs
	cond := strings.TrimSpace(condSrc)
	if cond == "" {
		return Rule{}, fmt.Errorf("rule %s: empty condition", r.Name)
	}
	expr, err := parseCondition(cond)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %s: %w", r.Name, err)
	}
	r.Condition = expr
	return r, nil
}

// splitSections carves a rule body into its meta / strings / condition spans
// by locating the section keywords at line starts.
func splitSections(body string) (meta, strs, cond string) {
	type sec struct {
		name string
		pos  int
	}
	var found []sec
	for _, name := range []string{"meta:", "strings:", "condition:"} {
		if i := sectionIndex(body, name); i >= 0 {
			found = append(found, sec{name, i})
		}
	}
	// sort by position
	for i := 0; i < len(found); i++ {
		for j := i + 1; j < len(found); j++ {
			if found[j].pos < found[i].pos {
				found[i], found[j] = found[j], found[i]
			}
		}
	}
	for i, s := range found {
		start := s.pos + len(s.name)
		end := len(body)
		if i+1 < len(found) {
			end = found[i+1].pos
		}
		span := body[start:end]
		switch s.name {
		case "meta:":
			meta = span
		case "strings:":
			strs = span
		case "condition:":
			cond = span
		}
	}
	return meta, strs, cond
}

// sectionIndex finds a section keyword preceded only by whitespace on its line.
func sectionIndex(body, kw string) int {
	from := 0
	for {
		i := strings.Index(body[from:], kw)
		if i < 0 {
			return -1
		}
		at := from + i
		// preceding char must be a line boundary / whitespace
		j := at - 1
		ok := true
		for j >= 0 {
			if body[j] == '\n' {
				break
			}
			if body[j] != ' ' && body[j] != '\t' {
				ok = false
				break
			}
			j--
		}
		if ok {
			return at
		}
		from = at + len(kw)
	}
}

func parseMeta(src string) map[string]string {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	out := map[string]string{}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}
		if s, err := strconv.Unquote(val); err == nil {
			val = s
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var reStringEntry = regexp.MustCompile(`(?m)^\s*(\$[A-Za-z0-9_]*)\s*=\s*(.*)$`)

func parseStrings(src string) ([]ruleString, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	var out []ruleString
	for _, m := range reStringEntry.FindAllStringSubmatch(src, -1) {
		id := m[1]
		rest := strings.TrimSpace(m[2])
		s, err := parseStringAtom(id, rest)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func parseStringAtom(id, rest string) (ruleString, error) {
	switch {
	case strings.HasPrefix(rest, "\""):
		end := indexUnescapedQuote(rest[1:])
		if end < 0 {
			return ruleString{}, fmt.Errorf("string %s: unterminated literal", id)
		}
		raw := rest[:end+2]
		text, err := strconv.Unquote(raw)
		if err != nil {
			// fall back: strip the surrounding quotes literally
			text = rest[1 : end+1]
		}
		mods := rest[end+2:]
		lit := &litAtom{text: text, ascii: true}
		applyStringMods(lit, mods)
		return ruleString{id: id, lit: lit}, nil
	case strings.HasPrefix(rest, "{"):
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return ruleString{}, fmt.Errorf("string %s: unterminated hex", id)
		}
		hb, err := parseHex(rest[1:end])
		if err != nil {
			return ruleString{}, fmt.Errorf("string %s: %w", id, err)
		}
		return ruleString{id: id, hex: hb}, nil
	case strings.HasPrefix(rest, "/"):
		end := lastRegexSlash(rest)
		if end <= 0 {
			return ruleString{}, fmt.Errorf("string %s: unterminated regex", id)
		}
		pat := rest[1:end]
		flags := rest[end+1:]
		goPat := pat
		if strings.Contains(flags, "i") {
			goPat = "(?i)" + goPat
		}
		if strings.Contains(flags, "s") {
			goPat = "(?s)" + goPat
		}
		re, err := regexp.Compile(goPat)
		if err != nil {
			return ruleString{}, fmt.Errorf("string %s: regex: %w", id, err)
		}
		return ruleString{id: id, re: re}, nil
	}
	return ruleString{}, fmt.Errorf("string %s: unrecognized atom %q", id, rest)
}

func applyStringMods(lit *litAtom, mods string) {
	for _, w := range strings.Fields(mods) {
		switch w {
		case "nocase":
			lit.nocase = true
		case "wide":
			lit.wide = true
		case "ascii":
			lit.ascii = true
		case "fullword":
			lit.fullword = true
		}
	}
	// `wide` alone (no `ascii`) means UTF-16 only.
	if lit.wide && !strings.Contains(mods, "ascii") {
		lit.ascii = false
	}
}

func indexUnescapedQuote(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '"' {
			return i
		}
	}
	return -1
}

// lastRegexSlash finds the closing slash of a /regex/ atom, skipping escaped
// slashes.
func lastRegexSlash(rest string) int {
	for i := 1; i < len(rest); i++ {
		if rest[i] == '\\' {
			i++
			continue
		}
		if rest[i] == '/' {
			return i
		}
	}
	return -1
}

// parseHex parses a YARA hex body into bytes/wildcards. Rejects jumps and
// alternations (returns an error so the rule is skipped).
func parseHex(s string) ([]hexByte, error) {
	if strings.ContainsAny(s, "[](|") {
		return nil, fmt.Errorf("hex jumps/alternations unsupported")
	}
	var out []hexByte
	toks := strings.Fields(s)
	for _, t := range toks {
		for len(t) > 0 {
			if len(t) < 2 {
				return nil, fmt.Errorf("odd hex nibble %q", t)
			}
			pair := t[:2]
			t = t[2:]
			if pair == "??" {
				out = append(out, hexByte{wildcard: true})
				continue
			}
			if strings.Contains(pair, "?") {
				// nibble wildcard (e.g. 4?) — approximate as full wildcard.
				out = append(out, hexByte{wildcard: true})
				continue
			}
			v, err := strconv.ParseUint(pair, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("bad hex byte %q", pair)
			}
			out = append(out, hexByte{val: byte(v)})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty hex pattern")
	}
	return out, nil
}
