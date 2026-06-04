package artifactscan

import (
	"fmt"
	"strconv"
	"strings"
)

// parseCondition compiles a YARA-subset condition into a condExpr tree.
//
// Grammar (lowest → highest precedence):
//
//	or      := and ('or' and)*
//	and     := not ('and' not)*
//	not     := 'not' not | compare
//	compare := bitor (('=='|'!='|'<'|'<='|'>'|'>=') bitor)?
//	bitor   := bitxor ('|' bitxor)*
//	bitxor  := bitand ('^' bitand)*
//	bitand  := shift ('&' shift)*
//	shift   := add (('<<'|'>>') add)*
//	add     := mul (('+'|'-') mul)*
//	mul     := unary (('*'|'\'|'%') unary)*
//	unary   := ('-'|'~') unary | primary
//	primary := '(' or ')' | 'true' | 'false'
//	         | ('all'|'any'|number) 'of' set
//	         | '$id' | number | string
//	         | module ('.' field)* ( '(' args ')' )?
//	set     := 'them' | '(' ($idglob (',' $idglob)*) ')'
//
// Supported modules: filesize, pe.*, elf.*, math.*, hash.*, and the integer
// readers uint8/16/32(be) and int8/16/32. Constructs outside this subset
// (string-count #a, offset @a / 'at', 'for' loops, regex args, unknown
// modules) cause the rule to be skipped — ParseRules collects the error and
// keeps the rest of the file, so dropping in a real-world .yar collection
// still loads whatever is expressible.
func parseCondition(s string) (condExpr, error) {
	toks, err := tokenizeCond(s)
	if err != nil {
		return nil, err
	}
	p := &condParser{toks: toks}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("condition: trailing tokens at %q", p.peekText())
	}
	return expr, nil
}

// --- tokenizer -------------------------------------------------------------

type ctkind uint8

const (
	tkIdent ctkind = iota // bareword / keyword
	tkStrID               // $id, $id*
	tkNum                 // integer literal (decimal or 0x..), KB/MB/GB scaled
	tkStr                 // "..." literal
	tkOp                  // operator or punctuation
)

type ctoken struct {
	kind ctkind
	text string
	num  int64
}

func tokenizeCond(s string) ([]ctoken, error) {
	var toks []ctoken
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			j := i + 1
			for j < len(s) && (s[j] == '_' || (s[j] >= '0' && s[j] <= '9') ||
				(s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
				j++
			}
			toks = append(toks, ctoken{kind: tkIdent, text: s[i:j]})
			i = j
		case c == '$':
			j := i + 1
			for j < len(s) && (s[j] == '_' || (s[j] >= '0' && s[j] <= '9') ||
				(s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
				j++
			}
			if j < len(s) && s[j] == '*' { // $a* glob
				j++
			}
			toks = append(toks, ctoken{kind: tkStrID, text: s[i:j]})
			i = j
		case c >= '0' && c <= '9':
			n, adv, err := scanNumber(s[i:])
			if err != nil {
				return nil, err
			}
			toks = append(toks, ctoken{kind: tkNum, num: n})
			i += adv
		case c == '"':
			end := indexUnescapedQuote(s[i+1:])
			if end < 0 {
				return nil, fmt.Errorf("condition: unterminated string literal")
			}
			raw := s[i : i+end+2]
			text, err := strconv.Unquote(raw)
			if err != nil {
				text = s[i+1 : i+end+1]
			}
			toks = append(toks, ctoken{kind: tkStr, text: text})
			i += end + 2
		case c == '(' || c == ')' || c == ',' || c == '.':
			toks = append(toks, ctoken{kind: tkOp, text: string(c)})
			i++
		case c == '+' || c == '-' || c == '*' || c == '%' || c == '&' ||
			c == '|' || c == '^' || c == '~' || c == '\\':
			toks = append(toks, ctoken{kind: tkOp, text: string(c)})
			i++
		case c == '=':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, ctoken{kind: tkOp, text: "=="})
				i += 2
			} else {
				return nil, fmt.Errorf("condition: lone '='")
			}
		case c == '!':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, ctoken{kind: tkOp, text: "!="})
				i += 2
			} else {
				return nil, fmt.Errorf("condition: unsupported '!' (string operators)")
			}
		case c == '<':
			i += emitRel(&toks, s, i, '<', "<=", "<<")
		case c == '>':
			i += emitRel(&toks, s, i, '>', ">=", ">>")
		default:
			// '#', '@', '/', etc. — unsupported construct; skip the rule.
			return nil, fmt.Errorf("condition: unsupported character %q", string(c))
		}
	}
	return toks, nil
}

// emitRel handles the '<' / '>' family: "<=", "<<", "<" (and the > mirror).
// Returns how many bytes were consumed.
func emitRel(toks *[]ctoken, s string, i int, base byte, eq, dbl string) int {
	if i+1 < len(s) {
		switch s[i+1] {
		case '=':
			*toks = append(*toks, ctoken{kind: tkOp, text: eq})
			return 2
		case base:
			*toks = append(*toks, ctoken{kind: tkOp, text: dbl})
			return 2
		}
	}
	*toks = append(*toks, ctoken{kind: tkOp, text: string(base)})
	return 1
}

// scanNumber parses a decimal / 0x-hex integer with an optional KB/MB/GB size
// suffix (YARA: 1KB == 1024). Returns the value and bytes consumed.
func scanNumber(s string) (int64, int, error) {
	j := 0
	base := 10
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		base = 16
		j = 2
		for j < len(s) && isHexDigit(s[j]) {
			j++
		}
	} else {
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
	}
	if j == 0 || (base == 16 && j == 2) {
		return 0, 0, fmt.Errorf("condition: malformed number %q", s)
	}
	digits := s[:j]
	if base == 16 {
		digits = s[2:j]
	}
	v, err := strconv.ParseInt(digits, base, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("condition: bad number %q: %w", s[:j], err)
	}
	// Size suffix.
	mult := int64(1)
	switch {
	case strings.HasPrefix(strings.ToUpper(s[j:]), "KB"):
		mult, j = 1<<10, j+2
	case strings.HasPrefix(strings.ToUpper(s[j:]), "MB"):
		mult, j = 1<<20, j+2
	case strings.HasPrefix(strings.ToUpper(s[j:]), "GB"):
		mult, j = 1<<30, j+2
	}
	return v * mult, j, nil
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// --- parser ----------------------------------------------------------------

type condParser struct {
	toks []ctoken
	pos  int
}

func (p *condParser) peek() (ctoken, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return ctoken{}, false
}

func (p *condParser) peekText() string {
	if t, ok := p.peek(); ok {
		return t.text
	}
	return ""
}

// matchKw consumes the next token if it is the identifier keyword kw.
func (p *condParser) matchKw(kw string) bool {
	if t, ok := p.peek(); ok && t.kind == tkIdent && t.text == kw {
		p.pos++
		return true
	}
	return false
}

// matchOp consumes the next token if it is the operator/punctuation op.
func (p *condParser) matchOp(op string) bool {
	if t, ok := p.peek(); ok && t.kind == tkOp && t.text == op {
		p.pos++
		return true
	}
	return false
}

func (p *condParser) parseOr() (condExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.matchKw("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = condOr{left, right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.matchKw("and") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = condAnd{left, right}
	}
	return left, nil
}

func (p *condParser) parseNot() (condExpr, error) {
	if p.matchKw("not") {
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return condNot{x}, nil
	}
	return p.parseCompare()
}

var relOps = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true}

func (p *condParser) parseCompare() (condExpr, error) {
	left, err := p.parseBinary(0)
	if err != nil {
		return nil, err
	}
	if t, ok := p.peek(); ok && t.kind == tkOp && relOps[t.text] {
		p.pos++
		right, err := p.parseBinary(0)
		if err != nil {
			return nil, err
		}
		return exprCompare{op: t.text, a: left, b: right}, nil
	}
	return left, nil
}

// binLevels lists left-associative binary operator tiers from lowest to
// highest precedence; parseBinary climbs them.
var binLevels = [][]string{
	{"|"},
	{"^"},
	{"&"},
	{"<<", ">>"},
	{"+", "-"},
	{"*", "\\", "%"},
}

func (p *condParser) parseBinary(level int) (condExpr, error) {
	if level >= len(binLevels) {
		return p.parseUnary()
	}
	left, err := p.parseBinary(level + 1)
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tkOp || !inSet(binLevels[level], t.text) {
			return left, nil
		}
		p.pos++
		right, err := p.parseBinary(level + 1)
		if err != nil {
			return nil, err
		}
		left = exprArith{op: t.text, a: left, b: right}
	}
}

func inSet(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func (p *condParser) parseUnary() (condExpr, error) {
	if t, ok := p.peek(); ok && t.kind == tkOp && (t.text == "-" || t.text == "~") {
		p.pos++
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return exprUnary{op: t.text, x: x}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condExpr, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("condition: unexpected end of expression")
	}
	switch t.kind {
	case tkOp:
		if t.text == "(" {
			p.pos++
			x, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			if !p.matchOp(")") {
				return nil, fmt.Errorf("condition: expected )")
			}
			return x, nil
		}
		return nil, fmt.Errorf("condition: unexpected %q", t.text)
	case tkStrID:
		p.pos++
		return condID{t.text}, nil
	case tkStr:
		p.pos++
		return exprStr{t.text}, nil
	case tkNum:
		p.pos++
		if p.matchKw("of") {
			return p.parseOfTail(int(t.num))
		}
		return exprNum{t.num}, nil
	case tkIdent:
		switch t.text {
		case "true":
			p.pos++
			return condBool{true}, nil
		case "false":
			p.pos++
			return condBool{false}, nil
		case "all":
			p.pos++
			if !p.matchKw("of") {
				return nil, fmt.Errorf("condition: expected 'of' after 'all'")
			}
			return p.parseOfTail(-1)
		case "any":
			p.pos++
			if !p.matchKw("of") {
				return nil, fmt.Errorf("condition: expected 'of' after 'any'")
			}
			return p.parseOfTail(0)
		case "and", "or", "not", "of", "them":
			return nil, fmt.Errorf("condition: unexpected keyword %q", t.text)
		default:
			return p.parseModule()
		}
	}
	return nil, fmt.Errorf("condition: unsupported token %q", t.text)
}

// parseOfTail parses the set after an `<N>|all|any of` quantifier.
func (p *condParser) parseOfTail(n int) (condExpr, error) {
	set, err := p.parseSet()
	if err != nil {
		return nil, err
	}
	return condOf{n: n, set: set}, nil
}

func (p *condParser) parseSet() ([]string, error) {
	if p.matchKw("them") {
		return []string{"them"}, nil
	}
	if !p.matchOp("(") {
		return nil, fmt.Errorf("condition: expected 'them' or '(' in set")
	}
	var set []string
	for {
		t, ok := p.peek()
		if !ok {
			return nil, fmt.Errorf("condition: unterminated set")
		}
		switch {
		case t.kind == tkStrID:
			set = append(set, t.text)
			p.pos++
		case t.kind == tkIdent && t.text == "them":
			set = append(set, "them")
			p.pos++
		default:
			return nil, fmt.Errorf("condition: unexpected %q in set", t.text)
		}
		if p.matchOp(",") {
			continue
		}
		if p.matchOp(")") {
			return set, nil
		}
		return nil, fmt.Errorf("condition: expected , or ) in set, got %q", p.peekText())
	}
}

// parseModule parses a dotted module path with an optional call: filesize,
// pe.is_dll(), pe.imports("k","f"), math.entropy(0, filesize), uint16(0).
func (p *condParser) parseModule() (condExpr, error) {
	t, _ := p.peek()
	head := t.text
	if !knownModuleHead(head) {
		return nil, fmt.Errorf("condition: unsupported identifier %q", head)
	}
	p.pos++
	path := []string{head}
	for p.matchOp(".") {
		nt, ok := p.peek()
		if !ok || nt.kind != tkIdent {
			return nil, fmt.Errorf("condition: expected field name after '.'")
		}
		path = append(path, nt.text)
		p.pos++
	}
	call := false
	var args []condExpr
	if p.matchOp("(") {
		call = true
		if !p.matchOp(")") { // arguments present
			for {
				a, err := p.parseOr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if p.matchOp(",") {
					continue
				}
				if p.matchOp(")") {
					break
				}
				return nil, fmt.Errorf("condition: expected , or ) in arguments")
			}
		}
	}
	return exprModule{path: path, args: args, call: call}, nil
}
