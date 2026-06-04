package artifactscan

import (
	"fmt"
	"strconv"
	"strings"
)

// parseCondition compiles a YARA-subset condition expression into a condExpr.
// Grammar (lowest to highest precedence):
//
//	or   := and ('or' and)*
//	and  := unary ('and' unary)*
//	unary:= 'not' unary | primary
//	prim := '(' or ')' | ofExpr | '$id' | 'true' | 'false'
//	ofExpr := ('all'|'any'|number) 'of' set
//	set  := 'them' | '(' idglob (',' idglob)* ')'
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
		return nil, fmt.Errorf("condition: trailing tokens at %q", p.peek())
	}
	return expr, nil
}

type condParser struct {
	toks []string
	pos  int
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) parseOr() (condExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = condOr{left, right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condExpr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = condAnd{left, right}
	}
	return left, nil
}

func (p *condParser) parseUnary() (condExpr, error) {
	if p.peek() == "not" {
		p.next()
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return condNot{x}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condExpr, error) {
	t := p.peek()
	switch {
	case t == "(":
		p.next()
		x, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("condition: expected )")
		}
		return x, nil
	case t == "true":
		p.next()
		return condBool{true}, nil
	case t == "false":
		p.next()
		return condBool{false}, nil
	case t == "all" || t == "any" || isNumber(t):
		return p.parseOf()
	case strings.HasPrefix(t, "$"):
		p.next()
		return condID{t}, nil
	}
	return nil, fmt.Errorf("condition: unsupported token %q", t)
}

func (p *condParser) parseOf() (condExpr, error) {
	q := p.next()
	n := 0
	switch {
	case q == "all":
		n = -1
	case q == "any":
		n = 0
	default:
		v, err := strconv.Atoi(q)
		if err != nil {
			return nil, fmt.Errorf("condition: bad quantifier %q", q)
		}
		n = v
	}
	if p.next() != "of" {
		return nil, fmt.Errorf("condition: expected 'of' after %q", q)
	}
	set, err := p.parseSet()
	if err != nil {
		return nil, err
	}
	return condOf{n: n, set: set}, nil
}

func (p *condParser) parseSet() ([]string, error) {
	if p.peek() == "them" {
		p.next()
		return []string{"them"}, nil
	}
	if p.peek() != "(" {
		return nil, fmt.Errorf("condition: expected 'them' or '(' in set")
	}
	p.next()
	var set []string
	for {
		t := p.next()
		if t == "" {
			return nil, fmt.Errorf("condition: unterminated set")
		}
		set = append(set, t)
		switch p.peek() {
		case ",":
			p.next()
			continue
		case ")":
			p.next()
			return set, nil
		default:
			return nil, fmt.Errorf("condition: expected , or ) in set, got %q", p.peek())
		}
	}
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// tokenizeCond splits a condition into tokens. Rejects arithmetic/comparison
// operators and function-call constructs (returns an error so the rule is
// skipped as unsupported).
func tokenizeCond(s string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == ',':
			toks = append(toks, string(c))
			i++
		case c == '$' || c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] == '*' || s[j] == '$' ||
				(s[j] >= '0' && s[j] <= '9') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
				j++
			}
			word := s[i:j]
			// Reject member access / function calls (pe.imports(...), etc.).
			if j < len(s) && (s[j] == '.' || s[j] == '(') && strings.HasPrefix(word, "$") == false && !isQuantOrKeyword(word) {
				return nil, fmt.Errorf("condition: unsupported construct near %q", word)
			}
			toks = append(toks, word)
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		default:
			return nil, fmt.Errorf("condition: unsupported character %q", string(c))
		}
	}
	return toks, nil
}

func isQuantOrKeyword(w string) bool {
	switch w {
	case "all", "any", "of", "them", "and", "or", "not", "true", "false":
		return true
	}
	return false
}
