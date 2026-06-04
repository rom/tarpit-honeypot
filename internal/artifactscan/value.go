package artifactscan

import "strings"

// value is a typed runtime value produced when evaluating a condition
// expression: an integer, float, string, boolean, or "undefined". Module
// expressions over an artifact that isn't the relevant format (e.g. pe.is_dll()
// on an ELF) yield undefined — and, as in real YARA, any comparison or boolean
// use of an undefined value is false, so such a rule simply doesn't fire.
type value struct {
	kind valKind
	i    int64
	f    float64
	s    string
	b    bool
}

type valKind uint8

const (
	vUndef valKind = iota
	vInt
	vFloat
	vStr
	vBool
)

var undefVal = value{kind: vUndef}

func intVal(i int64) value     { return value{kind: vInt, i: i} }
func floatVal(f float64) value { return value{kind: vFloat, f: f} }
func strVal(s string) value    { return value{kind: vStr, s: s} }
func boolVal(b bool) value     { return value{kind: vBool, b: b} }

// truthy reports whether v is true in a boolean context (the rule fires when
// its top-level condition is truthy). Undefined is never truthy.
func (v value) truthy() bool {
	switch v.kind {
	case vBool:
		return v.b
	case vInt:
		return v.i != 0
	case vFloat:
		return v.f != 0
	case vStr:
		return v.s != ""
	}
	return false
}

// asFloat returns v as a float64 (ints promote); ok is false for non-numerics.
func (v value) asFloat() (float64, bool) {
	switch v.kind {
	case vInt:
		return float64(v.i), true
	case vFloat:
		return v.f, true
	}
	return 0, false
}

// asInt returns v as an int (ints exact, floats truncated); ok=false otherwise.
func (v value) asInt() (int64, bool) {
	switch v.kind {
	case vInt:
		return v.i, true
	case vFloat:
		return int64(v.f), true
	}
	return 0, false
}

// compareValues evaluates a relational operator. Undefined operands, or
// mismatched string/number operands, compare false (never panic). Strings
// compare case-insensitively, which keeps hex-hash comparisons robust against
// upper/lowercase rule authoring.
func compareValues(op string, a, b value) value {
	if a.kind == vUndef || b.kind == vUndef {
		return boolVal(false)
	}
	if a.kind == vStr || b.kind == vStr {
		if a.kind != vStr || b.kind != vStr {
			return boolVal(false)
		}
		eq := strings.EqualFold(a.s, b.s)
		switch op {
		case "==":
			return boolVal(eq)
		case "!=":
			return boolVal(!eq)
		}
		return boolVal(false)
	}
	if a.kind == vInt && b.kind == vInt {
		return boolVal(cmpInt(op, a.i, b.i))
	}
	af, _ := a.asFloat()
	bf, _ := b.asFloat()
	return boolVal(cmpFloat(op, af, bf))
}

func cmpInt(op string, a, b int64) bool {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	}
	return false
}

func cmpFloat(op string, a, b float64) bool {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	}
	return false
}

// arith evaluates a binary arithmetic / bitwise operator. Bitwise ops, integer
// division (\) and modulo require integer operands; +,-,* promote to float when
// either side is a float. Division/shift hazards yield undefined.
func arith(op string, a, b value) value {
	if a.kind == vUndef || b.kind == vUndef {
		return undefVal
	}
	switch op {
	case "\\", "%", "&", "|", "^", "<<", ">>":
		if a.kind != vInt || b.kind != vInt {
			return undefVal
		}
		switch op {
		case "\\":
			if b.i == 0 {
				return undefVal
			}
			return intVal(a.i / b.i)
		case "%":
			if b.i == 0 {
				return undefVal
			}
			return intVal(a.i % b.i)
		case "&":
			return intVal(a.i & b.i)
		case "|":
			return intVal(a.i | b.i)
		case "^":
			return intVal(a.i ^ b.i)
		case "<<":
			return intVal(a.i << uint(b.i&63))
		case ">>":
			return intVal(a.i >> uint(b.i&63))
		}
	}
	if a.kind == vInt && b.kind == vInt {
		switch op {
		case "+":
			return intVal(a.i + b.i)
		case "-":
			return intVal(a.i - b.i)
		case "*":
			return intVal(a.i * b.i)
		}
		return undefVal
	}
	af, _ := a.asFloat()
	bf, _ := b.asFloat()
	switch op {
	case "+":
		return floatVal(af + bf)
	case "-":
		return floatVal(af - bf)
	case "*":
		return floatVal(af * bf)
	}
	return undefVal
}
