package yara

import (
	"fmt"
	"strconv"
	"strings"
)

// StringKind distinguishes the three forms a YARA string can take.
type StringKind int

const (
	KindText StringKind = iota
	KindHex
	KindRegex
)

// StringDef is one `$id = ...` entry.
type StringDef struct {
	ID   string // including the leading '$'
	Kind StringKind
	Text string
	Mods string // regex modifiers (i, s)

	NoCase   bool
	Wide     bool
	ASCII    bool
	FullWord bool
}

// Rule is a parsed YARA rule.
type Rule struct {
	Name    string
	Tags    []string
	Meta    map[string]string
	Strings []StringDef
	Cond    Node
	Private bool
	Global  bool
	Origin  string

	// compiled form, filled by Compile
	matchers []*matcher
	// literals are the plain text strings usable as a cheap prefilter.
	literals []string
	// prefilterable is false when the rule could match a file in which none of
	// its literals appear (hex/regex strings, negations, filesize-only
	// conditions). Such rules must always be fully evaluated.
	prefilterable bool
}

// Severity derives an alert level from rule metadata, falling back to a
// sensible default. Public rulesets commonly carry a `severity` or `score`.
func (r *Rule) Severity() string {
	if v, ok := r.Meta["severity"]; ok {
		return strings.ToLower(v)
	}
	if v, ok := r.Meta["score"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			switch {
			case n >= 80:
				return "critical"
			case n >= 60:
				return "high"
			case n >= 40:
				return "medium"
			}
			return "low"
		}
	}
	return "high"
}

func (r *Rule) Description() string {
	for _, k := range []string{"description", "desc", "info"} {
		if v, ok := r.Meta[k]; ok {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// condition AST
// ---------------------------------------------------------------------------

// Node is a boolean expression node.
type Node interface{ isNode() }

type nodeBool struct{ v bool }
type nodeAnd struct{ l, r Node }
type nodeOr struct{ l, r Node }
type nodeNot struct{ x Node }

// nodeStr is `$a` — true when the string matched at least once.
type nodeStr struct{ id string }

// nodeStrAt is `$a at <offset>`.
type nodeStrAt struct {
	id  string
	off Value
}

type quant int

const (
	quantAny quant = iota
	quantAll
	quantNone
	quantN
)

// nodeOf is `any|all|none|N of (them | $a*, $b)`.
type nodeOf struct {
	q   quant
	n   int64
	ids []string // empty means "them"
}

// nodeNear is `near(<set>, <set>, N)` — true when some string from the first
// set matches within N bytes of some string from the second.
//
// This is a WordEye extension, not stock YARA. It exists because co-occurrence
// anywhere in a file is not evidence: a 400KB plugin contains a decoder
// somewhere and an executor somewhere, and joining them with `and` produces a
// critical finding about two unrelated lines 9,000 apart. Malicious loaders put
// the decoder INSIDE the call to the sink. Distance is the signal.
//
// Stock YARA can express this only as a nested `for` over @offset arrays, which
// this subset does not implement; near() is the readable equivalent.
type nodeNear struct {
	a, b []string
	dist int64
}

// nodeRuleRef is a reference to another rule by name. YARA allows a rule to
// build on a previously defined one (commonly a `private rule` acting as a
// file-type guard), and the built-in ruleset uses exactly that shape.
type nodeRuleRef struct{ name string }

// nodeCmp compares two numeric values.
type nodeCmp struct {
	op   string
	l, r Value
}

func (nodeBool) isNode()    {}
func (nodeAnd) isNode()     {}
func (nodeOr) isNode()      {}
func (nodeNot) isNode()     {}
func (nodeStr) isNode()     {}
func (nodeStrAt) isNode()   {}
func (nodeOf) isNode()      {}
func (nodeNear) isNode()    {}
func (nodeCmp) isNode()     {}
func (nodeRuleRef) isNode() {}

// Value is a numeric expression.
type Value interface{ isValue() }

type valNum struct{ n int64 }
type valCount struct{ id string }  // #a
type valOffset struct{ id string } // @a
type valFilesize struct{}
type valUint struct {
	width int // bits
	off   Value
}

func (valNum) isValue()      {}
func (valCount) isValue()    {}
func (valOffset) isValue()   {}
func (valFilesize) isValue() {}
func (valUint) isValue()     {}

// ---------------------------------------------------------------------------
// condition parser
// ---------------------------------------------------------------------------

func (p *parser) parseCondition() (Node, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.tok.kind == tOp && p.tok.text == "or" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = nodeOr{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.tok.kind == tOp && p.tok.text == "and" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = nodeAnd{left, right}
	}
	return left, nil
}

func (p *parser) parseNot() (Node, error) {
	if p.tok.kind == tOp && p.tok.text == "not" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return nodeNot{x}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	lx := p.lx

	// Parenthesised sub-expression.
	if p.tok.kind == tPunct && p.tok.text == "(" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.tok.kind != tPunct || p.tok.text != ")" {
			return nil, lx.errf("expected ')'")
		}
		if err := p.advance(false); err != nil {
			return nil, err
		}
		return inner, nil
	}

	if p.tok.kind == tOp {
		switch p.tok.text {
		case "true", "false":
			v := p.tok.text == "true"
			if err := p.advance(false); err != nil {
				return nil, err
			}
			return nodeBool{v}, nil
		case "any", "all", "none":
			return p.parseOf()
		}
	}

	// `N of ...` — a number here is a quantifier only if `of` follows.
	if p.tok.kind == tNumber {
		save := p.tok
		if err := p.advance(false); err != nil {
			return nil, err
		}
		if p.tok.kind == tOp && p.tok.text == "of" {
			n, err := parseNumber(save.text)
			if err != nil {
				return nil, err
			}
			return p.parseOfTail(quantN, n)
		}
		// Otherwise it is the left side of a comparison.
		left := Value(valNum{mustNumber(save.text)})
		return p.parseComparisonTail(left)
	}

	// `$a` and `$a at N`.
	if p.tok.kind == tPunct && p.tok.text == "$" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		id := "$"
		if isNameTok(p.tok) {
			id += p.tok.text
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
		if p.tok.kind == tOp && p.tok.text == "at" {
			if err := p.advance(false); err != nil {
				return nil, err
			}
			off, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			return nodeStrAt{id: id, off: off}, nil
		}
		if p.tok.kind == tOp && p.tok.text == "in" {
			return nil, lx.errf("`$x in (a..b)` is not supported")
		}
		return nodeStr{id}, nil
	}

	// A bare identifier that is not a value keyword is a reference to another
	// rule, e.g. `is_php and ...` — unless it is the near() builtin.
	if p.tok.kind == tIdent && !isValueKeyword(p.tok.text) {
		name := p.tok.text
		if err := p.advance(false); err != nil {
			return nil, err
		}
		if name == "near" && p.tok.kind == tPunct && p.tok.text == "(" {
			return p.parseNear()
		}
		// Reject module accesses (pe.foo) explicitly rather than treating
		// "pe" as a rule name that will never resolve.
		if p.tok.kind == tPunct && p.tok.text == "." {
			return nil, lx.errf("module %q is not supported", name)
		}
		return nodeRuleRef{name}, nil
	}

	// Anything else is a numeric expression, optionally compared.
	left, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	return p.parseComparisonTail(left)
}

func (p *parser) parseComparisonTail(left Value) (Node, error) {
	if p.tok.kind == tPunct {
		switch p.tok.text {
		case "==", "!=", "<", ">", "<=", ">=":
			op := p.tok.text
			if err := p.advance(false); err != nil {
				return nil, err
			}
			right, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			return nodeCmp{op: op, l: left, r: right}, nil
		}
	}
	// A bare value is true when non-zero (YARA semantics for `#a`).
	return nodeCmp{op: "!=", l: left, r: valNum{0}}, nil
}

func (p *parser) parseOf() (Node, error) {
	var q quant
	switch p.tok.text {
	case "any":
		q = quantAny
	case "all":
		q = quantAll
	case "none":
		q = quantNone
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if p.tok.kind != tOp || p.tok.text != "of" {
		return nil, p.lx.errf("expected 'of' after quantifier")
	}
	return p.parseOfTail(q, 0)
}

// parseOfTail consumes `of them` or `of ($a, $b*)`.
func (p *parser) parseOfTail(q quant, n int64) (Node, error) {
	if err := p.advance(false); err != nil { // consume 'of'
		return nil, err
	}
	if p.tok.kind == tOp && p.tok.text == "them" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		return nodeOf{q: q, n: n}, nil
	}
	if p.tok.kind != tPunct || p.tok.text != "(" {
		return nil, p.lx.errf("expected 'them' or '(' after 'of'")
	}
	ids, err := p.parseStringSet("'of' list")
	if err != nil {
		return nil, err
	}
	return nodeOf{q: q, n: n, ids: ids}, nil
}

// parseStringSet consumes `($a, $b*)`, leaving the cursor after the ')'. The
// caller must have verified the current token is '('.
func (p *parser) parseStringSet(what string) ([]string, error) {
	if err := p.advance(false); err != nil {
		return nil, err
	}
	var ids []string
	for {
		if p.tok.kind != tPunct || p.tok.text != "$" {
			return nil, p.lx.errf("expected string identifier in %s", what)
		}
		if err := p.advance(false); err != nil {
			return nil, err
		}
		id := "$"
		if isNameTok(p.tok) {
			id += p.tok.text
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
		if p.tok.kind == tPunct && p.tok.text == "*" {
			id += "*"
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
		ids = append(ids, id)
		if p.tok.kind == tPunct && p.tok.text == "," {
			if err := p.advance(false); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	if p.tok.kind != tPunct || p.tok.text != ")" {
		return nil, p.lx.errf("expected ')' closing %s", what)
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	return ids, nil
}

// parseNear consumes `near(<set>, <set>, N)`. The cursor is on '(' .
func (p *parser) parseNear() (Node, error) {
	if err := p.advance(false); err != nil { // consume '('
		return nil, err
	}
	if p.tok.kind != tPunct || p.tok.text != "(" {
		return nil, p.lx.errf("near() expects a string set as its first argument")
	}
	a, err := p.parseStringSet("near() first argument")
	if err != nil {
		return nil, err
	}
	if p.tok.kind != tPunct || p.tok.text != "," {
		return nil, p.lx.errf("near() expects three arguments")
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if p.tok.kind != tPunct || p.tok.text != "(" {
		return nil, p.lx.errf("near() expects a string set as its second argument")
	}
	b, err := p.parseStringSet("near() second argument")
	if err != nil {
		return nil, err
	}
	if p.tok.kind != tPunct || p.tok.text != "," {
		return nil, p.lx.errf("near() expects a distance as its third argument")
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if p.tok.kind != tNumber {
		return nil, p.lx.errf("near() distance must be a number")
	}
	dist, err := parseNumber(p.tok.text)
	if err != nil {
		return nil, err
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if p.tok.kind != tPunct || p.tok.text != ")" {
		return nil, p.lx.errf("expected ')' closing near()")
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	return nodeNear{a: a, b: b, dist: dist}, nil
}

func (p *parser) parseValue() (Value, error) {
	lx := p.lx
	switch {
	case p.tok.kind == tNumber:
		n, err := parseNumber(p.tok.text)
		if err != nil {
			return nil, err
		}
		if err := p.advance(false); err != nil {
			return nil, err
		}
		return valNum{n}, nil

	case p.tok.kind == tPunct && p.tok.text == "#":
		if err := p.advance(false); err != nil {
			return nil, err
		}
		id := "$"
		if isNameTok(p.tok) {
			id += p.tok.text
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
		return valCount{id}, nil

	case p.tok.kind == tPunct && p.tok.text == "@":
		if err := p.advance(false); err != nil {
			return nil, err
		}
		id := "$"
		if isNameTok(p.tok) {
			id += p.tok.text
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
		return valOffset{id}, nil

	case p.tok.kind == tIdent && p.tok.text == "filesize":
		if err := p.advance(false); err != nil {
			return nil, err
		}
		return valFilesize{}, nil

	case p.tok.kind == tIdent && strings.HasPrefix(p.tok.text, "uint"),
		p.tok.kind == tIdent && strings.HasPrefix(p.tok.text, "int"):
		name := p.tok.text
		width := 8
		switch {
		case strings.HasSuffix(name, "8"):
			width = 8
		case strings.HasSuffix(name, "16"):
			width = 16
		case strings.HasSuffix(name, "32"):
			width = 32
		default:
			return nil, lx.errf("unsupported integer function %q", name)
		}
		if err := p.advance(false); err != nil {
			return nil, err
		}
		if p.tok.kind != tPunct || p.tok.text != "(" {
			return nil, lx.errf("expected '(' after %s", name)
		}
		if err := p.advance(false); err != nil {
			return nil, err
		}
		off, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		if p.tok.kind != tPunct || p.tok.text != ")" {
			return nil, lx.errf("expected ')' after %s offset", name)
		}
		if err := p.advance(false); err != nil {
			return nil, err
		}
		return valUint{width: width, off: off}, nil

	case p.tok.kind == tIdent:
		// A bare identifier here is a module reference (pe.*, math.*), which
		// this subset does not implement.
		return nil, lx.errf("unsupported identifier %q (modules are not supported)", p.tok.text)
	}
	return nil, lx.errf("unexpected token %q in expression", p.tok.text)
}

func parseNumber(s string) (int64, error) {
	mult := int64(1)
	up := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(up, "KB"):
		mult, s = 1024, s[:len(s)-2]
	case strings.HasSuffix(up, "MB"):
		mult, s = 1024*1024, s[:len(s)-2]
	case strings.HasSuffix(up, "GB"):
		mult, s = 1024*1024*1024, s[:len(s)-2]
	}
	var n int64
	var err error
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		var u uint64
		u, err = strconv.ParseUint(s[2:], 16, 64)
		n = int64(u)
	} else {
		n, err = strconv.ParseInt(s, 10, 64)
	}
	if err != nil {
		return 0, fmt.Errorf("bad number %q", s)
	}
	return n * mult, nil
}

func mustNumber(s string) int64 {
	n, _ := parseNumber(s)
	return n
}

// isValueKeyword reports whether an identifier introduces a numeric value
// rather than naming another rule.
func isValueKeyword(s string) bool {
	if s == "filesize" || s == "entrypoint" {
		return true
	}
	return strings.HasPrefix(s, "uint") || strings.HasPrefix(s, "int")
}
