// Package yara implements the subset of the YARA language that PHP/WordPress
// web-shell rulesets actually use.
//
// The obvious alternative — cgo bindings to libyara — was rejected on purpose.
// It would make the agent dynamically linked against a shared library that is
// not present on a managed WordPress host, which destroys the property the
// whole design rests on: one static file to scp, no dependencies, nothing
// installed. A native subset keeps CGO_ENABLED=0.
//
// Supported:
//
//	rule NAME : tag1 tag2 {
//	  meta:      key = "value" | 123 | true
//	  strings:   $a = "text" nocase wide ascii fullword
//	             $b = { 4D 5A ?? ?9 [2-6] 90 }
//	             $c = /regex/is
//	  condition: any of them | all of them | 2 of ($a*) | $a and not $b
//	             | #a > 3 | $a at 0 | filesize < 200KB | uint8(0) == 0x3C
//	}
//
// Not supported: modules (pe, elf, math, hash), external variables, `for..of`
// iteration, string offsets in arithmetic. Rules using them are rejected at
// load time with a clear error rather than silently never matching — a rule
// that cannot fire must never look like a rule that found nothing.
package yara

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// lexer
// ---------------------------------------------------------------------------

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString // "..."
	tRegex  // /.../ with modifiers
	tHex    // { ... }
	tNumber
	tPunct // { } ( ) : = , $ # @ ! < > + - * . [ ]
	tOp    // and or not of them all any at in matches contains
)

type token struct {
	kind tokKind
	text string
	mods string // regex modifiers
	line int
}

type lexer struct {
	src  string
	pos  int
	line int
}

func (l *lexer) errf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", l.line, fmt.Sprintf(format, args...))
}

func (l *lexer) peekByte() byte {
	if l.pos < len(l.src) {
		return l.src[l.pos]
	}
	return 0
}

func (l *lexer) skipSpaceAndComments() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			l.pos += 2
			for l.pos+1 < len(l.src) && !(l.src[l.pos] == '*' && l.src[l.pos+1] == '/') {
				if l.src[l.pos] == '\n' {
					l.line++
				}
				l.pos++
			}
			l.pos += 2
		default:
			return
		}
	}
}

// regexAllowed tells the lexer whether a '/' starts a regex literal or is a
// division operator. YARA has no division in the conditions we support, so a
// '/' after '=' is always a regex.
func (l *lexer) next(regexAllowed bool) (token, error) {
	l.skipSpaceAndComments()
	if l.pos >= len(l.src) {
		return token{kind: tEOF, line: l.line}, nil
	}
	start := l.line
	c := l.src[l.pos]

	switch {
	case c == '"':
		l.pos++
		var sb strings.Builder
		for l.pos < len(l.src) {
			ch := l.src[l.pos]
			if ch == '\\' && l.pos+1 < len(l.src) {
				esc := l.src[l.pos+1]
				l.pos += 2
				switch esc {
				case 'n':
					sb.WriteByte('\n')
				case 'r':
					sb.WriteByte('\r')
				case 't':
					sb.WriteByte('\t')
				case '\\':
					sb.WriteByte('\\')
				case '"':
					sb.WriteByte('"')
				case 'x':
					if l.pos+1 < len(l.src) {
						v, err := strconv.ParseUint(l.src[l.pos:l.pos+2], 16, 8)
						if err != nil {
							return token{}, l.errf("bad \\x escape")
						}
						sb.WriteByte(byte(v))
						l.pos += 2
					}
				default:
					sb.WriteByte(esc)
				}
				continue
			}
			if ch == '"' {
				l.pos++
				return token{kind: tString, text: sb.String(), line: start}, nil
			}
			if ch == '\n' {
				return token{}, l.errf("unterminated string")
			}
			sb.WriteByte(ch)
			l.pos++
		}
		return token{}, l.errf("unterminated string")

	case c == '/' && regexAllowed:
		l.pos++
		var sb strings.Builder
		for l.pos < len(l.src) {
			ch := l.src[l.pos]
			if ch == '\\' && l.pos+1 < len(l.src) {
				sb.WriteByte(ch)
				sb.WriteByte(l.src[l.pos+1])
				l.pos += 2
				continue
			}
			if ch == '/' {
				l.pos++
				mods := ""
				for l.pos < len(l.src) && (l.src[l.pos] == 'i' || l.src[l.pos] == 's' ||
					l.src[l.pos] == 'g' || l.src[l.pos] == 'm') {
					mods += string(l.src[l.pos])
					l.pos++
				}
				return token{kind: tRegex, text: sb.String(), mods: mods, line: start}, nil
			}
			if ch == '\n' {
				return token{}, l.errf("unterminated regex")
			}
			sb.WriteByte(ch)
			l.pos++
		}
		return token{}, l.errf("unterminated regex")

	case c == '{':
		// In a strings: section this is a hex pattern; the parser decides.
		depth := 0
		p := l.pos
		for p < len(l.src) {
			if l.src[p] == '{' {
				depth++
			} else if l.src[p] == '}' {
				depth--
				if depth == 0 {
					break
				}
			} else if l.src[p] == '\n' {
				l.line++
			}
			p++
		}
		if p >= len(l.src) {
			return token{}, l.errf("unterminated block")
		}
		body := l.src[l.pos+1 : p]
		l.pos = p + 1
		return token{kind: tHex, text: body, line: start}, nil

	case isIdentStart(c):
		p := l.pos
		for p < len(l.src) && isIdentChar(l.src[p]) {
			p++
		}
		word := l.src[l.pos:p]
		l.pos = p
		switch word {
		case "and", "or", "not", "of", "them", "all", "any", "at", "in",
			"matches", "contains", "true", "false", "none":
			return token{kind: tOp, text: word, line: start}, nil
		}
		return token{kind: tIdent, text: word, line: start}, nil

	case unicode.IsDigit(rune(c)):
		p := l.pos
		if c == '0' && p+1 < len(l.src) && (l.src[p+1] == 'x' || l.src[p+1] == 'X') {
			p += 2
			for p < len(l.src) && isHexDigit(l.src[p]) {
				p++
			}
		} else {
			for p < len(l.src) && unicode.IsDigit(rune(l.src[p])) {
				p++
			}
		}
		num := l.src[l.pos:p]
		l.pos = p
		// Size suffixes.
		for _, suf := range []string{"KB", "MB", "GB"} {
			if strings.HasPrefix(strings.ToUpper(l.src[l.pos:min(l.pos+2, len(l.src))]), suf) {
				num += suf
				l.pos += 2
				break
			}
		}
		return token{kind: tNumber, text: num, line: start}, nil

	default:
		// Multi-byte operators first.
		for _, op := range []string{"==", "!=", "<=", ">="} {
			if strings.HasPrefix(l.src[l.pos:], op) {
				l.pos += 2
				return token{kind: tPunct, text: op, line: start}, nil
			}
		}
		l.pos++
		return token{kind: tPunct, text: string(c), line: start}, nil
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isIdentChar(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// parser
// ---------------------------------------------------------------------------

type parser struct {
	lx   *lexer
	tok  token
	peek *token
}

func (p *parser) advance(regexAllowed bool) error {
	if p.peek != nil {
		p.tok = *p.peek
		p.peek = nil
		return nil
	}
	t, err := p.lx.next(regexAllowed)
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *parser) expectPunct(s string) error {
	if p.tok.kind != tPunct || p.tok.text != s {
		return p.lx.errf("expected %q, got %q", s, p.tok.text)
	}
	return p.advance(false)
}

// Parse compiles a .yar source file into rules.
func Parse(src, origin string) ([]*Rule, error) {
	lx := &lexer{src: src, line: 1}
	p := &parser{lx: lx}
	if err := p.advance(false); err != nil {
		return nil, fmt.Errorf("%s: %w", origin, err)
	}

	var out []*Rule
	for p.tok.kind != tEOF {
		// Skip imports and includes: we support no modules, and silently
		// ignoring an import is better than refusing an otherwise usable file.
		if p.tok.kind == tIdent && (p.tok.text == "import" || p.tok.text == "include") {
			if err := p.advance(false); err != nil {
				return nil, err
			}
			if err := p.advance(false); err != nil {
				return nil, err
			}
			continue
		}
		private, global := false, false
		for p.tok.kind == tIdent && (p.tok.text == "private" || p.tok.text == "global") {
			if p.tok.text == "private" {
				private = true
			} else {
				global = true
			}
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
		if p.tok.kind != tIdent || p.tok.text != "rule" {
			return nil, lx.errf("expected 'rule', got %q", p.tok.text)
		}
		r, err := p.parseRule()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", origin, err)
		}
		r.Private = private
		r.Global = global
		r.Origin = origin
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no rules found", origin)
	}
	return out, nil
}

func (p *parser) parseRule() (*Rule, error) {
	if err := p.advance(false); err != nil { // consume 'rule'
		return nil, err
	}
	if p.tok.kind != tIdent {
		return nil, p.lx.errf("expected rule name")
	}
	r := &Rule{Name: p.tok.text, Meta: map[string]string{}}
	if err := p.advance(false); err != nil {
		return nil, err
	}

	if p.tok.kind == tPunct && p.tok.text == ":" {
		if err := p.advance(false); err != nil {
			return nil, err
		}
		for p.tok.kind == tIdent {
			r.Tags = append(r.Tags, p.tok.text)
			if err := p.advance(false); err != nil {
				return nil, err
			}
		}
	}

	// The rule body arrives as a single tHex-style block token because the
	// lexer captures balanced braces; re-lex its contents.
	if p.tok.kind != tHex {
		return nil, p.lx.errf("expected rule body for %s", r.Name)
	}
	body := p.tok.text
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if err := parseBody(body, r); err != nil {
		return nil, fmt.Errorf("rule %s: %w", r.Name, err)
	}
	return r, nil
}

// parseBody handles the meta/strings/condition sections.
func parseBody(body string, r *Rule) error {
	lx := &lexer{src: body, line: 1}
	p := &parser{lx: lx}
	if err := p.advance(false); err != nil {
		return err
	}

	section := ""
	for p.tok.kind != tEOF {
		if p.tok.kind == tIdent && (p.tok.text == "meta" || p.tok.text == "strings" || p.tok.text == "condition") {
			section = p.tok.text
			if err := p.advance(false); err != nil {
				return err
			}
			if err := p.expectPunct(":"); err != nil {
				return err
			}
			if section == "condition" {
				node, err := p.parseCondition()
				if err != nil {
					return err
				}
				r.Cond = node
				continue
			}
			continue
		}

		switch section {
		case "meta":
			if p.tok.kind != tIdent {
				return lx.errf("expected meta key, got %q", p.tok.text)
			}
			key := p.tok.text
			if err := p.advance(false); err != nil {
				return err
			}
			if err := p.expectPunct("="); err != nil {
				return err
			}
			r.Meta[key] = p.tok.text
			if err := p.advance(false); err != nil {
				return err
			}

		case "strings":
			if p.tok.kind != tPunct || p.tok.text != "$" {
				return lx.errf("expected string identifier, got %q", p.tok.text)
			}
			if err := p.advance(false); err != nil {
				return err
			}
			id := "$"
			if isNameTok(p.tok) {
				id += p.tok.text
				if err := p.advance(false); err != nil {
					return err
				}
			}
			if p.tok.kind != tPunct || p.tok.text != "=" {
				return lx.errf("expected '=' after %s", id)
			}
			// Advance with regex mode ON: a '/' immediately after '=' always
			// opens a regex literal, never division.
			if err := p.advance(true); err != nil {
				return err
			}

			sd := StringDef{ID: id}
			switch p.tok.kind {
			case tString:
				sd.Kind = KindText
				sd.Text = p.tok.text
			case tHex:
				sd.Kind = KindHex
				sd.Text = p.tok.text
			case tRegex:
				sd.Kind = KindRegex
				sd.Text = p.tok.text
				sd.Mods = p.tok.mods
			default:
				return lx.errf("unsupported string value for %s", id)
			}
			if err := p.advance(false); err != nil {
				return err
			}

			// Trailing modifiers, if any.
			for p.tok.kind == tIdent {
				done := false
				switch strings.ToLower(p.tok.text) {
				case "nocase":
					sd.NoCase = true
				case "wide":
					sd.Wide = true
				case "ascii":
					sd.ASCII = true
				case "fullword":
					sd.FullWord = true
				case "private":
					// irrelevant to matching
				case "xor", "base64", "base64wide":
					// Refuse rather than accept-and-never-match: a rule that
					// silently cannot fire is worse than one that fails loudly.
					return lx.errf("string modifier %q is not supported", p.tok.text)
				default:
					done = true
				}
				if done {
					break
				}
				if err := p.advance(false); err != nil {
					return err
				}
			}
			// YARA's default is ascii; `wide` alone means wide-only.
			if !sd.Wide {
				sd.ASCII = true
			}
			r.Strings = append(r.Strings, sd)

		default:
			return lx.errf("unexpected token %q outside a section", p.tok.text)
		}
	}
	if r.Cond == nil {
		return fmt.Errorf("no condition")
	}
	return nil
}

// advanceStringValue moves past a string value, re-lexing with regex enabled so
// `$a = /foo/i` is handled.
func (p *parser) advanceStringValue() error {
	return p.advance(true)
}

// isNameTok reports whether a token can serve as a string identifier.
//
// YARA string names are free-form, so `$in`, `$all` and `$at` are perfectly
// legal even though those words are operators elsewhere in the grammar. The
// lexer cannot know the difference, so the parser accepts operator tokens in
// name position. Third-party rulesets rely on this constantly.
func isNameTok(t token) bool {
	return t.kind == tIdent || t.kind == tNumber || t.kind == tOp
}
