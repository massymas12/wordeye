package store

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// A small query language for findings.
//
// An estate of 236 hosts produces more findings than any flat list can serve,
// and `LIKE '%term%'` over four columns is not triage. This compiles a
// field-scoped expression into SQL:
//
//	severity:critical AND path:uploads
//	rule:yara.* AND NOT state:dismissed
//	meta.score:>20
//	sha256:76146007 OR path:*.php.js
//
// SQL INJECTION IS THE WHOLE RISK HERE
//
// This turns operator-supplied text into a WHERE clause, which is the single
// most dangerous shape a feature can have. Three rules make it safe, and all
// three are structural rather than filtering:
//
//  1. Every VALUE becomes a bound placeholder. No value is ever concatenated
//     into SQL, so no amount of quoting games in the input can reach the parser.
//  2. Every FIELD is resolved through a fixed allowlist to a hard-coded column
//     expression. An unknown field is an error, not a passthrough — so a field
//     name cannot smuggle SQL either.
//  3. meta.<key> paths are validated against a strict character class AND
//     passed to json_extract as a BOUND PARAMETER, never spliced into the
//     query text.
//
// There is deliberately no escape hatch for raw SQL. If a query cannot be
// expressed here it should be added to the grammar, not tunnelled through it.

// queryField maps an allowlisted name to the SQL expression it searches.
// Values are hard-coded; nothing from user input reaches this map's values.
var queryField = map[string]string{
	"severity":   "f.severity",
	"rule":       "f.rule_id",
	"class":      "f.class",
	"confidence": "f.confidence",
	"state":      "f.state",
	"path":       "f.path",
	"sha256":     "f.sha256",
	"title":      "f.title",
	"detail":     "f.detail",
	"evidence":   "f.evidence",
	"agent":      "f.agent_id",
	// host is the MACHINE, not the installer batch. This previously resolved to
	// the label when one was set, which on an estate enrolled from a single
	// installer meant every host carried the same value and `host:` could not
	// narrow anything. The label remains searchable under its own name.
	"host":    "a.hostname",
	"label":   "a.label",
	"site":    "a.site",
	"webroot": "a.webroot",
	"estate":  "a.estate_id",
	"line":    "f.line",
	"size":    "f.size",
	"seen":    "f.seen_count",
}

// metaKeyRe bounds what may appear in a meta.<key> path. Anything outside this
// is rejected rather than escaped: the set of legitimate keys is small and
// well-behaved, so there is no reason to accept exotic input and hope.
var metaKeyRe = regexp.MustCompile(`^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$`)

// maxQueryTerms bounds how much work one query may demand. A deeply nested
// expression is not a legitimate triage query, and an unbounded one is a way to
// make the console do arbitrary work on a single writer.
const maxQueryTerms = 40

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------

type tokKind int

const (
	tokTerm tokKind = iota
	tokAnd
	tokOr
	tokNot
	tokLParen
	tokRParen
)

type token struct {
	kind tokKind
	text string
}

// lexQuery splits the input, honouring double quotes so a value may contain
// spaces or a colon.
func lexQuery(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(':
			out = append(out, token{kind: tokLParen})
			i++
		case c == ')':
			out = append(out, token{kind: tokRParen})
			i++
		default:
			start := i
			var b strings.Builder
			inQuote := false
			for i < len(s) {
				ch := s[i]
				if ch == '"' {
					inQuote = !inQuote
					i++
					continue
				}
				if !inQuote && (ch == ' ' || ch == '\t' || ch == '(' || ch == ')') {
					break
				}
				b.WriteByte(ch)
				i++
			}
			word := b.String()
			if word == "" && i == start {
				i++
				continue
			}
			switch strings.ToUpper(word) {
			case "AND":
				out = append(out, token{kind: tokAnd})
			case "OR":
				out = append(out, token{kind: tokOr})
			case "NOT", "-":
				out = append(out, token{kind: tokNot})
			default:
				out = append(out, token{kind: tokTerm, text: word})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

type qparser struct {
	toks  []token
	pos   int
	terms int
}

func (p *qparser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{}, false
}

// parseOr handles the lowest-precedence operator.
func (p *qparser) parseOr() (string, []any, error) {
	sql, args, err := p.parseAnd()
	if err != nil {
		return "", nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			return sql, args, nil
		}
		p.pos++
		rs, ra, err := p.parseAnd()
		if err != nil {
			return "", nil, err
		}
		sql = "(" + sql + " OR " + rs + ")"
		args = append(args, ra...)
	}
}

// parseAnd treats adjacency as AND, so `severity:critical path:uploads` works
// without the operator — that is how people actually type search queries.
func (p *qparser) parseAnd() (string, []any, error) {
	sql, args, err := p.parseUnary()
	if err != nil {
		return "", nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind == tokOr || t.kind == tokRParen {
			return sql, args, nil
		}
		if t.kind == tokAnd {
			p.pos++
			if _, ok := p.peek(); !ok {
				return "", nil, fmt.Errorf("query ends after AND")
			}
		}
		rs, ra, err := p.parseUnary()
		if err != nil {
			return "", nil, err
		}
		sql = "(" + sql + " AND " + rs + ")"
		args = append(args, ra...)
	}
}

func (p *qparser) parseUnary() (string, []any, error) {
	t, ok := p.peek()
	if !ok {
		return "", nil, fmt.Errorf("unexpected end of query")
	}
	switch t.kind {
	case tokNot:
		p.pos++
		sql, args, err := p.parseUnary()
		if err != nil {
			return "", nil, err
		}
		return "(NOT " + sql + ")", args, nil
	case tokLParen:
		p.pos++
		sql, args, err := p.parseOr()
		if err != nil {
			return "", nil, err
		}
		nt, ok := p.peek()
		if !ok || nt.kind != tokRParen {
			return "", nil, fmt.Errorf("unbalanced parenthesis")
		}
		p.pos++
		return "(" + sql + ")", args, nil
	case tokTerm:
		p.pos++
		p.terms++
		if p.terms > maxQueryTerms {
			return "", nil, fmt.Errorf("query has too many terms (limit %d)", maxQueryTerms)
		}
		return compileTerm(t.text)
	default:
		return "", nil, fmt.Errorf("unexpected operator in query")
	}
}

// compileTerm turns one `field:value`, `field:>value` or bare word into SQL.
func compileTerm(raw string) (string, []any, error) {
	field, value, hasField := strings.Cut(raw, ":")
	if !hasField || field == "" {
		// A bare word searches the columns an analyst actually scans.
		like := "%" + likeEscape(raw) + "%"
		return `(f.path LIKE ? ESCAPE '\' OR f.title LIKE ? ESCAPE '\' OR ` +
				`f.rule_id LIKE ? ESCAPE '\' OR f.sha256 LIKE ? ESCAPE '\')`,
			[]any{like, like, like, like}, nil
	}
	field = strings.ToLower(field)

	// meta.<key> reads the finding's free-form metadata. The JSON path is bound
	// as a parameter, so even a validated key never becomes query text.
	if strings.HasPrefix(field, "meta.") {
		key := strings.TrimPrefix(field, "meta.")
		if !metaKeyRe.MatchString(key) {
			return "", nil, fmt.Errorf("invalid meta key %q", key)
		}
		return compileComparison("json_extract(f.meta, ?)", value, []any{"$." + key})
	}

	col, ok := queryField[field]
	if !ok {
		return "", nil, fmt.Errorf("unknown field %q", field)
	}
	return compileComparison(col, value, nil)
}

// compileComparison builds the operator half of a term. col is a hard-coded
// expression from the allowlist; value is always bound.
func compileComparison(col, value string, lead []any) (string, []any, error) {
	if value == "" {
		return "", nil, fmt.Errorf("missing value")
	}
	args := append([]any{}, lead...)

	// Numeric comparisons. CAST keeps this meaningful for json_extract, which
	// returns text for values pulled out of a JSON document.
	for _, op := range []struct{ prefix, sqlOp string }{
		{">=", ">="}, {"<=", "<="}, {">", ">"}, {"<", "<"},
	} {
		if strings.HasPrefix(value, op.prefix) {
			num := strings.TrimPrefix(value, op.prefix)
			n, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return "", nil, fmt.Errorf("%q is not a number", num)
			}
			return "(CAST(" + col + " AS REAL) " + op.sqlOp + " ?)", append(args, n), nil
		}
	}

	// Glob: * becomes a LIKE wildcard, everything else is matched literally.
	if strings.Contains(value, "*") {
		var b strings.Builder
		for _, r := range value {
			if r == '*' {
				b.WriteByte('%')
				continue
			}
			b.WriteString(likeEscape(string(r)))
		}
		return "(" + col + " LIKE ? ESCAPE '\\')", append(args, b.String()), nil
	}

	// Substring match by default: an analyst typing path:uploads means
	// "somewhere under uploads", not an exact path.
	return "(" + col + " LIKE ? ESCAPE '\\')",
		append(args, "%"+likeEscape(value)+"%"), nil
}

// CompileQuery turns a query string into a SQL fragment and its bound
// arguments. An empty query matches everything.
func CompileQuery(q string) (string, []any, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", nil, nil
	}
	if len(q) > 2000 {
		return "", nil, fmt.Errorf("query is too long")
	}
	toks := lexQuery(q)
	if len(toks) == 0 {
		return "", nil, nil
	}
	p := &qparser{toks: toks}
	sql, args, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	if p.pos != len(p.toks) {
		return "", nil, fmt.Errorf("unexpected trailing input in query")
	}
	return sql, args, nil
}

// QueryFields lists the searchable field names, for the UI's help text.
func QueryFields() []string {
	out := make([]string, 0, len(queryField)+1)
	for k := range queryField {
		out = append(out, k)
	}
	out = append(out, "meta.<key>")
	return out
}
