package yara

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Compilation and evaluation.
//
// Text and hex patterns are matched byte-exactly with hand-rolled scanners
// rather than through regexp. Go's regexp engine is rune-oriented: a pattern
// containing \xFF matches the rune U+00FF, which is two bytes in UTF-8, so
// binary patterns would silently fail to match. Only genuine /regex/ strings go
// through regexp, where that behaviour is expected.

type hexElem struct {
	isJump   bool
	min, max int
	val      byte
	mask     byte // 0xFF exact, 0x00 full wildcard, 0xF0/0x0F nibble
}

type matcher struct {
	id       string
	kind     StringKind
	pats     [][]byte // text: ascii and/or wide encodings
	nocase   bool
	fullword bool
	hex      []hexElem
	re       *regexp.Regexp
}

// Compile prepares rules for scanning. Rules that use unsupported features are
// returned as errors rather than being silently dropped.
func Compile(rules []*Rule) (*Set, error) {
	s := &Set{}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		if err := compileRule(r); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		analyzePrefilter(r)
		s.Rules = append(s.Rules, r)
	}
	return s, nil
}

func compileRule(r *Rule) error {
	for _, sd := range r.Strings {
		m := &matcher{id: sd.ID, kind: sd.Kind, nocase: sd.NoCase, fullword: sd.FullWord}
		switch sd.Kind {
		case KindText:
			if sd.ASCII {
				m.pats = append(m.pats, []byte(sd.Text))
			}
			if sd.Wide {
				m.pats = append(m.pats, toWide(sd.Text))
			}
			if len(m.pats) == 0 {
				return fmt.Errorf("%s has no encoding", sd.ID)
			}
		case KindHex:
			elems, err := parseHex(sd.Text)
			if err != nil {
				return fmt.Errorf("%s: %w", sd.ID, err)
			}
			m.hex = elems
		case KindRegex:
			pat := sd.Text
			var flags string
			if strings.Contains(sd.Mods, "i") || sd.NoCase {
				flags += "i"
			}
			if strings.Contains(sd.Mods, "s") {
				flags += "s"
			}
			if flags != "" {
				pat = "(?" + flags + ")" + pat
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return fmt.Errorf("%s: %w", sd.ID, err)
			}
			m.re = re
		}
		r.matchers = append(r.matchers, m)
	}
	return nil
}

// toWide produces the UTF-16LE form YARA's `wide` modifier looks for.
func toWide(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

// analyzePrefilter decides whether a rule can be skipped when none of its
// literal strings appear in a file.
//
// Conservative on purpose: a wrong "yes" here would make a rule silently unable
// to fire, which is the failure mode this whole design exists to avoid.
func analyzePrefilter(r *Rule) {
	r.prefilterable = true
	for _, sd := range r.Strings {
		if sd.Kind != KindText || !sd.ASCII {
			// Hex, regex, and wide-only strings are invisible to an ASCII
			// literal prefilter.
			r.prefilterable = false
		} else {
			r.literals = append(r.literals, sd.Text)
		}
	}
	if len(r.Strings) == 0 {
		r.prefilterable = false
	}
	// A rule is only safe to skip when its condition CANNOT be true unless at
	// least one of its own strings matched. Anything else — a negation, a
	// filesize-only clause, a reference to another rule in an OR branch — means
	// the rule could fire against a file containing none of its literals.
	if r.prefilterable && !requiresSomeString(r.Cond) {
		r.prefilterable = false
	}
}

// requiresSomeString reports whether every satisfying assignment of the
// condition involves at least one of this rule's strings matching.
//
// Deliberately conservative: returning true wrongly would let the prefilter
// skip a rule that could have matched, which is a silent false negative — the
// exact failure this codebase is built to avoid.
func requiresSomeString(n Node) bool {
	switch t := n.(type) {
	case nodeStr, nodeStrAt:
		return true
	case nodeNear:
		// near() is false unless a string from each side matched.
		return true
	case nodeOf:
		// `any/all/N of ...` requires a match; `none of ...` does not.
		return t.q != quantNone && !(t.q == quantN && t.n <= 0)
	case nodeAnd:
		// One conjunct demanding a string is enough for the whole AND.
		return requiresSomeString(t.l) || requiresSomeString(t.r)
	case nodeOr:
		// Both branches must demand one, or the other branch could match alone.
		return requiresSomeString(t.l) && requiresSomeString(t.r)
	}
	// not / comparisons / rule references / literals: cannot guarantee it.
	return false
}

// parseHex converts `4D 5A ?? ?9 [2-6] 90` into elements.
func parseHex(s string) ([]hexElem, error) {
	var out []hexElem
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, fmt.Errorf("unterminated jump")
			}
			body := s[i+1 : i+j]
			i += j + 1
			e := hexElem{isJump: true}
			if k := strings.IndexByte(body, '-'); k >= 0 {
				lo, err1 := strconv.Atoi(strings.TrimSpace(body[:k]))
				hiStr := strings.TrimSpace(body[k+1:])
				hi := 256
				var err2 error
				if hiStr != "" {
					hi, err2 = strconv.Atoi(hiStr)
				}
				if err1 != nil || err2 != nil {
					return nil, fmt.Errorf("bad jump [%s]", body)
				}
				e.min, e.max = lo, hi
			} else {
				n, err := strconv.Atoi(strings.TrimSpace(body))
				if err != nil {
					return nil, fmt.Errorf("bad jump [%s]", body)
				}
				e.min, e.max = n, n
			}
			out = append(out, e)
		case c == '(' || c == ')' || c == '|':
			return nil, fmt.Errorf("hex alternation is not supported")
		case isHexDigit(c) || c == '?':
			if i+1 >= len(s) {
				return nil, fmt.Errorf("odd hex nibble")
			}
			hi, lo := s[i], s[i+1]
			i += 2
			var e hexElem
			switch {
			case hi == '?' && lo == '?':
				e = hexElem{val: 0, mask: 0x00}
			case hi == '?':
				v, err := strconv.ParseUint(string(lo), 16, 8)
				if err != nil {
					return nil, err
				}
				e = hexElem{val: byte(v), mask: 0x0F}
			case lo == '?':
				v, err := strconv.ParseUint(string(hi), 16, 8)
				if err != nil {
					return nil, err
				}
				e = hexElem{val: byte(v) << 4, mask: 0xF0}
			default:
				v, err := strconv.ParseUint(string([]byte{hi, lo}), 16, 8)
				if err != nil {
					return nil, err
				}
				e = hexElem{val: byte(v), mask: 0xFF}
			}
			out = append(out, e)
		default:
			return nil, fmt.Errorf("unexpected character %q in hex string", string(c))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty hex string")
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// matching
// ---------------------------------------------------------------------------

func (m *matcher) findAll(data []byte, limit int) []int {
	switch m.kind {
	case KindText:
		return m.findText(data, limit)
	case KindHex:
		return m.findHex(data, limit)
	case KindRegex:
		var out []int
		for _, loc := range m.re.FindAllIndex(data, limit) {
			out = append(out, loc[0])
		}
		return out
	}
	return nil
}

func (m *matcher) findText(data []byte, limit int) []int {
	var out []int
	for _, pat := range m.pats {
		if len(pat) == 0 {
			continue
		}
		off := 0
		for len(out) < limit {
			var idx int
			if m.nocase {
				idx = indexFold(data[off:], pat)
			} else {
				idx = bytes.Index(data[off:], pat)
			}
			if idx < 0 {
				break
			}
			abs := off + idx
			if !m.fullword || isFullWord(data, abs, len(pat)) {
				out = append(out, abs)
			}
			off = abs + 1
		}
	}
	return out
}

// indexFold is a case-insensitive byte search. Deliberately byte-oriented:
// YARA's nocase is ASCII case folding, not Unicode.
func indexFold(data, pat []byte) int {
	n := len(pat)
	if n == 0 || len(data) < n {
		return -1
	}
	first := lowerB(pat[0])
	for i := 0; i+n <= len(data); i++ {
		if lowerB(data[i]) != first {
			continue
		}
		match := true
		for j := 1; j < n; j++ {
			if lowerB(data[i+j]) != lowerB(pat[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func lowerB(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isFullWord(data []byte, off, n int) bool {
	if off > 0 && isWordByte(data[off-1]) {
		return false
	}
	if off+n < len(data) && isWordByte(data[off+n]) {
		return false
	}
	return true
}

// maxHexSteps bounds the backtracking search for ONE scan of one string.
//
// Jump ranges multiply: a pattern with five [0-40] ranges explores up to 40^5
// paths per starting offset. Measured, that failed to finish in 30 seconds on a
// 20KB buffer. The agent runs on live customer web servers and the governor
// throttles IO, not CPU inside a match — so an imported third-party rule with
// several jumps could peg a core on someone's production site until the scan
// deadline fired. The budget converts that from an outage into a skipped rule.
const maxHexSteps = 2_000_000

func (m *matcher) findHex(data []byte, limit int) []int {
	var out []int
	budget := maxHexSteps
	for i := 0; i < len(data) && len(out) < limit; i++ {
		if hexMatchAt(m.hex, data, i, &budget) {
			out = append(out, i)
		}
		if budget <= 0 {
			// Exhausted. Returning what we have is the safe failure mode: a
			// possible missed match, never a hung scan on a customer's server.
			break
		}
	}
	return out
}

// hexMatchAt walks the element list, decrementing a shared step budget so a
// pathological pattern cannot run unbounded.
func hexMatchAt(elems []hexElem, data []byte, pos int, budget *int) bool {
	if *budget <= 0 {
		return false
	}
	*budget--
	if len(elems) == 0 {
		return true
	}
	e := elems[0]
	if e.isJump {
		maxJ := e.max
		if maxJ > len(data)-pos {
			maxJ = len(data) - pos
		}
		for j := e.min; j <= maxJ; j++ {
			if hexMatchAt(elems[1:], data, pos+j, budget) {
				return true
			}
			if *budget <= 0 {
				return false
			}
		}
		return false
	}
	if pos >= len(data) {
		return false
	}
	if data[pos]&e.mask != e.val&e.mask {
		return false
	}
	return hexMatchAt(elems[1:], data, pos+1, budget)
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------

// Set is a compiled ruleset.
type Set struct {
	Rules []*Rule
}

// Literals returns every plain-text string across the ruleset, so the caller
// can fold them into an existing prefilter automaton.
func (s *Set) Literals() []string {
	var out []string
	for _, r := range s.Rules {
		out = append(out, r.literals...)
	}
	return out
}

// Match is one rule firing against one file.
type Match struct {
	Rule    *Rule
	Strings []string
}

const maxMatchesPerString = 64

type evalCtx struct {
	data    []byte
	size    int64
	counts  map[string]int
	offsets map[string][]int
	ids     []string
	// results holds the outcome of previously evaluated rules, so a rule can
	// reference an earlier one by name.
	results map[string]bool
}

// Scan evaluates the ruleset against a buffer.
//
// gate is an optional prefilter: given a rule's literals, it reports whether
// any of them occur in the data. Rules flagged non-prefilterable are always
// evaluated regardless of what gate says.
func (s *Set) Scan(data []byte, filesize int64, gate func(literals []string) bool) []Match {
	var out []Match
	// Rules are evaluated in declaration order so that a reference to an
	// earlier rule (typically a private file-type guard) already has a result.
	results := make(map[string]bool, len(s.Rules))
	for _, r := range s.Rules {
		if r.prefilterable && gate != nil && !gate(r.literals) {
			results[r.Name] = false
			continue
		}
		ctx := &evalCtx{
			data: data, size: filesize,
			counts:  make(map[string]int, len(r.matchers)),
			offsets: make(map[string][]int, len(r.matchers)),
			results: results,
		}
		for _, m := range r.matchers {
			offs := m.findAll(data, maxMatchesPerString)
			ctx.counts[m.id] = len(offs)
			ctx.offsets[m.id] = offs
			ctx.ids = append(ctx.ids, m.id)
		}
		matched := evalNode(r.Cond, ctx)
		results[r.Name] = matched
		if !matched || r.Private {
			// Private rules exist to be referenced, never reported.
			continue
		}
		var hit []string
		for _, id := range ctx.ids {
			if ctx.counts[id] > 0 {
				hit = append(hit, id)
			}
		}
		out = append(out, Match{Rule: r, Strings: hit})
	}
	return out
}

func evalNode(n Node, c *evalCtx) bool {
	switch t := n.(type) {
	case nodeBool:
		return t.v
	case nodeAnd:
		return evalNode(t.l, c) && evalNode(t.r, c)
	case nodeOr:
		return evalNode(t.l, c) || evalNode(t.r, c)
	case nodeNot:
		return !evalNode(t.x, c)
	case nodeRuleRef:
		return c.results[t.name]
	case nodeStr:
		return c.counts[t.id] > 0
	case nodeStrAt:
		want := evalValue(t.off, c)
		for _, o := range c.offsets[t.id] {
			if int64(o) == want {
				return true
			}
		}
		return false
	case nodeOf:
		ids := t.ids
		if len(ids) == 0 {
			ids = c.ids
		} else {
			ids = expandWildcards(ids, c.ids)
		}
		matched := 0
		for _, id := range ids {
			if c.counts[id] > 0 {
				matched++
			}
		}
		switch t.q {
		case quantAny:
			return matched > 0
		case quantAll:
			return len(ids) > 0 && matched == len(ids)
		case quantNone:
			return matched == 0
		default:
			return int64(matched) >= t.n
		}
	case nodeNear:
		return evalNear(t, c)
	case nodeCmp:
		l, r := evalValue(t.l, c), evalValue(t.r, c)
		switch t.op {
		case "==":
			return l == r
		case "!=":
			return l != r
		case "<":
			return l < r
		case ">":
			return l > r
		case "<=":
			return l <= r
		case ">=":
			return l >= r
		}
	}
	return false
}

// evalNear implements near(). Both sides are merged into sorted offset lists
// and swept once, so cost is linear in the number of matches rather than the
// product of the two sides.
func evalNear(t nodeNear, c *evalCtx) bool {
	gather := func(pats []string) []int {
		var out []int
		for _, id := range expandWildcards(pats, c.ids) {
			out = append(out, c.offsets[id]...)
		}
		sort.Ints(out)
		return out
	}
	as, bs := gather(t.a), gather(t.b)
	if len(as) == 0 || len(bs) == 0 {
		return false
	}
	// Two-pointer sweep: for each offset on the left, advance the right cursor
	// to the first offset not before it, then test that one and its predecessor.
	j := 0
	for _, a := range as {
		for j < len(bs) && bs[j] < a {
			j++
		}
		if j < len(bs) && int64(bs[j]-a) <= t.dist {
			return true
		}
		if j > 0 && int64(a-bs[j-1]) <= t.dist {
			return true
		}
	}
	return false
}

func expandWildcards(pats, all []string) []string {
	var out []string
	for _, p := range pats {
		if !strings.HasSuffix(p, "*") {
			out = append(out, p)
			continue
		}
		prefix := strings.TrimSuffix(p, "*")
		for _, id := range all {
			if strings.HasPrefix(id, prefix) {
				out = append(out, id)
			}
		}
	}
	return out
}

func evalValue(v Value, c *evalCtx) int64 {
	switch t := v.(type) {
	case valNum:
		return t.n
	case valCount:
		return int64(c.counts[t.id])
	case valOffset:
		if offs := c.offsets[t.id]; len(offs) > 0 {
			return int64(offs[0])
		}
		return -1
	case valFilesize:
		return c.size
	case valUint:
		off := evalValue(t.off, c)
		if off < 0 {
			return 0
		}
		switch t.width {
		case 8:
			if int(off) < len(c.data) {
				return int64(c.data[off])
			}
		case 16:
			if int(off)+2 <= len(c.data) {
				return int64(binary.LittleEndian.Uint16(c.data[off : off+2]))
			}
		case 32:
			if int(off)+4 <= len(c.data) {
				return int64(binary.LittleEndian.Uint32(c.data[off : off+4]))
			}
		}
		return 0
	}
	return 0
}
