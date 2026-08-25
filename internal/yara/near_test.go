package yara

import (
	"strings"
	"testing"
)

// near() is the proximity primitive. Without it, conditions expressed only
// co-occurrence — and in a 400KB plugin any two tokens co-occur, which is what
// produced a field run's worth of critical false positives against Wordfence,
// Gravity Forms, ACF and Divi.

func compileSrc(t *testing.T, src string) *Set {
	t.Helper()
	rs, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s, err := Compile(rs)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func matched(s *Set, data []byte) []string {
	var out []string
	for _, m := range s.Scan(data, int64(len(data)), nil) {
		out = append(out, m.Rule.Name)
	}
	return out
}

const nearRule = `
rule prox
{
    strings:
        $d = "decodeit"
        $e = "runit"
    condition:
        near(($d), ($e), 100)
}
`

func TestNearMatchesWhenClose(t *testing.T) {
	s := compileSrc(t, nearRule)
	data := []byte("runit(decodeit($x));")
	if got := matched(s, data); len(got) != 1 {
		t.Errorf("adjacent decoder and sink did not match: %v", got)
	}
}

func TestNearRejectsWhenDistant(t *testing.T) {
	s := compileSrc(t, nearRule)
	data := []byte("decodeit($asset);" + strings.Repeat("x", 5000) + "runit($tpl);")
	if got := matched(s, data); len(got) != 0 {
		t.Errorf("distant decoder and sink matched: %v", got)
	}
}

// Order must not matter: the sink may precede the decoder.
func TestNearIsSymmetric(t *testing.T) {
	s := compileSrc(t, nearRule)
	fwd := []byte("decodeit(); runit();")
	rev := []byte("runit(); decodeit();")
	if len(matched(s, fwd)) != 1 || len(matched(s, rev)) != 1 {
		t.Error("near() is not symmetric in operand order")
	}
}

// A cluster later in the file must be found even when a decoy appears first.
func TestNearFindsLateCluster(t *testing.T) {
	s := compileSrc(t, nearRule)
	data := []byte("decodeit($a);" + strings.Repeat("y", 9000) + "runit(decodeit($b));")
	if got := matched(s, data); len(got) != 1 {
		t.Errorf("a genuine late cluster was missed: %v", got)
	}
}

// Wildcard sets are the common form in the shipped rules.
func TestNearAcceptsWildcardSets(t *testing.T) {
	s := compileSrc(t, `
rule prox_wild
{
    strings:
        $d1 = "aaa"
        $d2 = "bbb"
        $e1 = "zzz"
    condition:
        near(($d*), ($e*), 50)
}
`)
	if got := matched(s, []byte("bbb zzz")); len(got) != 1 {
		t.Errorf("wildcard set did not match: %v", got)
	}
	if got := matched(s, []byte("bbb"+strings.Repeat(".", 500)+"zzz")); len(got) != 0 {
		t.Errorf("wildcard set matched at distance: %v", got)
	}
}

// One side absent means no match, and must not panic.
func TestNearHandlesMissingSide(t *testing.T) {
	s := compileSrc(t, nearRule)
	if got := matched(s, []byte("decodeit only")); len(got) != 0 {
		t.Errorf("matched with one side absent: %v", got)
	}
	if got := matched(s, []byte("nothing here")); len(got) != 0 {
		t.Errorf("matched with both sides absent: %v", got)
	}
}

// near() must keep the rule prefilterable — it cannot be true unless strings
// matched, so gating on its literals is safe and preserves the fast path.
func TestNearStaysPrefilterable(t *testing.T) {
	s := compileSrc(t, nearRule)
	if len(s.Rules) != 1 {
		t.Fatal("expected one rule")
	}
	if !s.Rules[0].prefilterable {
		t.Error("a near() rule was marked non-prefilterable, costing the fast path")
	}
	// And the gate must actually be consulted: a gate that always says no must
	// suppress the rule.
	never := func([]string) bool { return false }
	if got := s.Scan([]byte("runit(decodeit($x));"), 20, never); len(got) != 0 {
		t.Error("gate was ignored for a near() rule")
	}
}

func TestNearRejectsMalformedSyntax(t *testing.T) {
	bad := []string{
		`rule a { strings: $x = "q" condition: near(($x), 100) }`,
		`rule b { strings: $x = "q" condition: near(($x), ($x)) }`,
		`rule c { strings: $x = "q" condition: near($x, ($x), 10) }`,
		`rule d { strings: $x = "q" condition: near(($x), ($x), abc) }`,
	}
	for i, src := range bad {
		if _, err := Parse(src, "test"); err == nil {
			t.Errorf("case %d: malformed near() was accepted", i)
		}
	}
}
