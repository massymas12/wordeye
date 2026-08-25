package yara

import (
	"strings"
	"testing"
)

func compile(t *testing.T, src string) *Set {
	t.Helper()
	rules, err := Parse(src, "test.yar")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set, err := Compile(rules)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return set
}

func names(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Rule.Name)
	}
	return out
}

func TestTextStringsAndQuantifiers(t *testing.T) {
	set := compile(t, `
rule any_of {
  strings:
    $a = "alpha"
    $b = "bravo"
  condition:
    any of them
}
rule all_of {
  strings:
    $a = "alpha"
    $b = "zulu"
  condition:
    all of them
}
rule two_of {
  strings:
    $x1 = "alpha"
    $x2 = "bravo"
    $x3 = "charlie"
  condition:
    2 of ($x*)
}
`)
	got := strings.Join(names(set.Scan([]byte("alpha and bravo"), 15, nil)), ",")
	if !strings.Contains(got, "any_of") {
		t.Errorf("any_of should match, got %q", got)
	}
	if strings.Contains(got, "all_of") {
		t.Errorf("all_of must not match without zulu, got %q", got)
	}
	if !strings.Contains(got, "two_of") {
		t.Errorf("two_of should match, got %q", got)
	}
}

func TestModifiers(t *testing.T) {
	set := compile(t, `
rule nocase_rule {
  strings: $a = "SeCrEt" nocase
  condition: $a
}
rule fullword_rule {
  strings: $a = "cat" fullword
  condition: $a
}
rule wide_rule {
  strings: $a = "wide" wide
  condition: $a
}
`)
	if n := names(set.Scan([]byte("this is secret"), 14, nil)); len(n) != 1 || n[0] != "nocase_rule" {
		t.Errorf("nocase: got %v", n)
	}
	// "concatenate" contains "cat" but not as a whole word.
	if n := names(set.Scan([]byte("concatenate"), 11, nil)); len(n) != 0 {
		t.Errorf("fullword should not match inside a word: got %v", n)
	}
	if n := names(set.Scan([]byte("a cat sat"), 9, nil)); len(n) != 1 || n[0] != "fullword_rule" {
		t.Errorf("fullword: got %v", n)
	}
	// UTF-16LE encoding of "wide".
	wide := []byte{'w', 0, 'i', 0, 'd', 0, 'e', 0}
	if n := names(set.Scan(wide, int64(len(wide)), nil)); len(n) != 1 || n[0] != "wide_rule" {
		t.Errorf("wide: got %v", n)
	}
	// The same rule must NOT match plain ascii, since `wide` alone is wide-only.
	if n := names(set.Scan([]byte("wide"), 4, nil)); len(n) != 0 {
		t.Errorf("wide-only rule matched ascii: got %v", n)
	}
}

// Hex patterns must match byte-exactly, including high bytes that a
// rune-oriented regexp engine would mangle.
func TestHexPatternsBinarySafe(t *testing.T) {
	set := compile(t, `
rule png_header {
  strings: $h = { 89 50 4E 47 0D 0A 1A 0A }
  condition: $h at 0
}
rule wildcard {
  strings: $w = { DE ?? BE ?F }
  condition: $w
}
rule jump {
  strings: $j = { 41 [2-4] 42 }
  condition: $j
}
`)
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFE}
	if n := names(set.Scan(png, int64(len(png)), nil)); len(n) == 0 || n[0] != "png_header" {
		t.Errorf("png header at 0: got %v", n)
	}
	// $h at 0 must be positional.
	shifted := append([]byte{0x00}, png...)
	for _, m := range set.Scan(shifted, int64(len(shifted)), nil) {
		if m.Rule.Name == "png_header" {
			t.Error("`at 0` matched a header that is not at offset 0")
		}
	}
	// 0xDE ?? 0xBE with low nibble F.
	wc := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if n := names(set.Scan(wc, 4, nil)); len(n) == 0 {
		t.Errorf("nibble wildcard: got %v", n)
	}
	jmp := []byte{0x41, 0x00, 0x00, 0x00, 0x42}
	found := false
	for _, m := range set.Scan(jmp, 5, nil) {
		if m.Rule.Name == "jump" {
			found = true
		}
	}
	if !found {
		t.Error("jump [2-4] did not match")
	}
}

func TestFilesizeAndCount(t *testing.T) {
	set := compile(t, `
rule small_only {
  strings: $a = "x"
  condition: $a and filesize < 10
}
rule counted {
  strings: $a = "ab"
  condition: #a >= 3
}
`)
	if n := names(set.Scan([]byte("x"), 5, nil)); len(n) == 0 {
		t.Error("filesize < 10 should match at size 5")
	}
	for _, m := range set.Scan([]byte("x"), 5000, nil) {
		if m.Rule.Name == "small_only" {
			t.Error("filesize guard ignored")
		}
	}
	if n := names(set.Scan([]byte("ababab"), 6, nil)); len(n) == 0 {
		t.Errorf("#a >= 3 should match: got %v", n)
	}
	for _, m := range set.Scan([]byte("abab"), 4, nil) {
		if m.Rule.Name == "counted" {
			t.Error("#a >= 3 matched with only 2 occurrences")
		}
	}
}

func TestNegationAndPrefilterSafety(t *testing.T) {
	set := compile(t, `
rule needs_a_not_b {
  strings:
    $a = "alpha"
    $b = "bravo"
  condition:
    $a and not $b
}
`)
	if n := names(set.Scan([]byte("alpha only"), 10, nil)); len(n) != 1 {
		t.Errorf("expected match: got %v", n)
	}
	if n := names(set.Scan([]byte("alpha bravo"), 11, nil)); len(n) != 0 {
		t.Errorf("negation ignored: got %v", n)
	}
	// Prefilter safety: gating is sound exactly when the condition cannot be
	// true unless one of the rule's own strings matched. `$a and not $b`
	// REQUIRES $a, so it is safe to gate. A bare negation or a filesize-only
	// clause is not.
	for _, r := range set.Rules {
		if r.Name == "needs_a_not_b" && !r.prefilterable {
			t.Error("`$a and not $b` requires $a, so it is safe to prefilter")
		}
	}

	unsafe := compile(t, `
rule bare_negation {
  strings: $b = "bravo"
  condition: not $b
}
rule size_or_string {
  strings: $a = "alpha"
  condition: $a or filesize < 10
}
`)
	for _, r := range unsafe.Rules {
		if r.prefilterable {
			t.Errorf("rule %s can match without any literal present; it must not be prefiltered", r.Name)
		}
	}
	// And prove it: bare_negation must fire on a file containing none of its
	// literals, even with a gate that rejects everything.
	if n := names(unsafe.Scan([]byte("nothing here"), 12, func([]string) bool { return false })); len(n) == 0 {
		t.Error("a non-prefilterable rule was skipped by the gate")
	}
}

// The gate must never cause a miss: a prefilterable rule skipped by the gate
// must be one that genuinely could not have matched.
func TestGateNeverCausesFalseNegative(t *testing.T) {
	set := compile(t, `
rule gated {
  strings:
    $a = "needle"
  condition:
    $a
}
`)
	data := []byte("haystack with a needle inside")
	// Gate says "no literals present" — but the rule IS prefilterable and the
	// literal IS present, so a correct caller would have returned true. Verify
	// the plumbing honours the gate (this documents the contract).
	if n := names(set.Scan(data, int64(len(data)), func([]string) bool { return false })); len(n) != 0 {
		t.Errorf("gate was not honoured: got %v", n)
	}
	if n := names(set.Scan(data, int64(len(data)), func(l []string) bool {
		for _, s := range l {
			if strings.Contains(string(data), s) {
				return true
			}
		}
		return false
	})); len(n) != 1 {
		t.Errorf("correct gate should allow the match: got %v", n)
	}
}

func TestUnsupportedFeaturesRejected(t *testing.T) {
	for _, src := range []string{
		`rule m { condition: pe.number_of_sections > 2 }`,
		`rule x { strings: $a = "z" xor condition: $a }`,
	} {
		if _, err := Parse(src, "t.yar"); err == nil {
			t.Errorf("expected rejection for unsupported feature: %s", src)
		}
	}
}

// The shipped ruleset must always compile.
func TestBuiltinRulesetCompiles(t *testing.T) {
	set, err := Embedded()
	if err != nil {
		t.Fatalf("built-in ruleset failed to compile: %v", err)
	}
	if len(set.Rules) < 10 {
		t.Errorf("expected the built-in ruleset to carry rules, got %d", len(set.Rules))
	}
	if len(set.Literals()) == 0 {
		t.Error("built-in ruleset exposed no literals for prefiltering")
	}
}
