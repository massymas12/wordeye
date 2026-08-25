package rules

import (
	"strings"
	"testing"
)

// Proximity and scope.
//
// A rule that ANDs several patterns across a whole file is nearly worthless on
// large files, because a 500KB plugin contains almost any combination of tokens
// somewhere. These tests pin the two mechanisms that turn co-occurrence into
// evidence: a bounded window, and matching against code rather than prose.

func compileOne(t *testing.T, y string) *Rule {
	t.Helper()
	p, err := Parse([]byte("meta:\n  name: t\nrules:\n"+y), "test")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Compile(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(s.Rules))
	}
	return s.Rules[0]
}

func TestWithinRequiresProximity(t *testing.T) {
	r := compileOne(t, `
  - id: t.near
    gate: ['alpha']
    all:
      - 'alpha'
      - 'omega'
    within: 100
`)
	near := []byte("alpha " + strings.Repeat("x", 50) + " omega")
	far := []byte("alpha " + strings.Repeat("x", 5000) + " omega")

	if ok, _ := r.MatchContent(near, nil); !ok {
		t.Error("patterns 50 bytes apart did not match a 100-byte window")
	}
	if ok, _ := r.MatchContent(far, nil); ok {
		t.Error("patterns 5000 bytes apart matched a 100-byte window")
	}
}

// The window must find a qualifying cluster even when earlier occurrences are
// spread out — otherwise a shell could hide behind one decoy mention.
func TestWithinFindsClusterAmongDecoys(t *testing.T) {
	r := compileOne(t, `
  - id: t.cluster
    gate: ['alpha']
    all:
      - 'alpha'
      - 'omega'
    within: 60
`)
	// A lone "alpha", a long gap, then a genuine adjacent pair.
	data := []byte("alpha" + strings.Repeat(" ", 4000) + "omega ... alpha omega")
	if ok, _ := r.MatchContent(data, nil); !ok {
		t.Error("a genuine adjacent pair was missed because a decoy came first")
	}
}

// Zero means unbounded, preserving the original semantics.
func TestWithinZeroIsUnbounded(t *testing.T) {
	r := compileOne(t, `
  - id: t.unbounded
    gate: ['alpha']
    all:
      - 'alpha'
      - 'omega'
`)
	far := []byte("alpha" + strings.Repeat("x", 100000) + "omega")
	if ok, _ := r.MatchContent(far, nil); !ok {
		t.Error("a rule with no window should match at any distance")
	}
}

func TestScopeCodeIgnoresCommentsAndStrings(t *testing.T) {
	r := compileOne(t, `
  - id: t.code
    gate: ['danger']
    scope: code
    any:
      - 'danger'
`)
	raw := []byte("<?php // danger is only named here\n$x = 'danger';\n")
	// Stand in for the lexer: comment and string CONTENTS blanked, offsets kept.
	code := []byte("<?php //                          \n$x = '      ';\n")

	if ok, _ := r.MatchContent(raw, code); ok {
		t.Error("code-scoped rule fired on a comment/string mention")
	}
	live := []byte("<?php danger($x);\n")
	if ok, _ := r.MatchContent(live, live); !ok {
		t.Error("code-scoped rule missed a real call")
	}
}

// all_code exists for genuinely mixed rules: a string-literal path plus an
// executor that must be real code.
func TestAllCodeMixesSubjects(t *testing.T) {
	r := compileOne(t, `
  - id: t.mixed
    gate: ['php://input']
    all:
      - 'php://input'
    all_code:
      - 'runit\s*\('
    within: 500
`)
	// The path lives in a string literal, so it survives only in raw.
	raw := []byte("<?php $d = get('php://input'); runit($d);")
	code := []byte("<?php $d = get('           '); runit($d);")
	if ok, _ := r.MatchContent(raw, code); !ok {
		t.Error("mixed rule missed: string-literal path plus real executor")
	}

	// Same tokens, but the executor is only named in a comment.
	raw2 := []byte("<?php // php://input is parsed, never runit( ) here\n")
	code2 := []byte("<?php //                                          \n")
	if ok, _ := r.MatchContent(raw2, code2); ok {
		t.Error("mixed rule fired when the executor was only in a comment")
	}
}

func TestScopeIsValidated(t *testing.T) {
	p, err := Parse([]byte("meta:\n  name: t\nrules:\n  - id: t.bad\n    scope: sideways\n    any: ['x']\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(nil, p); err == nil {
		t.Error("an unknown scope was accepted")
	}
}

// smallestWindow is the core of the proximity check; exercise it directly
// including the exhaustion path.
func TestSmallestWindow(t *testing.T) {
	cases := []struct {
		name   string
		groups [][]int
		within int
		want   bool
	}{
		{"adjacent", [][]int{{0}, {10}}, 20, true},
		{"too far", [][]int{{0}, {100}}, 20, false},
		{"exact boundary", [][]int{{0}, {20}}, 20, true},
		{"three groups cluster", [][]int{{0, 500}, {505}, {510}}, 20, true},
		{"three groups spread", [][]int{{0}, {500}, {1000}}, 20, false},
		{"single group", [][]int{{42}}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := smallestWindow(c.groups, c.within); ok != c.want {
				t.Errorf("smallestWindow(%v, %d) = %v, want %v",
					c.groups, c.within, ok, c.want)
			}
		})
	}
}
