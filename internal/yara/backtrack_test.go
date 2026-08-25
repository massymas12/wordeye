package yara

import (
	"bytes"
	"testing"
	"time"
)

// Regression: hex jump ranges multiply, so a pattern with several of them used
// to explore an exponential search space. Before the step budget this did not
// finish in 30 seconds on a 20KB buffer — on a customer's production web server
// that is a pegged core until the scan deadline fires.
func TestHexJumpBacktrackingIsBounded(t *testing.T) {
	set := compile(t, `
rule jumpy {
  strings: $a = { 41 [0-40] 41 [0-40] 41 [0-40] 41 [0-40] 41 [0-40] 42 }
  condition: $a
}`)
	data := bytes.Repeat([]byte{'A'}, 20000) // no 'B': worst case, every path fails

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		set.Scan(data, int64(len(data)), nil)
		done <- time.Since(start)
	}()

	select {
	case d := <-done:
		t.Logf("20KB buffer, 5 jump ranges: %s", d)
		if d > 5*time.Second {
			t.Errorf("scan took %s — the step budget is not bounding the search", d)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("scan did not finish: backtracking is unbounded")
	}
}

// The budget must not break ordinary hex matching.
func TestBudgetDoesNotBreakNormalHexMatching(t *testing.T) {
	set := compile(t, `
rule png { strings: $h = { 89 50 4E 47 0D 0A 1A 0A } condition: $h at 0 }
rule jump_ok { strings: $j = { 41 [2-4] 42 } condition: $j }
`)
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0}, 64)...)
	if got := names(set.Scan(png, int64(len(png)), nil)); len(got) == 0 || got[0] != "png" {
		t.Errorf("png header no longer matches: %v", got)
	}
	jmp := []byte{0x41, 0x00, 0x00, 0x42}
	found := false
	for _, m := range set.Scan(jmp, 4, nil) {
		if m.Rule.Name == "jump_ok" {
			found = true
		}
	}
	if !found {
		t.Error("a normal bounded jump stopped matching")
	}
}
