package rules

// Aho-Corasick multi-pattern literal matcher.
//
// This is the prefilter that makes a single-pass scan viable. Rules declare
// cheap literal "gates" (e.g. "eval", "_request"); we need to know which of the
// ~150 distinct gates occur in a file. Doing that with bytes.Contains per gate
// costs 150 full passes over every file. Aho-Corasick answers the same question
// in exactly one pass, regardless of how many gates exist, so adding rules to a
// pack stays effectively free at scan time.
//
// Matching is ASCII-case-insensitive: patterns are lowercased at build time and
// input bytes are folded during the walk, which avoids allocating a lowercased
// copy of every file.

// acNode uses a dense 256-wide transition table. That trades memory (1KiB per
// node, a couple of MiB for a realistic pack) for a branch-free lookup in the
// inner loop, which is the right trade when the automaton is built once and
// then walked over gigabytes of webroot.
type acNode struct {
	next [256]int32
	fail int32
	out  []int32
}

// AC is an immutable automaton. It is safe for concurrent use by the scan
// worker pool once Build returns.
type AC struct {
	nodes    []acNode
	patterns []string
	// hasEmpty short-circuits the degenerate no-patterns case.
	hasEmpty bool
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// BuildAC compiles the given literals into an automaton. Duplicate literals are
// collapsed; the returned index map reports, for each input literal, the
// pattern id assigned to it.
func BuildAC(literals []string) (*AC, map[string]int) {
	a := &AC{nodes: make([]acNode, 1, len(literals)*8+1)}
	a.nodes[0].fail = 0
	for i := range a.nodes[0].next {
		a.nodes[0].next[i] = -1
	}

	index := make(map[string]int, len(literals))
	for _, lit := range literals {
		if lit == "" {
			continue
		}
		low := make([]byte, len(lit))
		for i := 0; i < len(lit); i++ {
			low[i] = lowerByte(lit[i])
		}
		key := string(low)
		if _, seen := index[key]; seen {
			index[lit] = index[key]
			continue
		}
		id := len(a.patterns)
		a.patterns = append(a.patterns, key)
		index[key] = id
		index[lit] = id

		cur := int32(0)
		for i := 0; i < len(low); i++ {
			c := low[i]
			if a.nodes[cur].next[c] == -1 {
				var n acNode
				for j := range n.next {
					n.next[j] = -1
				}
				a.nodes = append(a.nodes, n)
				a.nodes[cur].next[c] = int32(len(a.nodes) - 1)
			}
			cur = a.nodes[cur].next[c]
		}
		a.nodes[cur].out = append(a.nodes[cur].out, int32(id))
	}

	if len(a.patterns) == 0 {
		a.hasEmpty = true
		return a, index
	}

	// BFS to build failure links, converting the sparse trie into a complete
	// DFA: every -1 transition is rewritten to the failure state's transition,
	// so the match loop never has to follow fail pointers.
	queue := make([]int32, 0, len(a.nodes))
	for c := 0; c < 256; c++ {
		nxt := a.nodes[0].next[c]
		if nxt == -1 {
			a.nodes[0].next[c] = 0
		} else {
			a.nodes[nxt].fail = 0
			queue = append(queue, nxt)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		cur := queue[qi]
		// Inherit outputs from the failure state so a single terminal check
		// reports every pattern ending at this position.
		f := a.nodes[cur].fail
		if len(a.nodes[f].out) > 0 {
			a.nodes[cur].out = append(a.nodes[cur].out, a.nodes[f].out...)
		}
		for c := 0; c < 256; c++ {
			nxt := a.nodes[cur].next[c]
			if nxt == -1 {
				a.nodes[cur].next[c] = a.nodes[f].next[c]
				continue
			}
			a.nodes[nxt].fail = a.nodes[f].next[c]
			queue = append(queue, nxt)
		}
	}
	return a, index
}

// NumPatterns is the size the hit slice passed to MatchSet must have.
func (a *AC) NumPatterns() int { return len(a.patterns) }

// MatchSet walks data once and sets hit[id]=true for every pattern present.
// The caller owns and reuses hit across files to keep the scan allocation-free.
func (a *AC) MatchSet(data []byte, hit []bool) {
	if a.hasEmpty || len(a.patterns) == 0 {
		return
	}
	var cur int32
	nodes := a.nodes
	for i := 0; i < len(data); i++ {
		cur = nodes[cur].next[lowerByte(data[i])]
		if out := nodes[cur].out; len(out) > 0 {
			for _, id := range out {
				hit[id] = true
			}
		}
	}
}
