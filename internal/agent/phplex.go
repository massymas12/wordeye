package agent

import "bytes"

// A minimal PHP lexer.
//
// The heuristic engine used to be a bag of literals: it could not tell
// `eval($_POST[0])` from `// never use eval($_POST[0])` in a docblock. That
// costs precision in both directions — false positives on documentation, and a
// threshold pushed so high that real shells slip under it.
//
// This is not a parser and does not try to be. It answers three questions that
// turn out to carry most of the value:
//
//	1. Which bytes are executable code, as opposed to comments or string data?
//	2. Where are the string literals, and what do they contain?
//	3. Are there constructs (backticks, heredocs) that a literal scan misses?
//
// The code view is the SAME LENGTH as the input, with comment bytes and string
// contents overwritten by spaces. Preserving offsets means line numbers,
// evidence snippets and proximity distances all keep working unchanged.

type span struct{ start, end int }

type phpView struct {
	// code is the input with comments and string contents blanked to spaces.
	code []byte
	// strs are the spans of string-literal CONTENT (excluding delimiters).
	strs []span
	// comments are the spans of comment content.
	comments []span

	hasOpenTag  bool
	hasBacktick bool // `cmd` is PHP's shell-exec operator
	heredocs    int
}

// lexPHP builds the views. Single pass, no allocation beyond the code buffer
// (which the caller may supply for reuse).
func lexPHP(src []byte, reuse []byte) *phpView {
	v := &phpView{}
	if cap(reuse) >= len(src) {
		v.code = reuse[:len(src)]
	} else {
		v.code = make([]byte, len(src))
	}
	copy(v.code, src)

	blank := func(from, to int) {
		if from < 0 {
			from = 0
		}
		if to > len(v.code) {
			to = len(v.code)
		}
		for i := from; i < to; i++ {
			// Keep newlines so line numbering downstream stays correct.
			if v.code[i] != '\n' {
				v.code[i] = ' '
			}
		}
	}

	i := 0
	inPHP := false

	for i < len(src) {
		if !inPHP {
			// Outside PHP tags everything is literal output, not code.
			next := bytes.Index(src[i:], []byte("<?"))
			if next < 0 {
				blank(i, len(src))
				break
			}
			blank(i, i+next)
			i += next
			v.hasOpenTag = true
			// Skip the opening tag itself.
			if bytes.HasPrefix(src[i:], []byte("<?php")) {
				i += 5
			} else if bytes.HasPrefix(src[i:], []byte("<?=")) {
				i += 3
			} else {
				i += 2
			}
			inPHP = true
			continue
		}

		c := src[i]
		switch {
		// ---- close tag ----
		case c == '?' && i+1 < len(src) && src[i+1] == '>':
			i += 2
			inPHP = false

		// ---- line comments ----
		case c == '/' && i+1 < len(src) && src[i+1] == '/',
			c == '#' && !(i+1 < len(src) && src[i+1] == '['): // #[Attr] is not a comment
			start := i
			for i < len(src) && src[i] != '\n' {
				// A close tag terminates a line comment.
				if src[i] == '?' && i+1 < len(src) && src[i+1] == '>' {
					break
				}
				i++
			}
			v.comments = append(v.comments, span{start, i})
			blank(start, i)

		// ---- block comments ----
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			start := i
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			if i+1 < len(src) {
				i += 2
			} else {
				i = len(src)
			}
			v.comments = append(v.comments, span{start, i})
			blank(start, i)

		// ---- single-quoted ----
		case c == '\'':
			i++
			start := i
			for i < len(src) {
				if src[i] == '\\' && i+1 < len(src) {
					i += 2
					continue
				}
				if src[i] == '\'' {
					break
				}
				i++
			}
			v.strs = append(v.strs, span{start, i})
			blank(start, i)
			i++ // closing quote

		// ---- double-quoted ----
		case c == '"':
			i++
			start := i
			for i < len(src) {
				if src[i] == '\\' && i+1 < len(src) {
					i += 2
					continue
				}
				if src[i] == '"' {
					break
				}
				i++
			}
			v.strs = append(v.strs, span{start, i})
			blank(start, i)
			i++

		// ---- backtick: PHP's shell_exec operator, invisible to literal scans ----
		case c == '`':
			v.hasBacktick = true
			i++
			start := i
			for i < len(src) && src[i] != '`' {
				i++
			}
			v.strs = append(v.strs, span{start, i})
			blank(start, i)
			i++

		// ---- heredoc / nowdoc ----
		case c == '<' && bytes.HasPrefix(src[i:], []byte("<<<")):
			v.heredocs++
			j := i + 3
			for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
				j++
			}
			quote := byte(0)
			if j < len(src) && (src[j] == '\'' || src[j] == '"') {
				quote = src[j]
				j++
			}
			idStart := j
			for j < len(src) && (isIdentByte(src[j])) {
				j++
			}
			label := src[idStart:j]
			if quote != 0 && j < len(src) && src[j] == quote {
				j++
			}
			// Body runs until a line whose first non-whitespace is the label.
			for j < len(src) && src[j] != '\n' {
				j++
			}
			bodyStart := j
			end := findHeredocEnd(src, j, label)
			v.strs = append(v.strs, span{bodyStart, end})
			blank(bodyStart, end)
			i = end

		default:
			i++
		}
	}
	return v
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// findHeredocEnd locates the terminating label.
func findHeredocEnd(src []byte, from int, label []byte) int {
	if len(label) == 0 {
		return len(src)
	}
	i := from
	for i < len(src) {
		nl := bytes.IndexByte(src[i:], '\n')
		if nl < 0 {
			return len(src)
		}
		lineStart := i + nl + 1
		j := lineStart
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if bytes.HasPrefix(src[j:], label) {
			after := j + len(label)
			if after >= len(src) || !isIdentByte(src[after]) {
				return after
			}
		}
		i = lineStart
	}
	return len(src)
}

// stringValues returns the contents of string literals, bounded in count and
// size so a pathological file cannot blow up memory.
func (v *phpView) stringValues(src []byte, maxCount, maxLen int) [][]byte {
	out := make([][]byte, 0, minInt(len(v.strs), maxCount))
	for _, s := range v.strs {
		if len(out) >= maxCount {
			break
		}
		if s.end <= s.start || s.start >= len(src) {
			continue
		}
		end := s.end
		if end > len(src) {
			end = len(src)
		}
		if end-s.start > maxLen {
			end = s.start + maxLen
		}
		out = append(out, src[s.start:end])
	}
	return out
}

// withoutComments returns src with comment bodies blanked to spaces, leaving
// string literals intact. Offsets are preserved.
//
// This is the right view for pattern engines that reason about PHP but still
// need string contents as evidence — YARA rules match shell banners, stored
// password hashes and packed blobs, all of which live inside string literals.
// Comments carry no such evidence: they are prose, and prose that names a
// technique is not a use of it. A security plugin documenting php://input, or a
// docblock showing example code, is the canonical case.
//
// The caller may supply a buffer to reuse.
func (v *phpView) withoutComments(src []byte, reuse []byte) []byte {
	if len(v.comments) == 0 {
		return src
	}
	buf := reuse
	if cap(buf) < len(src) {
		buf = make([]byte, len(src))
	}
	buf = buf[:len(src)]
	copy(buf, src)
	for _, c := range v.comments {
		start, end := c.start, c.end
		if start < 0 {
			start = 0
		}
		if end > len(buf) {
			end = len(buf)
		}
		for i := start; i < end; i++ {
			if buf[i] != '\n' && buf[i] != '\r' {
				buf[i] = ' '
			}
		}
	}
	return buf
}

// concatChains merges string literals joined only by the `.` operator.
//
// This is what defeats split-literal evasion. An attacker who writes
// `$f = 'ev' . 'al';` removes the literal "eval" from the file entirely, so
// every literal-based scanner — including this one, before this function —
// sees nothing. Reassembling the chain puts the identifier back.
func (v *phpView) concatChains(src []byte, maxChains int) []concatChain {
	var out []concatChain
	i := 0
	for i < len(v.strs) && len(out) < maxChains {
		chain := []span{v.strs[i]}
		j := i + 1
		for j < len(v.strs) {
			prev := chain[len(chain)-1]
			gapStart, gapEnd := prev.end, v.strs[j].start
			if gapEnd <= gapStart || gapEnd > len(src) {
				break
			}
			// The gap must be only the closing quote, a dot, whitespace, and the
			// opening quote of the next literal.
			if !isConcatGap(src[gapStart:gapEnd]) {
				break
			}
			chain = append(chain, v.strs[j])
			j++
		}
		if len(chain) >= 2 {
			var buf []byte
			for _, s := range chain {
				end := s.end
				if end > len(src) {
					end = len(src)
				}
				if s.start < end {
					buf = append(buf, src[s.start:end]...)
				}
				if len(buf) > 512 {
					break
				}
			}
			out = append(out, concatChain{value: buf, at: chain[0].start, parts: len(chain)})
		}
		if j > i {
			i = j
		} else {
			i++
		}
	}
	return out
}

type concatChain struct {
	value []byte
	at    int
	parts int
}

func isConcatGap(gap []byte) bool {
	sawDot := false
	for _, c := range gap {
		switch {
		case c == '.':
			if sawDot {
				return false // ".." is not a simple concat
			}
			sawDot = true
		case c == '\'' || c == '"' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			// delimiters and whitespace are fine
		default:
			return false
		}
	}
	return sawDot
}
