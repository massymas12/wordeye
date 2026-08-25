package agent

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
)

// A constant folder for a tiny subset of PHP.
//
// This exists to answer one question: what bytes does `$key` actually hold?
//
// A self-decrypting shell must carry everything it needs to decrypt itself, so
// when the key is in the body it is always *derivable* — but rarely written as
// a plain literal. It is far more often assembled:
//
//	$k = base64_decode('c2VjcmV0');
//	$iv = pack('H*', '00112233445566778899aabbccddeeff');
//	$p = openssl_decrypt($blob, 'AES-256-CBC', md5($k, true), 0, $iv);
//
// Resolving those three variables is the whole difficulty. The decryption
// itself is microseconds.
//
// IMPORTANT: this evaluates, it does not EXECUTE. There is no PHP interpreter
// here and no code from the file ever runs. It walks a restricted expression
// grammar — literals, concatenation, and a fixed set of pure transforms — and
// gives up on anything else. An expression it cannot fold is simply unknown,
// never a side effect.

const (
	// constBudget bounds total folding work per file.
	constBudget = 4000
	// constMaxDepth bounds recursion through variable references.
	constMaxDepth = 12
	// constMaxValue caps any intermediate value.
	constMaxValue = 4 << 20
)

type constResolver struct {
	src  []byte
	view *phpView

	// assigns maps a variable name to the source range of its last assignment.
	assigns map[string]span
	cache   map[string][]byte
	failed  map[string]bool
	budget  int
	depth   int
}

func newConstResolver(src []byte, view *phpView) *constResolver {
	r := &constResolver{
		src: src, view: view,
		assigns: map[string]span{},
		cache:   map[string][]byte{},
		failed:  map[string]bool{},
		budget:  constBudget,
	}
	// Assignments are located in the CODE view (so a `$x = ...` inside a comment
	// or a string is ignored), but evaluated against the original source, where
	// the string contents still exist.
	for _, m := range assignRe.FindAllSubmatchIndex(view.code, 400) {
		name := string(view.code[m[2]:m[3]])
		r.assigns[name] = span{m[4], m[5]}
	}
	return r
}

// literalAt returns the content of a string literal whose delimiter sits at or
// just before pos, if any.
func (r *constResolver) literalAt(pos int) ([]byte, int, bool) {
	for _, s := range r.view.strs {
		// The opening delimiter is the byte before the content.
		if s.start-1 == pos || s.start == pos {
			end := s.end
			if end > len(r.src) {
				end = len(r.src)
			}
			if s.start > end {
				return nil, 0, false
			}
			// Consume through the closing delimiter.
			return unescapePHP(r.src[s.start:end]), end + 1, true
		}
	}
	return nil, 0, false
}

// resolveVar folds a variable to its literal value.
func (r *constResolver) resolveVar(name string) ([]byte, bool) {
	if v, ok := r.cache[name]; ok {
		return v, true
	}
	if r.failed[name] {
		return nil, false
	}
	sp, ok := r.assigns[name]
	if !ok {
		r.failed[name] = true
		return nil, false
	}
	if r.depth >= constMaxDepth {
		return nil, false
	}
	r.depth++
	v, ok := r.evalRange(sp.start, sp.end)
	r.depth--
	if !ok {
		r.failed[name] = true
		return nil, false
	}
	r.cache[name] = v
	return v, true
}

// evalRange folds the expression occupying src[start:end).
//
// Concatenation is the only operator: everything else must be a literal, a
// variable, or a call to one of the pure functions in applyFunc.
func (r *constResolver) evalRange(start, end int) ([]byte, bool) {
	if start < 0 || end > len(r.src) || start >= end {
		return nil, false
	}
	var out []byte
	i := start

	for i < end {
		if r.budget <= 0 {
			return nil, false
		}
		r.budget--

		c := r.src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
			continue
		case c == '.' || c == '(' || c == ')' || c == ',':
			// Concatenation and stray grouping are skipped; argument splitting
			// is handled by the caller.
			i++
			continue
		case c == '\'' || c == '"':
			val, next, ok := r.literalAt(i)
			if !ok {
				return nil, false
			}
			out = append(out, val...)
			i = next
		case c == '$':
			j := i + 1
			for j < end && isIdentByte(r.src[j]) {
				j++
			}
			if j == i+1 {
				return nil, false
			}
			v, ok := r.resolveVar(string(r.src[i+1 : j]))
			if !ok {
				return nil, false
			}
			out = append(out, v...)
			i = j
		case isIdentByte(c):
			j := i
			for j < end && isIdentByte(r.src[j]) {
				j++
			}
			name := string(bytes.ToLower(r.src[i:j]))
			// Skip whitespace before a possible '('.
			k := j
			for k < end && (r.src[k] == ' ' || r.src[k] == '\t') {
				k++
			}
			if k < end && r.src[k] == '(' {
				argEnd := matchParen(r.src, k, end)
				if argEnd < 0 {
					return nil, false
				}
				args := r.splitArgs(k+1, argEnd)
				v, ok := r.applyFunc(name, args)
				if !ok {
					return nil, false
				}
				out = append(out, v...)
				i = argEnd + 1
				continue
			}
			// A bare number is a value; a bare identifier is an unknown
			// constant, which we cannot fold.
			if n, err := strconv.Atoi(name); err == nil {
				out = append(out, []byte(strconv.Itoa(n))...)
				i = j
				continue
			}
			return nil, false
		default:
			return nil, false
		}
		if len(out) > constMaxValue {
			return nil, false
		}
	}
	return out, true
}

// splitArgs divides an argument list on top-level commas, skipping commas that
// sit inside nested calls or string literals.
func (r *constResolver) splitArgs(start, end int) []span {
	var out []span
	depth := 0
	argStart := start
	i := start
	for i < end {
		c := r.src[i]
		switch c {
		case '\'', '"':
			if _, next, ok := r.literalAt(i); ok {
				i = next
				continue
			}
			i++
			continue
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, span{argStart, i})
				argStart = i + 1
			}
		}
		i++
	}
	if argStart < end {
		out = append(out, span{argStart, end})
	}
	return out
}

func (r *constResolver) arg(args []span, n int) ([]byte, bool) {
	if n >= len(args) {
		return nil, false
	}
	return r.evalRange(args[n].start, args[n].end)
}

// applyFunc implements the pure transforms a packer realistically uses. Any
// function not listed makes the whole expression unknown, which is the correct
// conservative outcome.
func (r *constResolver) applyFunc(name string, args []span) ([]byte, bool) {
	first := func() ([]byte, bool) { return r.arg(args, 0) }

	switch name {
	case "base64_decode":
		v, ok := first()
		if !ok {
			return nil, false
		}
		d, err := base64.StdEncoding.DecodeString(string(stripLayout(v)))
		if err != nil {
			d, err = base64.RawStdEncoding.DecodeString(string(stripLayout(v)))
			if err != nil {
				return nil, false
			}
		}
		return d, true

	case "hex2bin":
		v, ok := first()
		if !ok {
			return nil, false
		}
		d, err := hex.DecodeString(string(v))
		return d, err == nil

	case "pack":
		// Only the hex form matters here: pack('H*', '...').
		fmtArg, ok := r.arg(args, 0)
		if !ok || len(args) < 2 {
			return nil, false
		}
		// pack('H*', $hex) is the hex form and 'h*' its nibble-swapped variant.
		// Lower-casing the format code collapses both spellings, so this needs
		// to compare once — the original compared the same value twice, which
		// go vet correctly flagged as a redundant condition.
		if f := string(bytes.ToLower(fmtArg)); f != "h*" {
			return nil, false
		}
		v, ok := r.arg(args, 1)
		if !ok {
			return nil, false
		}
		d, err := hex.DecodeString(string(v))
		return d, err == nil

	case "str_rot13":
		v, ok := first()
		if !ok {
			return nil, false
		}
		return rot13(v), true

	case "strrev":
		v, ok := first()
		if !ok {
			return nil, false
		}
		out := make([]byte, len(v))
		for i := range v {
			out[len(v)-1-i] = v[i]
		}
		return out, true

	case "trim", "stripslashes", "rtrim", "ltrim":
		v, ok := first()
		if !ok {
			return nil, false
		}
		return bytes.TrimSpace(v), true

	case "strtolower":
		v, ok := first()
		if !ok {
			return nil, false
		}
		return bytes.ToLower(v), true

	case "strtoupper":
		v, ok := first()
		if !ok {
			return nil, false
		}
		return bytes.ToUpper(v), true

	case "chr":
		v, ok := first()
		if !ok {
			return nil, false
		}
		n, err := strconv.Atoi(string(bytes.TrimSpace(v)))
		if err != nil || n < 0 || n > 255 {
			return nil, false
		}
		return []byte{byte(n)}, true

	case "md5":
		v, ok := first()
		if !ok {
			return nil, false
		}
		sum := md5.Sum(v)
		// md5($x, true) returns raw bytes; the default returns lowercase hex.
		if raw, ok := r.boolArg(args, 1); ok && raw {
			return sum[:], true
		}
		return []byte(hex.EncodeToString(sum[:])), true

	case "sha1":
		v, ok := first()
		if !ok {
			return nil, false
		}
		sum := sha1.Sum(v)
		if raw, ok := r.boolArg(args, 1); ok && raw {
			return sum[:], true
		}
		return []byte(hex.EncodeToString(sum[:])), true

	case "gzinflate":
		return inflateWith(r, args, "flate")
	case "gzuncompress":
		return inflateWith(r, args, "zlib")
	case "gzdecode":
		return inflateWith(r, args, "gzip")

	case "substr":
		v, ok := first()
		if !ok {
			return nil, false
		}
		off, ok := r.intArg(args, 1)
		if !ok {
			return nil, false
		}
		if off < 0 {
			off = len(v) + off
		}
		if off < 0 || off > len(v) {
			return nil, false
		}
		out := v[off:]
		if n, ok := r.intArg(args, 2); ok {
			if n < 0 {
				n = len(out) + n
			}
			if n >= 0 && n <= len(out) {
				out = out[:n]
			}
		}
		return out, true

	case "str_replace":
		search, ok1 := r.arg(args, 0)
		replace, ok2 := r.arg(args, 1)
		subject, ok3 := r.arg(args, 2)
		if !ok1 || !ok2 || !ok3 {
			return nil, false
		}
		return bytes.ReplaceAll(subject, search, replace), true

	case "urldecode", "rawurldecode":
		v, ok := first()
		if !ok {
			return nil, false
		}
		return urlDecodeBytes(v), true
	}
	return nil, false
}

func inflateWith(r *constResolver, args []span, kind string) ([]byte, bool) {
	v, ok := r.arg(args, 0)
	if !ok {
		return nil, false
	}
	var rc io.ReadCloser
	var err error
	switch kind {
	case "flate":
		rc = flate.NewReader(bytes.NewReader(v))
	case "zlib":
		rc, err = zlib.NewReader(bytes.NewReader(v))
	case "gzip":
		rc, err = gzip.NewReader(bytes.NewReader(v))
	}
	if err != nil || rc == nil {
		return nil, false
	}
	defer rc.Close()
	out, err := io.ReadAll(io.LimitReader(rc, constMaxValue))
	if err != nil && len(out) == 0 {
		return nil, false
	}
	return out, true
}

func (r *constResolver) intArg(args []span, n int) (int, bool) {
	v, ok := r.arg(args, n)
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(string(bytes.TrimSpace(v)))
	return i, err == nil
}

// boolArg reads a literal true/false without folding, since `true` is a bare
// identifier the expression evaluator deliberately refuses.
func (r *constResolver) boolArg(args []span, n int) (bool, bool) {
	if n >= len(args) {
		return false, false
	}
	s := args[n]
	if s.start < 0 || s.end > len(r.src) || s.start >= s.end {
		return false, false
	}
	t := bytes.ToLower(bytes.TrimSpace(r.src[s.start:s.end]))
	switch string(t) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	}
	return false, false
}

// matchParen returns the index of the ')' matching the '(' at open.
func matchParen(src []byte, open, limit int) int {
	if open >= len(src) || src[open] != '(' {
		return -1
	}
	if limit > len(src) {
		limit = len(src)
	}
	depth := 0
	inStr := byte(0)
	for i := open; i < limit; i++ {
		c := src[i]
		if inStr != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// unescapePHP resolves the escape sequences a double-quoted PHP string uses.
// Single-quoted strings only honour \\ and \', and treating them alike is
// harmless for the purpose of recovering a key.
func unescapePHP(b []byte) []byte {
	if !bytes.ContainsRune(b, '\\') {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		i++
		switch b[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '0':
			out = append(out, 0)
		case 'x':
			if i+2 < len(b) {
				if v, err := strconv.ParseUint(string(b[i+1:i+3]), 16, 8); err == nil {
					out = append(out, byte(v))
					i += 2
					continue
				}
			}
			out = append(out, 'x')
		default:
			out = append(out, b[i])
		}
	}
	return out
}

func urlDecodeBytes(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '+':
			out = append(out, ' ')
		case b[i] == '%' && i+2 < len(b):
			if v, err := strconv.ParseUint(string(b[i+1:i+3]), 16, 8); err == nil {
				out = append(out, byte(v))
				i += 2
				continue
			}
			out = append(out, b[i])
		default:
			out = append(out, b[i])
		}
	}
	return out
}
