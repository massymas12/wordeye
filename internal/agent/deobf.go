package agent

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
	"strings"
)

// Payload unwrapping.
//
// A packed shell looks almost innocuous on the surface: one decoder call and a
// long opaque string. Scoring only the wrapper means judging a file by its
// packaging rather than its contents — and the contents are the whole point.
// `eval(gzinflate(base64_decode('...')))` is a wrapper around something, and
// that something is what an analyst actually needs to see.
//
// So: find the encoded blobs, decode them, and re-run detection on the RESULT.
// Every signature and heuristic then applies to the real payload.
//
// This is attacker-controlled input driving a decompressor, so every step is
// bounded: output size, layer count, recursion depth, and total work.

const (
	// maxDecodedSize caps a single decode. Compression bombs are cheap to write
	// and this runs on live customer servers.
	maxDecodedSize = 8 << 20
	// maxLayers bounds how many distinct blobs are unwrapped per file.
	maxLayers = 6
	// maxDepth bounds nesting: shells are commonly double-wrapped, rarely more.
	maxDepth = 3
	// minBlobLen is the shortest run worth attempting.
	minBlobLen = 48
)

// DecodedLayer is one successfully unwrapped payload.
type DecodedLayer struct {
	// Via describes the transform chain, e.g. "base64 → gzinflate".
	Via string
	// Depth is 1 for a directly encoded blob, 2 for a blob inside that, etc.
	Depth int
	// At is the byte offset of the encoded blob in the ORIGINAL file.
	At int
	// Data is the decoded payload.
	Data []byte
}

// deobfuscate finds encoded blobs and unwraps them.
//
// String literals are preferred over raw byte runs: that is where a packer puts
// its payload, and it avoids wasting the budget on base64-looking runs inside
// minified JavaScript or binary assets.
func deobfuscate(src []byte, v *phpView) []DecodedLayer {
	var out []DecodedLayer
	budget := maxLayers

	var walk func(data []byte, baseOffset, depth int, prefix string)
	walk = func(data []byte, baseOffset, depth int, prefix string) {
		if depth > maxDepth || budget <= 0 {
			return
		}
		for _, blob := range findEncodedBlobs(data, v, depth) {
			if budget <= 0 {
				return
			}
			decoded, via, ok := tryDecode(blob.bytes)
			if !ok {
				continue
			}
			// Only report payloads that look like something worth executing.
			// Decoded noise (a licence key, a serialised blob, an image) is not
			// evidence of anything.
			if !looksLikeCode(decoded) {
				// Still recurse: a wrapper may itself contain a wrapper.
				if depth < maxDepth {
					walk(decoded, baseOffset+blob.at, depth+1, joinVia(prefix, via))
				}
				continue
			}
			budget--
			out = append(out, DecodedLayer{
				Via:   joinVia(prefix, via),
				Depth: depth,
				At:    baseOffset + blob.at,
				Data:  decoded,
			})
			// Peel the next layer.
			walk(decoded, baseOffset+blob.at, depth+1, joinVia(prefix, via))
		}
	}

	walk(src, 0, 1, "")

	// Encrypted payloads are a separate recovery path: they need the key
	// resolved out of the file body rather than a fixed transform chain.
	out = append(out, findDecryptedPayloads(src, v)...)
	return out
}

func joinVia(prefix, via string) string {
	if prefix == "" {
		return via
	}
	return prefix + " → " + via
}

type blobRef struct {
	bytes []byte
	at    int
}

// findEncodedBlobs locates candidate encoded runs. At depth 1 it uses the
// lexer's string spans; deeper layers have no lexer view, so it falls back to
// scanning for long encoded runs.
func findEncodedBlobs(data []byte, v *phpView, depth int) []blobRef {
	var out []blobRef

	if depth == 1 && v != nil && len(v.strs) > 0 {
		for _, s := range v.strs {
			if s.end <= s.start || s.start >= len(data) {
				continue
			}
			end := s.end
			if end > len(data) {
				end = len(data)
			}
			if end-s.start < minBlobLen {
				continue
			}
			candidate := data[s.start:end]
			if isEncodedRun(candidate) {
				out = append(out, blobRef{bytes: candidate, at: s.start})
			}
			if len(out) >= maxLayers*2 {
				break
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	// Fallback: longest encoded-looking runs anywhere in the data.
	off, length := longestEncodedRun(data)
	if length >= minBlobLen {
		out = append(out, blobRef{bytes: data[off : off+length], at: off})
	}
	return out
}

// isEncodedRun reports whether a byte slice is plausibly base64. Requiring a
// high proportion of alphabet characters keeps ordinary prose and code out.
func isEncodedRun(b []byte) bool {
	if len(b) < minBlobLen {
		return false
	}
	var alpha, other int
	for _, c := range b {
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_':
			alpha++
		case c == '\n' || c == '\r' || c == ' ' || c == '\t':
			// Wrapped base64 is common; ignore layout.
		default:
			other++
		}
	}
	if alpha < minBlobLen {
		return false
	}
	// Allow a little slack for stray characters, but a run that is mostly other
	// things is just text.
	return other*20 < alpha
}

// tryDecode attempts base64 (several alphabets) and then the compression
// wrappers PHP exposes, returning the first result that yields plausible data.
func tryDecode(blob []byte) ([]byte, string, bool) {
	clean := stripLayout(blob)
	if len(clean) < minBlobLen {
		return nil, "", false
	}

	encodings := []struct {
		name string
		enc  *base64.Encoding
	}{
		{"base64", base64.StdEncoding},
		{"base64", base64.RawStdEncoding},
		{"base64url", base64.URLEncoding},
		{"base64url", base64.RawURLEncoding},
	}

	for _, e := range encodings {
		decoded, err := e.enc.DecodeString(string(clean))
		if err != nil || len(decoded) == 0 {
			continue
		}
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		// The decoded bytes may themselves be compressed. PHP's gzinflate is raw
		// DEFLATE, gzuncompress is zlib, gzdecode is gzip — try each.
		if inflated, how, ok := tryInflate(decoded); ok {
			return inflated, e.name + " → " + how, true
		}
		if looksTextual(decoded) {
			return decoded, e.name, true
		}
		// ROT13 after base64 is a common cheap extra layer.
		if r := rot13(decoded); looksLikeCode(r) {
			return r, e.name + " → str_rot13", true
		}
		// Return it anyway; the caller decides whether it is interesting.
		return decoded, e.name, true
	}

	// Some packers rot13 the base64 itself.
	if r := rot13(clean); len(r) >= minBlobLen {
		if decoded, err := base64.StdEncoding.DecodeString(string(r)); err == nil && len(decoded) > 0 {
			if len(decoded) > maxDecodedSize {
				decoded = decoded[:maxDecodedSize]
			}
			if inflated, how, ok := tryInflate(decoded); ok {
				return inflated, "str_rot13 → base64 → " + how, true
			}
			if looksTextual(decoded) {
				return decoded, "str_rot13 → base64", true
			}
		}
	}
	return nil, "", false
}

// tryInflate attempts the three decompressors PHP exposes.
func tryInflate(b []byte) ([]byte, string, bool) {
	type attempt struct {
		name string
		open func([]byte) (io.ReadCloser, error)
	}
	attempts := []attempt{
		{"gzinflate", func(d []byte) (io.ReadCloser, error) {
			return flate.NewReader(bytes.NewReader(d)), nil
		}},
		{"gzuncompress", func(d []byte) (io.ReadCloser, error) {
			return zlib.NewReader(bytes.NewReader(d))
		}},
		{"gzdecode", func(d []byte) (io.ReadCloser, error) {
			return gzip.NewReader(bytes.NewReader(d))
		}},
	}
	for _, a := range attempts {
		rc, err := a.open(b)
		if err != nil {
			continue
		}
		// LimitReader is the compression-bomb guard: a few hundred bytes can
		// expand to gigabytes, and this runs on a live web server.
		out, err := io.ReadAll(io.LimitReader(rc, maxDecodedSize))
		rc.Close()
		if err != nil && len(out) == 0 {
			continue
		}
		if len(out) > 0 && looksTextual(out) {
			return out, a.name, true
		}
	}
	return nil, "", false
}

func stripLayout(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case '\n', '\r', '\t', ' ':
		default:
			out = append(out, c)
		}
	}
	return out
}

func rot13(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		default:
			out[i] = c
		}
	}
	return out
}

// looksTextual is a cheap filter: decoded output that is mostly unprintable is
// an image or a binary, not a payload worth re-scanning.
func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	sample := b
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	printable := 0
	for _, c := range sample {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*10 >= len(sample)*8
}

// codeMarkers are tokens whose presence in decoded output indicates executable
// PHP rather than decoded data.
var codeMarkers = []string{
	"<?php", "<?=", "eval(", "assert(", "$_post", "$_get", "$_request",
	"$_cookie", "$_server", "$_files", "shell_exec", "passthru", "system(",
	"base64_decode", "gzinflate", "preg_replace", "function ", "echo ",
	"file_put_contents", "move_uploaded_file", "create_function", "proc_open",
	"str_rot13", "php://input",
}

// looksLikeCode decides whether a decoded payload is worth reporting and
// rescanning. Deliberately conservative: unwrapping a licence blob or a
// serialised option and calling it malware would be worse than missing it.
func looksLikeCode(b []byte) bool {
	if !looksTextual(b) {
		return false
	}
	if bytes.Contains(b, []byte("<?php")) || bytes.Contains(b, []byte("<?=")) {
		return true
	}
	sample := b
	if len(sample) > 64<<10 {
		sample = sample[:64<<10]
	}
	lower := bytes.ToLower(sample)
	hits := 0
	for _, m := range codeMarkers {
		if bytes.Contains(lower, []byte(m)) {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	return false
}

// summarizeLayers renders the transform chains for an operator.
func summarizeLayers(layers []DecodedLayer) string {
	seen := map[string]bool{}
	var parts []string
	for _, l := range layers {
		if seen[l.Via] {
			continue
		}
		seen[l.Via] = true
		parts = append(parts, l.Via)
	}
	return strings.Join(parts, "; ")
}
