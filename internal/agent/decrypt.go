package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Self-decrypting payloads.
//
// The interesting case in practice looks like this:
//
//	$k  = 'somekeymaterial';
//	$iv = 'sixteenbyteiv...';
//	$p  = openssl_decrypt('<base64 ciphertext>', 'AES-256-CBC', $k, 0, $iv);
//	eval($p);
//
// Often with another base64 layer inside, because the plaintext is itself
// encoded. Nothing here can be read by a signature scanner, and scoring the
// wrapper tells an analyst only that "something is encrypted".
//
// But a shell that decrypts itself must CARRY its own key. When the key is in
// the body it is always recoverable — the difficulty is never the cryptography,
// it is resolving `$k` back to bytes (see phpconst.go). Once resolved, the
// decryption is microseconds.
//
// Two strategies, in order of confidence:
//
//  1. Directed. Find the decrypt call, resolve its arguments, decrypt exactly
//     as PHP would. High confidence, names the cipher and key in the finding.
//  2. Speculative. When the call cannot be resolved, try candidate keys drawn
//     from the file's own literals against its encoded blobs. Cheap, and safe
//     because a result is only reported if it looks like code — a wrong key
//     yields noise, which is silently discarded.

const (
	// maxDecryptAttempts bounds speculative work.
	maxDecryptAttempts = 120
	// maxCiphertext bounds a DIRECTED decryption, where the cipher and key are
	// known and exactly one pass is performed.
	maxCiphertext = 2 << 20
	// maxSpeculativeCiphertext is far smaller, because speculative work runs
	// the full key/cipher matrix over the buffer. A 2 MB blob times 120
	// attempts is minutes of pointless crypto; a real packed shell's payload is
	// comfortably under this.
	maxSpeculativeCiphertext = 256 << 10
)

var (
	opensslDecryptRe = regexp.MustCompile(`openssl_decrypt\s*\(`)
	mcryptDecryptRe  = regexp.MustCompile(`mcrypt_decrypt\s*\(`)
)

// findDecryptedPayloads returns payloads recovered from in-file cryptography.
func findDecryptedPayloads(src []byte, view *phpView) []DecodedLayer {
	// Cheap gate: no decrypt call and no crypto-shaped words means nothing to do.
	hasCall := opensslDecryptRe.Match(view.code) || mcryptDecryptRe.Match(view.code)
	if !hasCall && !mightBeXORPacked(view.code) {
		return nil
	}

	r := newConstResolver(src, view)
	var out []DecodedLayer

	if hasCall {
		out = append(out, directedDecrypt(src, view, r)...)
	}
	// Speculative work is only worth doing when there is actually something
	// encoded to decrypt. Establishing that first is cheap and skips the
	// expensive key/cipher matrix entirely for ordinary files.
	if len(out) == 0 && len(candidateCiphertexts(src, view)) > 0 {
		out = append(out, speculativeDecrypt(src, view, r)...)
	}
	return out
}

// directedDecrypt resolves the arguments of an actual decrypt call.
func directedDecrypt(src []byte, view *phpView, r *constResolver) []DecodedLayer {
	var out []DecodedLayer

	for _, form := range []struct {
		re   *regexp.Regexp
		name string
	}{
		{opensslDecryptRe, "openssl_decrypt"},
		{mcryptDecryptRe, "mcrypt_decrypt"},
	} {
		for _, loc := range form.re.FindAllIndex(view.code, 8) {
			open := bytes.IndexByte(src[loc[0]:loc[1]], '(')
			if open < 0 {
				continue
			}
			open += loc[0]
			closeIdx := matchParen(src, open, len(src))
			if closeIdx < 0 {
				continue
			}
			args := r.splitArgs(open+1, closeIdx)

			var data, cipherName, key, iv []byte
			var rawFlag bool

			if form.name == "openssl_decrypt" {
				// openssl_decrypt(data, cipher, key, options, iv)
				data, _ = r.arg(args, 0)
				cipherName, _ = r.arg(args, 1)
				key, _ = r.arg(args, 2)
				if opts, ok := r.intArg(args, 3); ok {
					rawFlag = opts&1 != 0 // OPENSSL_RAW_DATA
				}
				iv, _ = r.arg(args, 4)
			} else {
				// mcrypt_decrypt(cipher, key, data, mode, iv)
				cipherName, _ = r.arg(args, 0)
				key, _ = r.arg(args, 1)
				data, _ = r.arg(args, 2)
				mode, _ := r.arg(args, 3)
				iv, _ = r.arg(args, 4)
				cipherName = append(append(cipherName, '-'), mode...)
				rawFlag = true // mcrypt never base64-wraps
			}

			if len(key) == 0 || len(data) == 0 {
				continue
			}
			// Without OPENSSL_RAW_DATA, PHP base64-decodes the ciphertext for
			// you. That is the outer base64 in a "base64 → AES → base64" shell:
			// it is not the attacker being clever, it is the API default.
			if !rawFlag {
				if d, err := base64.StdEncoding.DecodeString(string(stripLayout(data))); err == nil {
					data = d
				}
			}
			if len(data) > maxCiphertext {
				data = data[:maxCiphertext]
			}

			plain, ok := decryptAES(string(cipherName), key, iv, data)
			if !ok {
				continue
			}
			// The plaintext is frequently base64 again.
			via := fmt.Sprintf("%s(%s)", form.name, strings.ToUpper(strings.TrimSpace(string(cipherName))))
			if !rawFlag {
				via = "base64 → " + via
			}
			if inner, ok := unwrapInnerEncoding(plain); ok {
				plain = inner
				via += " → base64"
			}
			if !looksLikeCode(plain) {
				continue
			}
			out = append(out, DecodedLayer{
				Via:   via + fmt.Sprintf(" [key %s]", keyPreview(key)),
				Depth: 1,
				At:    open,
				Data:  plain,
			})
		}
	}
	return out
}

// speculativeDecrypt tries the file's own literals as keys against its blobs.
//
// Safe because of the reporting gate: a wrong key produces high-entropy noise,
// looksLikeCode rejects it, and nothing is surfaced. Only a key that yields
// actual PHP is ever shown to an operator.
func speculativeDecrypt(src []byte, view *phpView, r *constResolver) []DecodedLayer {
	keys := candidateKeys(src, view, r)
	blobs := candidateCiphertexts(src, view)
	if len(keys) == 0 || len(blobs) == 0 {
		return nil
	}

	attempts := 0
	var out []DecodedLayer
	for _, blob := range blobs {
		for _, k := range keys {
			if attempts >= maxDecryptAttempts {
				return out
			}
			attempts++

			// XOR is the most common hand-rolled "encryption" in shells.
			if plain := xorBytes(blob.data, k.bytes); looksLikeCode(plain) {
				out = append(out, DecodedLayer{
					Via:   fmt.Sprintf("base64 → XOR [key %s]", keyPreview(k.bytes)),
					Depth: 1, At: blob.at, Data: plain,
				})
				return out
			}

			// AES with a zero IV, and with the leading block treated as the IV
			// (the two conventions shells actually use).
			for _, mode := range []string{"aes-256-cbc", "aes-128-cbc", "aes-256-ecb", "aes-128-ecb"} {
				if plain, ok := decryptAES(mode, k.bytes, nil, blob.data); ok && looksLikeCode(plain) {
					out = append(out, DecodedLayer{
						Via:   fmt.Sprintf("base64 → %s [key %s, zero IV]", strings.ToUpper(mode), keyPreview(k.bytes)),
						Depth: 1, At: blob.at, Data: plain,
					})
					return out
				}
				if len(blob.data) > aes.BlockSize {
					iv, body := blob.data[:aes.BlockSize], blob.data[aes.BlockSize:]
					if plain, ok := decryptAES(mode, k.bytes, iv, body); ok && looksLikeCode(plain) {
						out = append(out, DecodedLayer{
							Via:   fmt.Sprintf("base64 → %s [key %s, prefixed IV]", strings.ToUpper(mode), keyPreview(k.bytes)),
							Depth: 1, At: blob.at, Data: plain,
						})
						return out
					}
				}
			}
		}
	}
	return out
}

type candidateKey struct{ bytes []byte }
type candidateBlob struct {
	data []byte
	at   int
}

// candidateKeys gathers plausible key material from the file: every resolvable
// string literal of sensible length, plus md5 digests of them, since
// `md5('secret', true)` is a common way to reach 16 bytes.
func candidateKeys(src []byte, view *phpView, r *constResolver) []candidateKey {
	seen := map[string]bool{}
	var out []candidateKey

	add := func(b []byte) {
		if len(b) < 4 || len(b) > 64 {
			return
		}
		if seen[string(b)] {
			return
		}
		seen[string(b)] = true
		out = append(out, candidateKey{bytes: b})
	}

	for _, s := range view.strs {
		if len(out) >= 40 {
			break
		}
		if s.end <= s.start || s.end > len(src) {
			continue
		}
		lit := unescapePHP(src[s.start:s.end])
		if len(lit) == 0 || len(lit) > 64 {
			continue
		}
		add(lit)
		// Derived forms.
		sum := md5.Sum(lit)
		add(sum[:])
		add([]byte(hex.EncodeToString(sum[:])))
		if d, err := hex.DecodeString(string(lit)); err == nil && len(d) >= 8 {
			add(d)
		}
		if d, err := base64.StdEncoding.DecodeString(string(lit)); err == nil && len(d) >= 8 && len(d) <= 64 {
			add(d)
		}
	}

	// Anything the constant folder already resolved is a strong candidate.
	for _, v := range r.cache {
		add(v)
	}
	return out
}

// candidateCiphertexts finds encoded blobs and returns their decoded bytes.
func candidateCiphertexts(src []byte, view *phpView) []candidateBlob {
	var out []candidateBlob
	for _, s := range view.strs {
		if len(out) >= 6 {
			break
		}
		if s.end <= s.start || s.end > len(src) || s.end-s.start < minBlobLen {
			continue
		}
		raw := src[s.start:s.end]
		if !isEncodedRun(raw) {
			continue
		}
		d, err := base64.StdEncoding.DecodeString(string(stripLayout(raw)))
		if err != nil || len(d) < 16 {
			continue
		}
		if len(d) > maxSpeculativeCiphertext {
			// Truncating rather than skipping keeps the head of the payload,
			// which is where the PHP opening tag would be.
			d = d[:maxSpeculativeCiphertext]
		}
		out = append(out, candidateBlob{data: d, at: s.start})
	}
	return out
}

// decryptAES mirrors what PHP would do for the named cipher.
//
// Every path is guarded: an invalid key length, a short IV or a ciphertext that
// is not a whole number of blocks returns false rather than panicking. All three
// are attacker-controllable, and crypto/cipher panics on the last one.
func decryptAES(name string, key, iv, data []byte) ([]byte, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "rijndael-128-")

	keyLen := 0
	switch {
	case strings.Contains(name, "128"):
		keyLen = 16
	case strings.Contains(name, "192"):
		keyLen = 24
	case strings.Contains(name, "256"):
		keyLen = 32
	default:
		if !strings.HasPrefix(name, "aes") {
			return nil, false
		}
		keyLen = 32
	}
	if !strings.HasPrefix(name, "aes") {
		return nil, false
	}

	// OpenSSL zero-pads a short passphrase and truncates a long one.
	k := make([]byte, keyLen)
	copy(k, key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}
	bs := block.BlockSize()

	ivFull := make([]byte, bs)
	copy(ivFull, iv)

	if len(data) == 0 || len(data) > maxCiphertext {
		return nil, false
	}

	out := make([]byte, len(data))
	switch {
	case strings.Contains(name, "cbc"):
		if len(data)%bs != 0 {
			return nil, false
		}
		cipher.NewCBCDecrypter(block, ivFull).CryptBlocks(out, data)
	case strings.Contains(name, "ecb"):
		if len(data)%bs != 0 {
			return nil, false
		}
		for i := 0; i+bs <= len(data); i += bs {
			block.Decrypt(out[i:i+bs], data[i:i+bs])
		}
	case strings.Contains(name, "ctr"):
		cipher.NewCTR(block, ivFull).XORKeyStream(out, data)
	case strings.Contains(name, "ofb"):
		cipher.NewOFB(block, ivFull).XORKeyStream(out, data)
	case strings.Contains(name, "cfb"):
		cipher.NewCFBDecrypter(block, ivFull).XORKeyStream(out, data)
	default:
		return nil, false
	}
	return stripPKCS7(out, bs), true
}

// stripPKCS7 removes block padding when it is well formed, and leaves the data
// untouched otherwise.
func stripPKCS7(b []byte, blockSize int) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n <= 0 || n > blockSize || n > len(b) {
		return b
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return b
		}
	}
	return b[:len(b)-n]
}

func xorBytes(data, key []byte) []byte {
	if len(key) == 0 || len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// unwrapInnerEncoding peels a base64 layer from decrypted plaintext, which is
// the common "base64 → AES → base64" shape.
func unwrapInnerEncoding(plain []byte) ([]byte, bool) {
	t := stripLayout(plain)
	if len(t) < minBlobLen || !isEncodedRun(t) {
		return nil, false
	}
	d, err := base64.StdEncoding.DecodeString(string(t))
	if err != nil {
		d, err = base64.RawStdEncoding.DecodeString(string(t))
		if err != nil {
			return nil, false
		}
	}
	if !looksTextual(d) {
		return nil, false
	}
	return d, true
}

// mightBeXORPacked looks for the shape of a hand-rolled stream cipher: an XOR,
// inside a loop, operating on an indexed string.
//
// The first version asked only for "^" plus "strlen(" or "substr(" — which is
// true of most of WordPress core. Measured in the field, that sent nearly every
// PHP file through up to 240 speculative AES/XOR attempts and was the dominant
// cost in a scan that failed to finish. All three elements are now required,
// and the XOR must actually sit near an index expression.
func mightBeXORPacked(code []byte) bool {
	if !bytes.Contains(code, []byte("^")) {
		return false
	}
	hasLoop := bytes.Contains(code, []byte("for(")) || bytes.Contains(code, []byte("for (")) ||
		bytes.Contains(code, []byte("while(")) || bytes.Contains(code, []byte("while ("))
	if !hasLoop {
		return false
	}
	return xorNearIndex(code)
}

// xorNearIndex reports whether any XOR operator sits close to a string-indexing
// or length expression, which is what a byte-wise cipher loop looks like.
func xorNearIndex(code []byte) bool {
	const window = 80
	checked := 0
	for off := 0; checked < 64; checked++ {
		i := bytes.IndexByte(code[off:], '^')
		if i < 0 {
			return false
		}
		at := off + i
		lo := at - window
		if lo < 0 {
			lo = 0
		}
		hi := at + window
		if hi > len(code) {
			hi = len(code)
		}
		near := code[lo:hi]
		if bytes.Contains(near, []byte("[$")) || bytes.Contains(near, []byte("strlen(")) ||
			bytes.Contains(near, []byte("substr(")) || bytes.Contains(near, []byte("ord(")) {
			return true
		}
		off = at + 1
		if off >= len(code) {
			return false
		}
	}
	return false
}

// keyPreview renders key material for an operator without dumping raw bytes
// into a report. Printable keys are shown; binary keys are hashed.
func keyPreview(k []byte) string {
	if len(k) == 0 {
		return "?"
	}
	printable := true
	for _, c := range k {
		if c < 0x20 || c > 0x7e {
			printable = false
			break
		}
	}
	if printable && len(k) <= 40 {
		return strconv.Quote(string(k))
	}
	sum := md5.Sum(k)
	return fmt.Sprintf("%d bytes, md5:%s", len(k), hex.EncodeToString(sum[:])[:12])
}
