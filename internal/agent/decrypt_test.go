package agent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Self-decrypting shells.
//
// The shape these tests target is one seen in the field: base64 on the outside,
// AES in the middle, base64 again on the inside, with the key sitting in the
// file body. A signature scanner sees one opaque string. Scoring the wrapper
// tells an analyst only that something is encrypted.
//
// As elsewhere in this package, payload fragments are assembled at runtime so
// this source file never contains a contiguous shell on disk.

// aesEncryptCBC produces what the PHP side would have to decrypt.
func aesEncryptCBC(t *testing.T, key, iv, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(plain, block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out
}

func pkcs7Pad(b []byte, size int) []byte {
	n := size - len(b)%size
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

// buildAESShell returns PHP matching: base64 -> AES-256-CBC -> base64 -> code.
//
// keyExpr is the PHP expression the file uses to produce the key, so the same
// ciphertext can be tested with the key written as a plain literal or built up
// through transforms the constant folder has to unwind.
func buildAESShell(t *testing.T, key, iv []byte, keyExpr string) string {
	t.Helper()
	inner := innerShell()
	// The plaintext is itself base64 — the "and base64 again" layer.
	innerB64 := base64.StdEncoding.EncodeToString([]byte(inner))
	ct := aesEncryptCBC(t, key, iv, []byte(innerB64))
	// openssl_decrypt with options=0 expects base64, so PHP performs the outer
	// decode itself. That is where the outermost base64 layer comes from.
	blob := base64.StdEncoding.EncodeToString(ct)

	return fmt.Sprintf("%s\n$k = %s;\n$iv = '%s';\n$p = openssl_decrypt('%s', 'AES-256-CBC', $k, 0, $iv);\n%s(%s($p));\n",
		open, keyExpr, string(iv), blob, kEval, kB64)
}

func TestAESPackedShellIsDecrypted(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes, AES-256
	iv := []byte("aaaaaaaaaaaaaaaa")                  // 16 bytes

	cases := []struct {
		name    string
		keyExpr string
	}{
		{
			"key as a plain literal",
			"'" + string(key) + "'",
		},
		{
			"key built with base64_decode",
			"base64_" + "decode('" + base64.StdEncoding.EncodeToString(key) + "')",
		},
		{
			"key assembled by concatenation",
			"'" + string(key[:16]) + "' . '" + string(key[16:]) + "'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := buildAESShell(t, key, iv, tc.keyExpr)
			h := scoreFile(t, "wp-content/plugins/p/enc.php", content)
			if h == nil {
				t.Fatalf("encrypted shell not detected at all")
			}
			if len(h.Layers) == 0 {
				t.Fatalf("payload was not decrypted (score %d): %s",
					h.Score, strings.Join(h.Reasons, "; "))
			}

			chain := summarizeLayers(h.Layers)
			t.Logf("score=%d severity=%s\n  chain: %s", h.Score, h.Severity, chain)

			// The recovered plaintext must be the real shell, not the wrapper.
			recovered := false
			for _, l := range h.Layers {
				if bytes.Contains(l.Data, []byte(kPost)) && bytes.Contains(l.Data, []byte(kEval)) {
					recovered = true
					t.Logf("  recovered: %s", truncate(string(l.Data), 160))
				}
			}
			if !recovered {
				t.Errorf("decrypted, but the inner shell was not recovered; chain was %q", chain)
			}
			if !strings.Contains(chain, "openssl_decrypt") {
				t.Errorf("chain %q does not name the decrypt call", chain)
			}
			// The key belongs in the report: an analyst wants to decrypt the
			// other samples in the estate themselves.
			if !strings.Contains(chain, "key") {
				t.Errorf("chain %q does not report the recovered key", chain)
			}
		})
	}
}

// XOR is the most common hand-rolled "encryption" in shells, and it has no
// decrypt CALL to find — so it exercises the speculative path.
func TestXORPackedShellIsRecovered(t *testing.T) {
	key := []byte("s3cr3tk3y")
	inner := innerShell()
	ct := xorBytes([]byte(inner), key)
	blob := base64.StdEncoding.EncodeToString(ct)

	content := fmt.Sprintf(`%s
$k = '%s';
$d = %s('%s');
$o = '';
for ($i = 0; $i < strlen($d); $i++) { $o .= $d[$i] ^ $k[$i %% strlen($k)]; }
%s($o);
`, open, string(key), kB64, blob, kEval)

	h := scoreFile(t, "wp-content/plugins/p/xor.php", content)
	if h == nil {
		t.Fatal("XOR-packed shell not detected")
	}
	if len(h.Layers) == 0 {
		t.Fatalf("payload not recovered (score %d): %s", h.Score, strings.Join(h.Reasons, "; "))
	}
	found := false
	for _, l := range h.Layers {
		if bytes.Contains(l.Data, []byte(kEval)) {
			found = true
		}
	}
	if !found {
		t.Errorf("XOR payload not recovered; chain was %q", summarizeLayers(h.Layers))
	} else {
		t.Logf("recovered via %s", summarizeLayers(h.Layers))
	}
}

// The honest boundary. When the key arrives in the request there is nothing in
// the file to decrypt with, and no amount of analysis changes that. What must
// NOT happen is the file going unreported: input flowing into a decrypt and
// then into eval is a textbook taint path.
func TestKeyFromRequestCannotBeDecryptedButIsStillFlagged(t *testing.T) {
	content := fmt.Sprintf("%s\n$k = %s['k'];\n$p = openssl_decrypt('%s', 'AES-256-CBC', $k, 0, 'aaaaaaaaaaaaaaaa');\n%s($p);\n",
		open, kPost, strings.Repeat("QUJDRA", 20), kEval)

	h := scoreFile(t, "wp-content/plugins/p/reqkey.php", content)
	if h == nil {
		t.Fatal("a shell whose key arrives in the request went entirely unreported")
	}
	if !h.Tainted {
		t.Error("expected the taint path (request input -> decrypt -> eval) to be traced")
	}
	if h.Severity != "critical" && h.Severity != "high" {
		t.Errorf("severity %s (score %d); this should still rate high or critical",
			h.Severity, h.Score)
	}
	t.Logf("undecryptable but detected: score=%d severity=%s\n  %s",
		h.Score, h.Severity, strings.Join(h.Reasons, "\n  "))
}

// The constant folder is the load-bearing part; the cryptography is trivial.
func TestConstantFolderResolvesKeyExpressions(t *testing.T) {
	secret := "supersecret"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))

	cases := []struct{ name, expr, want string }{
		{"literal", "'" + secret + "'", secret},
		{"concatenation", "'super' . 'secret'", secret},
		{"base64_decode", "base64_" + "decode('" + b64 + "')", secret},
		{"nested transforms", "base64_" + "decode(base64_" + "encode_placeholder", ""},
		{"strrev", "strrev('" + reverseString(secret) + "')", secret},
		{"hex2bin", "hex2bin('" + toHex(secret) + "')", secret},
		{"trim of a literal", "trim('  " + secret + "  ')", secret},
	}

	for _, tc := range cases {
		if tc.want == "" {
			continue // placeholder row, exercised elsewhere
		}
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(open + "\n$k = " + tc.expr + ";\n")
			view := lexPHP(src, nil)
			r := newConstResolver(src, view)
			got, ok := r.resolveVar("k")
			if !ok {
				t.Fatalf("could not fold %s", tc.expr)
			}
			if string(got) != tc.want {
				t.Errorf("folded to %q, want %q", got, tc.want)
			}
		})
	}
}

// An expression the folder cannot resolve must fail cleanly rather than
// guessing — a wrong key silently produces garbage.
func TestConstantFolderRefusesUnresolvable(t *testing.T) {
	for _, expr := range []string{
		kPost + "['k']",
		"file_get_contents('/etc/passwd')",
		"$undefined_variable",
		"SOME_CONSTANT",
	} {
		src := []byte(open + "\n$k = " + expr + ";\n")
		view := lexPHP(src, nil)
		r := newConstResolver(src, view)
		if v, ok := r.resolveVar("k"); ok {
			t.Errorf("folded %q to %q; it should be unresolvable", expr, v)
		}
	}
}

// Every input here is attacker-controlled, including key and IV lengths.
// crypto/cipher panics on a ciphertext that is not a whole number of blocks, so
// this must be guarded rather than merely unlikely.
func TestDecryptRejectsMalformedInputWithoutPanicking(t *testing.T) {
	cases := []struct {
		name          string
		cipher        string
		key, iv, data []byte
	}{
		{"empty key", "aes-256-cbc", nil, make([]byte, 16), make([]byte, 32)},
		{"short key is zero-padded", "aes-256-cbc", []byte("k"), make([]byte, 16), make([]byte, 32)},
		{"over-long key is truncated", "aes-128-cbc", bytes.Repeat([]byte("k"), 200), make([]byte, 16), make([]byte, 32)},
		{"short IV is zero-padded", "aes-256-cbc", bytes.Repeat([]byte("k"), 32), []byte("x"), make([]byte, 32)},
		{"ciphertext not a whole block", "aes-256-cbc", bytes.Repeat([]byte("k"), 32), make([]byte, 16), make([]byte, 31)},
		{"empty ciphertext", "aes-256-cbc", bytes.Repeat([]byte("k"), 32), make([]byte, 16), nil},
		{"unknown cipher", "blowfish-cbc", bytes.Repeat([]byte("k"), 32), make([]byte, 16), make([]byte, 32)},
		{"garbage cipher name", "\x00\xff not a cipher", nil, nil, make([]byte, 16)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on attacker-controlled input: %v", r)
				}
			}()
			decryptAES(tc.cipher, tc.key, tc.iv, tc.data)
		})
	}
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func toHex(s string) string {
	var sb strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}
