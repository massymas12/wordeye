// Package authn implements operator authentication primitives: password
// hashing, TOTP second factors, and recovery codes.
//
// Everything here is stdlib. Go 1.24 moved PBKDF2 into crypto/pbkdf2, and TOTP
// is HMAC-SHA1 with a truncation rule, so a console with mandatory MFA costs no
// third-party dependency and no supply-chain surface.
package authn

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

// Iterations follows OWASP's PBKDF2-HMAC-SHA256 guidance. Stored per-hash so
// the figure can be raised later without invalidating existing credentials.
const Iterations = 600_000

const saltLen = 32
const keyLen = 32

// HashPassword returns (hashHex, saltHex, iterations).
func HashPassword(password string) (string, string, int, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", 0, err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, Iterations, keyLen)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(dk), hex.EncodeToString(salt), Iterations, nil
}

// VerifyPassword is constant-time with respect to the derived key.
func VerifyPassword(password, hashHex, saltHex string, iter int) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	if iter <= 0 {
		iter = Iterations
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// PasswordPolicy rejects the credentials that actually get consoles breached.
// Length is the dominant factor, so the floor is high rather than the rules
// being fussy about character classes.
func PasswordPolicy(pw string) error {
	if len([]rune(pw)) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	if len(pw) > 1024 {
		return fmt.Errorf("password is too long")
	}
	lower := strings.ToLower(pw)
	for _, bad := range []string{"password", "wordeye", "changeme", "letmein", "12345678", "qwerty"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("password contains a common, easily guessed word")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------

const (
	totpPeriod = 30
	totpDigits = 6
	// Accept one step either side, covering clock skew between the console and
	// the operator's phone without meaningfully widening the attack window.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a base32 secret of the size RFC 4226 recommends.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPCode computes the code for a given time.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}
	counter := uint64(t.Unix()) / totpPeriod

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 §5.3.
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3]))
	code %= 1_000_000
	return fmt.Sprintf("%0*d", totpDigits, code), nil
}

// VerifyTOTP checks a submitted code against the accepted window.
//
// Comparison is constant-time. Callers must additionally enforce single-use per
// time step (see store.ConsumeTOTP) — without that, an intercepted code can be
// replayed for the remainder of its validity.
func VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	now := time.Now()
	for i := -totpSkew; i <= totpSkew; i++ {
		want, err := TOTPCode(secret, now.Add(time.Duration(i)*totpPeriod*time.Second))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// TOTPStep identifies the time step a code belongs to, so a used code can be
// pinned and refused on replay.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// OTPAuthURL builds the otpauth:// URI an authenticator app consumes.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// Excludes visually ambiguous characters, because these get transcribed by hand
// under pressure, usually when someone has lost their phone mid-incident.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes returns n single-use codes in plaintext. Only their hashes
// should be stored.
func NewRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for j := 0; j < 10; j++ {
			if j == 5 {
				sb.WriteByte('-')
			}
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(recoveryAlphabet))))
			if err != nil {
				return nil, err
			}
			sb.WriteByte(recoveryAlphabet[idx.Int64()])
		}
		out = append(out, sb.String())
	}
	return out, nil
}

// HashRecoveryCode normalises then hashes. Normalisation means a code typed
// with different spacing or case still works.
func HashRecoveryCode(code string) string {
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
