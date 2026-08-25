// Package sign provides detached signatures for agent release binaries.
//
// This exists because of what self-update would otherwise be. Replacing the
// agent binary is strictly more powerful than anything else this product can
// do: containment deletes a file that an operator already reviewed, but an
// upgrade replaces the security control itself, on every host in the estate, in
// one action. If the console alone could authorise that, then compromising the
// console would mean arbitrary code execution on every customer's production
// server — and the console is the internet-facing component.
//
// So the console is deliberately not trusted to vouch for code. Releases are
// signed with a key that lives on a build machine and is never deployed; the
// agent carries only the PUBLIC half, stamped in at install time, and verifies
// every byte before it will run it. A console that has been taken over can
// serve whatever it likes and every agent refuses it.
//
// Ed25519 rather than RSA: small keys, small signatures, no parameter choices
// to get wrong, and constant-time verification in the standard library.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Prefixes make a key visible for what it is in a config file or an error
// message, and make it impossible to paste a private key where a public one
// belongs without it being obvious.
const (
	PublicPrefix  = "wordeye-pub-v1:"
	PrivatePrefix = "wordeye-priv-v1:"
)

// GenerateKey creates a signing keypair. The private half is for a build
// machine and must never be deployed to a console.
func GenerateKey() (pub, priv string, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return PublicPrefix + base64.StdEncoding.EncodeToString(pk),
		PrivatePrefix + base64.StdEncoding.EncodeToString(sk), nil
}

// Sign produces a detached signature over the exact bytes of a release.
func Sign(privKey string, data []byte) (string, error) {
	sk, err := decode(privKey, PrivatePrefix, ed25519.PrivateKeySize)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(sk), data)), nil
}

// Verify reports whether sig is a valid signature over data.
//
// Every failure mode returns false rather than an error the caller might treat
// as advisory: an unparseable key, a malformed signature and a genuine mismatch
// all mean the same thing here, which is that these bytes must not be executed.
func Verify(pubKey string, data []byte, sig string) bool {
	pk, err := decode(pubKey, PublicPrefix, ed25519.PublicKeySize)
	if err != nil {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), data, raw)
}

// PublicOf derives the public half of a private key, so a build script can
// print the value to stamp into installers without keeping a second file in
// sync with the first.
func PublicOf(privKey string) (string, error) {
	sk, err := decode(privKey, PrivatePrefix, ed25519.PrivateKeySize)
	if err != nil {
		return "", err
	}
	pk := ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)
	return PublicPrefix + base64.StdEncoding.EncodeToString(pk), nil
}

func decode(key, prefix string, want int) ([]byte, error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, prefix) {
		return nil, fmt.Errorf("not a %s key", strings.TrimSuffix(prefix, ":"))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(key, prefix))
	if err != nil {
		return nil, fmt.Errorf("key is not valid base64: %w", err)
	}
	if len(raw) != want {
		return nil, fmt.Errorf("key is %d bytes, expected %d", len(raw), want)
	}
	return raw, nil
}
