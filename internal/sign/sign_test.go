package sign

import (
	"strings"
	"testing"
)

// These tests are the whole security argument for self-update. If Verify can be
// made to return true for bytes the build machine did not sign, then a
// compromised console owns every host in the estate.

func TestSignedReleaseVerifies(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	release := []byte("\x7fELF pretend this is wordeye-agent-linux-amd64")
	sig, err := Sign(priv, release)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, release, sig) {
		t.Error("a genuinely signed release did not verify")
	}
}

// The case that matters: the console serves different bytes from the ones that
// were signed.
func TestTamperedReleaseIsRejected(t *testing.T) {
	pub, priv, _ := GenerateKey()
	release := []byte("\x7fELF genuine agent")
	sig, _ := Sign(priv, release)

	tampered := []byte("\x7fELF genuine agent\x00backdoor")
	if Verify(pub, tampered, sig) {
		t.Fatal("a modified binary verified against the original signature")
	}
	// A single flipped byte must be enough.
	oneBit := append([]byte(nil), release...)
	oneBit[len(oneBit)-1] ^= 0x01
	if Verify(pub, oneBit, sig) {
		t.Error("a one-byte change verified")
	}
}

// An attacker with their own keypair must not be able to sign a release the
// fleet accepts.
func TestSignatureFromAnotherKeyIsRejected(t *testing.T) {
	pub, _, _ := GenerateKey()
	_, attackerPriv, _ := GenerateKey()

	release := []byte("\x7fELF malicious agent")
	sig, err := Sign(attackerPriv, release)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, release, sig) {
		t.Fatal("a release signed by an unrelated key was accepted")
	}
}

// Every malformed input must fail closed. An agent that treats "I could not
// check" as "it is fine" has no signature check at all.
func TestMalformedInputsFailClosed(t *testing.T) {
	pub, priv, _ := GenerateKey()
	release := []byte("data")
	good, _ := Sign(priv, release)

	cases := []struct {
		name, pub, sig string
	}{
		{"empty key", "", good},
		{"empty signature", pub, ""},
		{"private key used as public", priv, good},
		{"key without prefix", strings.TrimPrefix(pub, PublicPrefix), good},
		{"key not base64", PublicPrefix + "!!!!not base64!!!!", good},
		{"truncated key", PublicPrefix + "AAAA", good},
		{"signature not base64", pub, "!!!!"},
		{"truncated signature", pub, "AAAA"},
	}
	for _, c := range cases {
		if Verify(c.pub, release, c.sig) {
			t.Errorf("%s: verified", c.name)
		}
	}
}

// An agent installed before signing existed carries no key. It must refuse
// upgrades rather than accept anything.
func TestNoPublicKeyMeansNoUpgrade(t *testing.T) {
	release := []byte("anything")
	if Verify("", release, "") {
		t.Error("an agent with no pinned key accepted an unsigned release")
	}
}

func TestPublicOfMatchesGeneratedPublic(t *testing.T) {
	pub, priv, _ := GenerateKey()
	derived, err := PublicOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	if derived != pub {
		t.Errorf("derived %q, generated %q", derived, pub)
	}
	if _, err := PublicOf(pub); err == nil {
		t.Error("PublicOf accepted a public key as private")
	}
}

// Keys must be self-describing, so a private key pasted where a public one
// belongs is obvious rather than silently wrong.
func TestKeysAreDistinguishable(t *testing.T) {
	pub, priv, _ := GenerateKey()
	if !strings.HasPrefix(pub, PublicPrefix) || !strings.HasPrefix(priv, PrivatePrefix) {
		t.Fatal("keys are not prefixed")
	}
	if strings.HasPrefix(pub, PrivatePrefix) {
		t.Error("a public key looks like a private one")
	}
}
