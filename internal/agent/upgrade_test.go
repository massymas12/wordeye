package agent

import (
	"testing"

	"wordeye/internal/sign"
)

// Version comparison is a security control, not a convenience.
//
// Signature verification stops an attacker substituting their own code, but it
// does not stop someone who can choose WHICH signed build is served from
// pinning the fleet to an older release with a known hole. Every genuinely
// signed binary the project ever shipped is a candidate, so the agent has to
// refuse to move backwards on its own.
func TestUpgradeRefusesDowngrades(t *testing.T) {
	cases := []struct {
		candidate, running string
		want               bool
	}{
		{"0.7.1", "0.7.0", true},
		{"0.8.0", "0.7.9", true},
		{"1.0.0", "0.9.9", true},
		{"0.7.0", "0.7.0", false}, // same version is not an upgrade
		{"0.6.9", "0.7.0", false}, // the attack: pin to something older
		{"0.7.0", "0.7.1", false},
		{"0.9.0", "1.0.0", false},
	}
	for _, c := range cases {
		if got := isNewerVersion(c.candidate, c.running); got != c.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", c.candidate, c.running, got, c.want)
		}
	}
}

// Anything unparseable must be treated as not-an-upgrade. A version string the
// agent cannot reason about is not a reason to replace its own binary.
func TestUnparseableVersionsAreNotUpgrades(t *testing.T) {
	for _, c := range []struct{ candidate, running string }{
		{"", "0.7.0"},
		{"0.7.0", ""},
		{"latest", "0.7.0"},
		{"0.7.x", "0.7.0"},
		{"9999999999999999999999", "0.7.0"},
		{"0.7.0.1.2", "0.7.0"},
	} {
		if isNewerVersion(c.candidate, c.running) {
			t.Errorf("isNewerVersion(%q, %q) accepted an unparseable version", c.candidate, c.running)
		}
	}
}

// Pre-release and build suffixes are ignored rather than rejected, so a build
// tagged 0.8.0-rc1 still counts as newer than 0.7.0.
func TestVersionSuffixesAreIgnored(t *testing.T) {
	if !isNewerVersion("0.8.0-rc1", "0.7.0") {
		t.Error("a release-candidate suffix defeated the comparison")
	}
	if isNewerVersion("0.6.0+build9", "0.7.0") {
		t.Error("a build suffix let an older version through")
	}
}

// An agent with no pinned key cannot distinguish a genuine release from a
// hostile one, so it must refuse rather than trust whichever console answered.
func TestUpgradeRefusedWithoutAPinnedKey(t *testing.T) {
	c := &Client{cfg: ClientConfig{SigningKey: ""}}
	if _, err := c.SelfUpgrade(t.Context()); err == nil {
		t.Fatal("an agent with no signing key attempted an upgrade")
	}
}

// The security boundary, end to end at the verification step: bytes the build
// key did not sign must never be installed, however they were obtained.
func TestOnlyTheEstateBuildKeyIsAccepted(t *testing.T) {
	estatePub, estatePriv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, _ := sign.GenerateKey()

	release := []byte("\x7fELF a new agent build")

	good, _ := sign.Sign(estatePriv, release)
	if !sign.Verify(estatePub, release, good) {
		t.Fatal("a release signed by the estate key did not verify")
	}

	// A console that has been taken over signs its own build.
	forged, _ := sign.Sign(attackerPriv, []byte("\x7fELF hostile agent"))
	if sign.Verify(estatePub, []byte("\x7fELF hostile agent"), forged) {
		t.Fatal("a release signed by an attacker key was accepted")
	}
	// Or serves the genuine signature over different bytes.
	if sign.Verify(estatePub, []byte("\x7fELF hostile agent"), good) {
		t.Fatal("a genuine signature validated hostile bytes")
	}
}
