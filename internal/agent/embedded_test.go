package agent

import (
	"bytes"
	"strings"
	"testing"
)

// Stamped installers.
//
// The console appends a config to a copy of the release binary so an
// administrator runs one file with no arguments. Two properties matter beyond
// "it round-trips": the executable image must be untouched, and the stamp must
// never be able to grant remote containment.

func TestStampRoundTrip(t *testing.T) {
	src := []byte("\x7fELF" + strings.Repeat("machine code", 500))
	cfg := EmbeddedConfig{
		Server: "https://console.example.com:8444",
		Token:  "wek_abc123",
		Label:  "client-web-01",
		Estate: "Acme Ltd",
	}
	var out bytes.Buffer
	if err := Stamp(&out, src, cfg); err != nil {
		t.Fatal(err)
	}
	got, ok := parseTrailer(out.Bytes())
	if !ok {
		t.Fatal("stamped binary did not parse")
	}
	if got.Server != cfg.Server || got.Token != cfg.Token || got.Estate != cfg.Estate {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

// The executable image must be byte-identical, or the binary will not run and
// its hash can no longer be compared against a published release.
func TestStampLeavesImageIntact(t *testing.T) {
	src := []byte("\x7fELF" + strings.Repeat("x", 4096))
	var out bytes.Buffer
	if err := Stamp(&out, src, EmbeddedConfig{Server: "https://c", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out.Bytes(), src) {
		t.Error("the executable image was modified by stamping")
	}
	if out.Len() <= len(src) {
		t.Error("nothing was appended")
	}
}

// An ordinary build must be recognised as unstamped rather than misparsed.
func TestUnstampedBinaryParsesAsAbsent(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		[]byte("short"),
		[]byte(strings.Repeat("no trailer here", 1000)),
	} {
		if _, ok := parseTrailer(b); ok {
			t.Errorf("unstamped input reported a config (%d bytes)", len(b))
		}
	}
}

// A truncated or corrupted trailer must not panic or half-load.
func TestCorruptTrailerIsRejected(t *testing.T) {
	src := []byte("\x7fELF" + strings.Repeat("x", 2048))
	var out bytes.Buffer
	if err := Stamp(&out, src, EmbeddedConfig{Server: "https://c", Token: "t"}); err != nil {
		t.Fatal(err)
	}
	full := out.Bytes()

	// Magic intact, declared length absurd.
	bad := append([]byte{}, full...)
	copy(bad[len(bad)-len(embedMagic)-4:], []byte{0xff, 0xff, 0xff, 0x7f})
	if _, ok := parseTrailer(bad); ok {
		t.Error("a trailer with an absurd length was accepted")
	}

	// Truncated mid-config.
	if _, ok := parseTrailer(full[:len(full)-8]); ok {
		t.Error("a truncated trailer was accepted")
	}

	// Corrupted JSON body.
	bad2 := append([]byte{}, full...)
	bad2[len(bad2)-len(embedMagic)-8] ^= 0xff
	if cfg, ok := parseTrailer(bad2); ok && cfg.Server == "https://c" {
		t.Error("a corrupted config body round-tripped unchanged")
	}
}

// Double-stamping would bury a live token in the file while the reader used
// only the outermost one.
func TestDoubleStampRefused(t *testing.T) {
	src := []byte("\x7fELF" + strings.Repeat("x", 1024))
	var once bytes.Buffer
	if err := Stamp(&once, src, EmbeddedConfig{Server: "https://c", Token: "t1"}); err != nil {
		t.Fatal(err)
	}
	var twice bytes.Buffer
	if err := Stamp(&twice, once.Bytes(), EmbeddedConfig{Server: "https://c", Token: "t2"}); err == nil {
		t.Error("stamping an already-stamped binary was allowed")
	}
}

// A config that could not enroll must fail loudly at stamp time rather than
// producing a file that looks fine and silently does nothing.
func TestStampRejectsUnusableConfig(t *testing.T) {
	src := []byte("\x7fELF")
	for _, cfg := range []EmbeddedConfig{
		{Token: "t"},          // no server
		{Server: "https://c"}, // no token
		{},                    // neither
	} {
		var out bytes.Buffer
		if err := Stamp(&out, src, cfg); err == nil {
			t.Errorf("accepted an unusable config: %+v", cfg)
		}
	}
}

// The security invariant: there is no field by which a stamped installer can
// pre-authorise destruction of the host that runs it. If this test has to
// change, the two-key containment rule is being weakened — which requires a
// deliberate decision, not an incidental edit.
func TestEmbeddedConfigCannotGrantContainment(t *testing.T) {
	cfg := EmbeddedConfig{Server: "https://c", Token: "t"}
	var out bytes.Buffer
	if err := Stamp(&out, []byte("\x7fELF"), cfg); err != nil {
		t.Fatal(err)
	}
	// Serialised form must contain no containment grant under any spelling.
	blob := strings.ToLower(out.String())
	for _, forbidden := range []string{"contain", "allow_remote", "destruct"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("stamped config mentions %q — containment must not be grantable by a file", forbidden)
		}
	}
}
