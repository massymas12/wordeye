package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Self-configuring binaries.
//
// The console stamps a configuration onto a copy of the agent so that a site
// administrator can run ONE file with NO arguments and have the host appear in
// the console. That is the difference between an estate that gets covered and
// one where the rollout stalls on a page of instructions.
//
// HOW
//
// The config is appended AFTER the executable image, followed by its length and
// a magic marker:
//
//	[ ELF/PE image ][ JSON config ][ uint32 length ][ 16-byte magic ]
//
// Both ELF and PE locate their contents through headers, so trailing bytes are
// ignored by the loader and the binary runs normally. It also means stamping is
// a copy and an append — the console needs no compiler, and the executable code
// is byte-identical to the release build, so its hash can still be compared
// against a published one over the image portion.
//
// WHAT IS DELIBERATELY NOT IN HERE
//
// A stamped config CANNOT grant remote containment. The two-key rule is that
// the console's token must permit it AND the host must opt in, so that console
// compromise alone can never order destruction across an estate. If a generated
// installer could carry both keys, the second one would be decorative — a
// stolen or leaked installer would arrive pre-authorised to destroy the host it
// lands on. Containment therefore stays an explicit act on the host.
//
// THE TOKEN IS A SECRET
//
// A stamped binary contains a live enrollment token. It is single-use and
// time-bounded, but until consumed anyone holding the file can enroll a host.
// Treat a generated installer like a credential, because it is one.

var embedMagic = []byte("WORDEYE-CFG-v1\x00\x00")

const (
	embedTrailerLen = 4 + 16 // uint32 length + magic
	embedMaxConfig  = 64 << 10
)

// EmbeddedConfig is the stamped enrollment instruction.
type EmbeddedConfig struct {
	// Server is the console base URL, e.g. https://console.example.com:8444.
	Server string `json:"server"`
	// Token is a single-use enrollment token minted when the installer was
	// generated.
	Token string `json:"token"`
	// Label identifies the host in the console when it has nothing better.
	Label string `json:"label,omitempty"`
	// Estate is recorded for display only; authority comes from the token.
	Estate string `json:"estate,omitempty"`
	// CAPEM pins the console's certificate authority, so a self-signed console
	// works without --insecure. Without this the agent uses the system roots;
	// it never falls back to skipping verification.
	CAPEM string `json:"ca_pem,omitempty"`

	// SigningKey is the PUBLIC half of the estate release key. It is stamped
	// into the installer so that a host can verify a future upgrade against the
	// build machine rather than trusting whichever console happens to answer.
	SigningKey string `json:"signing_key,omitempty"`
	// Monitor starts resident monitoring after enrollment rather than performing
	// a single scan and exiting.
	Monitor bool `json:"monitor,omitempty"`
	// GeneratedAt and GeneratedBy are provenance for the audit trail.
	GeneratedAt string `json:"generated_at,omitempty"`
	GeneratedBy string `json:"generated_by,omitempty"`
}

// Validate rejects a config that could not enroll, so a mis-stamped binary fails
// loudly at once rather than looking like a silent no-op.
func (c *EmbeddedConfig) Validate() error {
	if c.Server == "" {
		return errors.New("embedded config has no server")
	}
	if c.Token == "" {
		return errors.New("embedded config has no enrollment token")
	}
	return nil
}

// Stamp appends cfg to the executable in src and writes the result to w.
func Stamp(w io.Writer, src []byte, cfg EmbeddedConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Refuse to stamp something already stamped: the reader takes the LAST
	// trailer, so a double stamp would silently shadow the first and leave a
	// live token buried in the file.
	if _, ok := parseTrailer(src); ok {
		return errors.New("source binary already carries an embedded config")
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if len(body) > embedMaxConfig {
		return fmt.Errorf("embedded config too large (%d bytes)", len(body))
	}
	if _, err := w.Write(src); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(body))); err != nil {
		return err
	}
	_, err = w.Write(embedMagic)
	return err
}

// parseTrailer extracts a config from a complete binary image.
func parseTrailer(b []byte) (EmbeddedConfig, bool) {
	var cfg EmbeddedConfig
	if len(b) < embedTrailerLen {
		return cfg, false
	}
	if !bytes.Equal(b[len(b)-len(embedMagic):], embedMagic) {
		return cfg, false
	}
	lenOff := len(b) - len(embedMagic) - 4
	n := int(binary.LittleEndian.Uint32(b[lenOff : lenOff+4]))
	if n <= 0 || n > embedMaxConfig || lenOff-n < 0 {
		return cfg, false
	}
	if err := json.Unmarshal(b[lenOff-n:lenOff], &cfg); err != nil {
		return cfg, false
	}
	return cfg, true
}

// HasEmbeddedConfig reports whether a complete binary image carries a readable
// config. Used by the console to verify what it just produced, so a broken
// installer is caught at generation rather than by the administrator running it.
func HasEmbeddedConfig(b []byte) bool {
	cfg, ok := parseTrailer(b)
	return ok && cfg.Validate() == nil
}

// LoadEmbeddedConfig reads a stamped config from the running executable.
// Returns (nil, nil) for an ordinary unstamped build, which is the common case
// and not an error.
func LoadEmbeddedConfig() (*EmbeddedConfig, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil
	}
	f, err := os.Open(exe)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() < embedTrailerLen {
		return nil, nil
	}
	// Read only the tail: the executable may be tens of megabytes and the
	// config is at most 64KB.
	tail := int64(embedMaxConfig + embedTrailerLen)
	if tail > fi.Size() {
		tail = fi.Size()
	}
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, fi.Size()-tail); err != nil && err != io.EOF {
		return nil, nil
	}
	cfg, ok := parseTrailer(buf)
	if !ok {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		// Stamped but unusable. Say so rather than behaving like a plain build,
		// or an operator will conclude the installer silently did nothing.
		return nil, err
	}
	return &cfg, nil
}
