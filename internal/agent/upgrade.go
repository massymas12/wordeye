package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"wordeye/internal/sign"
)

// Self-update, and why every step of it refuses by default.
//
// Replacing this binary is the most powerful thing the agent can be asked to
// do. Containment deletes a file an operator already looked at; an upgrade
// replaces the security control itself, on every host in the estate, from one
// action taken on an internet-facing server. If the console alone could
// authorise it, compromising the console would mean arbitrary code execution on
// every customer production host — a far worse outcome than anything WordEye is
// deployed to find.
//
// So the console is not trusted to vouch for code. It distributes bytes; the
// build machine signs them; the agent verifies against a public key stamped in
// at install time and executes nothing it cannot prove. An attacker who owns
// the console can serve whatever they like and every agent refuses it.
//
// The sequence, and the reason for its order:
//
//	1. refuse if no key was pinned   an agent that cannot verify must not upgrade
//	2. download to a staged file     never overwrite ourselves before checking
//	3. verify the signature over
//	   the exact bytes received      this is the security boundary
//	4. run the new --version         a signed binary that cannot execute here
//	                                 would end monitoring silently
//	5. refuse downgrades             otherwise someone who cannot forge a
//	                                 signature can still pin the fleet to an
//	                                 older, known-vulnerable release
//	6. atomic rename over ourselves  a partial write must be impossible
//	7. re-exec                       same pid, no supervisor required
//
// A failure at any step leaves the running agent exactly as it was.

const (
	// upgradeMaxBytes bounds the download. A release is tens of megabytes; a
	// console persuaded to stream something enormous must not be able to fill a
	// customer disk.
	upgradeMaxBytes = 128 << 20
	upgradeTimeout  = 5 * time.Minute
)

// UpgradeResult describes a completed swap, for the command result.
type UpgradeResult struct {
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	SHA256      string `json:"sha256"`
	Path        string `json:"path"`
}

// SelfUpgrade downloads, verifies and installs a new agent binary. Any error
// means nothing was changed.
func (c *Client) SelfUpgrade(ctx context.Context) (*UpgradeResult, error) {
	pub := c.cfg.SigningKey
	if strings.TrimSpace(pub) == "" {
		// An agent installed before signing existed, or deliberately deployed
		// without a key. It cannot tell a genuine release from a hostile one,
		// so it must not try.
		return nil, fmt.Errorf("this agent has no pinned signing key and cannot verify a release; " +
			"reinstall from an installer generated with --signing-key")
	}

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locating the running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	ctx, cancel := context.WithTimeout(ctx, upgradeTimeout)
	defer cancel()

	raw, sig, err := c.fetchRelease(ctx)
	if err != nil {
		return nil, err
	}

	// THE security boundary. Everything above is untrusted input.
	if !sign.Verify(pub, raw, sig) {
		return nil, fmt.Errorf("the release served by the console is not signed by the build key for "+
			"this estate (%d bytes rejected); refusing to install it", len(raw))
	}
	sum := sha256.Sum256(raw)

	// Stage beside the current binary, so the rename below cannot cross a
	// filesystem boundary and quietly degrade into a copy.
	staged := self + ".new"
	if err := os.WriteFile(staged, raw, 0o755); err != nil {
		return nil, fmt.Errorf("staging the new binary: %w", err)
	}
	defer os.Remove(staged) // no-op once renamed
	if err := os.Chmod(staged, 0o755); err != nil {
		return nil, fmt.Errorf("making the new binary executable: %w", err)
	}

	newVersion, err := binaryVersion(ctx, staged)
	if err != nil {
		// Signed, but it will not run here: wrong architecture, missing loader,
		// noexec mount. Installing it would silently end monitoring on this host.
		return nil, fmt.Errorf("the new binary is correctly signed but would not run: %w", err)
	}
	if !isNewerVersion(newVersion, Version) {
		return nil, fmt.Errorf("refusing to move from %s to %s: an upgrade must move forward, and "+
			"accepting older releases would let anyone able to choose which signed build is served "+
			"pin this fleet to a known-vulnerable one", Version, newVersion)
	}

	// Keep the outgoing binary beside the new one, so an administrator has
	// something to restore by hand if the process fails to come back.
	_ = os.Rename(self, self+".old")
	if err := os.Rename(staged, self); err != nil {
		_ = os.Rename(self+".old", self)
		return nil, fmt.Errorf("installing the new binary: %w", err)
	}

	return &UpgradeResult{
		FromVersion: Version,
		ToVersion:   newVersion,
		SHA256:      hex.EncodeToString(sum[:]),
		Path:        self,
	}, nil
}

// fetchRelease downloads the binary and its detached signature.
func (c *Client) fetchRelease(ctx context.Context) ([]byte, string, error) {
	url := fmt.Sprintf("%s/v1/agent-release?os=%s&arch=%s", c.state.Server, runtime.GOOS, runtime.GOARCH)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", c.authHeader())

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("downloading the release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("the console returned %s for this platform release", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, upgradeMaxBytes))
	if err != nil {
		return nil, "", fmt.Errorf("reading the release: %w", err)
	}
	sig := resp.Header.Get("X-WordEye-Signature")
	if sig == "" {
		return nil, "", fmt.Errorf("the console served a release with no signature")
	}
	return raw, sig, nil
}

// binaryVersion runs a candidate binary and reads the version it reports. This
// is the proof that a signed release can actually execute on this host.
func binaryVersion(ctx context.Context, path string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	out, err := exec.CommandContext(cctx, path, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v (%s)", err, strings.TrimSpace(truncate(string(out), 200)))
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return "", fmt.Errorf("it printed no version")
	}
	return fields[len(fields)-1], nil
}

// isNewerVersion compares dotted numeric versions. Unparseable input returns
// false, so anything the agent cannot reason about is treated as not-an-upgrade
// rather than waved through.
func isNewerVersion(candidate, current string) bool {
	c, ok1 := parseVersion(candidate)
	r, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if c[i] != r[i] {
			return c[i] > r[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		// Bound the width. Without this a component of twenty-odd digits
		// overflows int and wraps to a value that compares as NEWER, which
		// turns a nonsense version string into an upgrade.
		if p == "" || len(p) > 6 {
			return out, false
		}
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return out, false
			}
			n = n*10 + int(ch-'0')
		}
		out[i] = n
	}
	return out, true
}
