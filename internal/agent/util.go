package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Shared helpers used by both the portable and the Linux-only checks.

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func depth(p string) int { return strings.Count(filepath.ToSlash(p), "/") }

func currentUser() string {
	for _, k := range []string{"USER", "LOGNAME", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// runCmd executes a command with a hard timeout. Every external invocation in
// the agent is bounded: a wp-cli call that hangs on a broken install must not
// be able to hang the scan.
func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	return string(out), err
}

// runCmdCombined also captures stderr, which is where wp-cli reports checksum
// mismatches.
func runCmdCombined(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out), err
}

// lookWPCLI finds a wp-cli binary, including the common non-PATH install
// locations used by managed hosts.
func lookWPCLI() (string, error) {
	if p, err := exec.LookPath("wp"); err == nil {
		return p, nil
	}
	for _, c := range []string{
		"/usr/local/bin/wp", "/usr/bin/wp", "/opt/bin/wp",
		filepath.Join(os.Getenv("HOME"), "bin", "wp"),
		filepath.Join(os.Getenv("HOME"), ".local", "bin", "wp"),
	} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", exec.ErrNotFound
}
