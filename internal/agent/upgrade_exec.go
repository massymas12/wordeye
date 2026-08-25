package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"wordeye/internal/model"
)

// The console-driven half of self-update: receive the order, do the work, then
// hand the process over to the new binary.

var errUpgradeRequested = errors.New("upgrade requested")

// IsUpgradeRequest reports whether an error is the upgrade sentinel.
func IsUpgradeRequest(err error) bool { return errors.Is(err, errUpgradeRequested) }

// upgrade verifies and installs a new release, then re-execs into it.
//
// Reporting happens BEFORE the re-exec, for the same reason it happens before
// deletion in uninstall: once the process image is replaced there is nothing
// left to speak with. And it reports the OUTCOME rather than the intent — a
// refused signature is the mechanism working, and an operator who is told
// "done" when the agent declined to install would draw exactly the wrong
// conclusion about their fleet.
func (c *Client) upgrade(ctx context.Context, id string, logf func(string, ...any)) {
	logf("upgrade requested by the console")

	res, err := c.SelfUpgrade(ctx)
	if err != nil {
		logf("upgrade refused: %v", err)
		c.queueFinding(model.Finding{
			RuleID:     "agent.upgrade_refused",
			Class:      "OSP",
			Severity:   model.SevMedium,
			Confidence: model.ConfConfirmed,
			Title:      "Agent refused an upgrade",
			Detail: fmt.Sprintf("The console offered a new release and this host declined it: %v. "+
				"The agent is still running its existing version; nothing was changed.", err),
			Remediation: "If this was an intended release, confirm it was signed on the build machine " +
				"with `wordeye sign-release` using the same key stamped into these installers. A refusal " +
				"here means the bytes served did not match that key, which is the check working.",
			Meta: map[string]any{"running_version": Version, "error": err.Error()},
		})
		c.flushEvents(ctx)
		_ = c.post(ctx, "/v1/command/result", map[string]any{
			"id": id, "status": "failed", "error": err.Error(),
		}, nil)
		return
	}

	logf("upgraded %s -> %s (sha256 %s)", res.FromVersion, res.ToVersion, res.SHA256[:16])
	c.queueFinding(model.Finding{
		RuleID:     "agent.upgraded",
		Class:      "OSP",
		Severity:   model.SevInfo,
		Confidence: model.ConfConfirmed,
		Title:      fmt.Sprintf("Agent upgraded from %s to %s", res.FromVersion, res.ToVersion),
		Detail: "The release was verified against the signing key pinned at install time before it " +
			"was installed, and the new binary was executed once to confirm it runs on this host.",
		Meta: map[string]any{
			"from": res.FromVersion, "to": res.ToVersion, "sha256": res.SHA256,
		},
	})
	c.flushEvents(ctx)
	_ = c.post(ctx, "/v1/command/result", map[string]any{
		"id":     id,
		"status": "done",
		"result": fmt.Sprintf("upgraded %s to %s (sha256 %s)", res.FromVersion, res.ToVersion, res.SHA256[:16]),
	}, nil)

	// Record a clean exit before handing over. Without it the new process would
	// find no clean-exit marker and report its own predecessor as having been
	// killed — an upgrade would manufacture a tamper alert on every host.
	if c.cfg.StateFile != "" {
		_ = MarkCleanExit(c.cfg.StateFile, time.Now())
	}

	if err := reexec(res.Path); err != nil {
		// The binary is already replaced, so stopping is correct: a supervisor
		// restarts us on the new version, and an unsupervised agent is better
		// stopped than left running code that no longer matches its own file.
		logf("upgraded, but could not re-exec (%v); exiting so a supervisor can restart", err)
	}
	c.requestShutdown()
}

// reexec replaces the current process image with the binary at path.
//
// Same pid, same arguments, same environment — so a host with no supervisor
// still comes back, and one with a supervisor sees no restart at all. On
// platforms without exec semantics this returns an error and the caller falls
// back to a clean shutdown.
func reexec(path string) error {
	args := append([]string{path}, os.Args[1:]...)
	return execSelf(path, args, os.Environ())
}
