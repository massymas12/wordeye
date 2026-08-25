package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"wordeye/internal/model"
)

// A blessed way to remove the agent.
//
// This exists because of what the tamper detection would otherwise do to it.
// Once an unexplained disappearance is a security finding, an administrator
// decommissioning a site the ordinary way — stop the process, delete the files
// — produces exactly the signature of an intruder silencing the agent. That is
// a false positive the operator creates for themselves every time they do
// routine work, and a watchdog nobody trusts is a watchdog nobody reads.
//
// So there is a right way: the console asks, the agent acknowledges, records a
// clean exit, removes its own credential and state, and goes. Anything else
// remains suspicious, which is what makes the suspicion meaningful.
//
// The command is approval-gated for a reason of its own. It destroys nothing on
// the customer's server, but it blinds the estate — and silently disabling
// monitoring everywhere is precisely what someone who reached the console would
// want. Requiring a second human makes that impossible from one stolen session.

var errUninstallRequested = errors.New("uninstall requested")

// IsUninstallRequest reports whether an error is the uninstall sentinel.
func IsUninstallRequest(err error) bool { return errors.Is(err, errUninstallRequested) }

// UninstallResult describes what was removed, for the final report.
type UninstallResult struct {
	Removed []string `json:"removed"`
	Failed  []string `json:"failed"`
}

// PerformUninstall removes the agent's local footprint.
//
// The BINARY is deliberately left alone. A process deleting the file it is
// executing is a shape this product spends its time detecting, and an agent
// that does it teaches an administrator that the behaviour is normal. What goes
// is the credential and the state: after this the agent cannot authenticate,
// which is what "uninstalled" has to mean from the console's point of view.
func PerformUninstall(stateFile string) UninstallResult {
	var res UninstallResult
	dir := filepath.Dir(stateFile)
	targets := []string{
		stateFile,
		LivenessFile(stateFile),
		filepath.Join(dir, "provenance"),
	}
	for _, p := range targets {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			res.Failed = append(res.Failed, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		res.Removed = append(res.Removed, p)
	}
	return res
}

// UninstallFinding is the agent's last word before it stops.
//
// Reported at info severity and confirmed: this is bookkeeping, not an
// incident. Its whole purpose is to sit in the record so that the silence which
// follows is explained, and so the console can tell an authorised removal from
// an intruder with a kill command.
func UninstallFinding(res UninstallResult, by string) model.Finding {
	detail := "The console requested removal and the agent is stopping deliberately. " +
		"Local credential and state have been deleted, so this host can no longer authenticate. " +
		"The binary itself was left in place: a process that deletes its own executable is a shape " +
		"this tool exists to detect, and it should not model that behaviour."
	if len(res.Failed) > 0 {
		detail += fmt.Sprintf(" Some files could not be removed: %v", res.Failed)
	}
	return model.Finding{
		RuleID:      "agent.uninstalled",
		Class:       "OSP",
		Severity:    model.SevInfo,
		Confidence:  model.ConfConfirmed,
		Title:       "Agent uninstalled at the console's request",
		Detail:      detail,
		Remediation: "Remove the binary and any service unit for this agent to complete the decommission.",
		Meta: map[string]any{
			"removed":      res.Removed,
			"failed":       res.Failed,
			"requested_by": by,
			"at":           time.Now().UTC(),
		},
	}
}
