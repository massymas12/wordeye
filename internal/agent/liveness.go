package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"wordeye/internal/model"
)

// Detecting the death that cannot be reported.
//
// SIGKILL is not delivered to userspace, so an agent cannot say goodbye when it
// is killed with -9 — and -9 is what an intruder uses. The answer is not to try
// harder to catch it; it is to arrange that a silent death leaves evidence.
//
// The agent keeps a small liveness file, refreshed on every heartbeat and
// marked clean only on a deliberate exit. On the next start, a file that was
// never marked clean is proof that the previous instance was killed or the host
// went down hard, and the last_alive timestamp bounds when. Silence becomes a
// reportable fact rather than an absence nobody notices.
//
// This is also why the console's view matters: an agent that neither reports a
// termination nor restarts is the loudest case, and only the server can see it.

type livenessRecord struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	LastAlive time.Time `json:"last_alive"`
	CleanExit bool      `json:"clean_exit"`
	Version   string    `json:"version"`
}

// LivenessFile is where the record lives, beside the credential.
func LivenessFile(stateFile string) string {
	return filepath.Join(filepath.Dir(stateFile), "liveness.json")
}

// PriorShutdown reads the previous run's record, if any.
func PriorShutdown(stateFile string) (*livenessRecord, error) {
	b, err := os.ReadFile(LivenessFile(stateFile))
	if err != nil {
		return nil, err
	}
	var r livenessRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// MarkAlive records that this instance is running. Called at startup and on
// every heartbeat, so last_alive bounds how long ago an unreported death
// happened.
func MarkAlive(stateFile string, started time.Time) error {
	return writeLiveness(stateFile, livenessRecord{
		PID: os.Getpid(), StartedAt: started, LastAlive: time.Now().UTC(),
		CleanExit: false, Version: Version,
	})
}

// MarkCleanExit records a deliberate shutdown. Its absence is the evidence.
func MarkCleanExit(stateFile string, started time.Time) error {
	return writeLiveness(stateFile, livenessRecord{
		PID: os.Getpid(), StartedAt: started, LastAlive: time.Now().UTC(),
		CleanExit: true, Version: Version,
	})
}

func writeLiveness(stateFile string, r livenessRecord) error {
	p := LivenessFile(stateFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// Written atomically: a torn liveness file would itself look like a crash.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// UncleanShutdownFinding describes a previous instance that vanished.
//
// Returns nil when the last exit was clean or there is no history, so a normal
// restart says nothing.
func UncleanShutdownFinding(stateFile string) *model.Finding {
	prior, err := PriorShutdown(stateFile)
	if err != nil || prior == nil || prior.CleanExit {
		return nil
	}
	gap := time.Since(prior.LastAlive).Round(time.Second)

	detail := fmt.Sprintf(
		"The previous agent process (pid %d, version %s) stopped without recording a clean exit. "+
			"It was last alive %s ago, at %s. A deliberate shutdown always leaves a marker, so this "+
			"means the process was killed with a signal it could not catch, the host lost power, or "+
			"the container was destroyed.",
		prior.PID, prior.Version, gap, prior.LastAlive.Format(time.RFC3339))

	sev, conf := model.SevMedium, model.ConfLikely
	reason, checked := oomEvidence()
	switch {
	case reason != "":
		detail += " " + reason
		sev = model.SevLow
	case checked:
		// The counter was readable and said zero. That is a real negative and
		// it is what makes an external kill the likely explanation.
		detail += " No out-of-memory kill was recorded for this container, which makes an external " +
			"kill the more likely explanation."
		sev = model.SevHigh
	default:
		// We could not consult the counter. Saying "no OOM was recorded" here
		// would be asserting a fact never established, and escalating on it
		// would turn an ordinary container restart into a security incident.
		detail += " Whether the kernel's OOM killer was involved could not be determined on this host, " +
			"so an external kill is possible but unproven."
		conf = model.ConfReview
	}

	return &model.Finding{
		RuleID:     "agent.unclean_stop",
		Class:      "OSP",
		Severity:   sev,
		Confidence: conf,
		Title:      "The agent was stopped without a clean exit",
		Detail:     detail,
		Remediation: "Correlate the timestamp with web-server and auth logs. An agent killed with SIGKILL " +
			"immediately before a gap in monitoring is an attempt to blind the host, and anything written " +
			"during that gap was not evaluated in real time — run a full scan.",
		Meta: map[string]any{
			"prior_pid":     prior.PID,
			"prior_version": prior.Version,
			"last_alive":    prior.LastAlive,
			"gap_seconds":   int64(gap.Seconds()),
		},
	}
}
