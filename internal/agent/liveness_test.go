package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wordeye/internal/model"
)

// An intruder who finds an EDR agent on a host they control will try to stop
// it, and an unprivileged process cannot prevent that. SIGKILL is not delivered
// to userspace at all, so the agent cannot report its own death.
//
// The answer is to make silence itself evidence: a deliberate exit leaves a
// marker, and the absence of that marker on the next start proves the previous
// instance did not choose to stop.

func TestUncleanShutdownIsReportedOnNextStart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	started := time.Now().Add(-time.Hour)

	// A previous instance that ran and was killed: alive, never marked clean.
	if err := MarkAlive(state, started); err != nil {
		t.Fatal(err)
	}

	f := UncleanShutdownFinding(state)
	if f == nil {
		t.Fatal("a killed agent left no evidence; the next start says nothing")
	}
	if f.RuleID != "agent.unclean_stop" {
		t.Errorf("rule %q", f.RuleID)
	}
	if f.Severity == "" || f.Severity == "info" {
		t.Errorf("severity %q is too quiet for an unexplained agent death", f.Severity)
	}
	if _, ok := f.Meta["last_alive"]; !ok {
		t.Error("the finding does not bound when the agent was last alive")
	}
}

// A deliberate shutdown must be silent, or every restart cries wolf and the
// real event is lost among them.
func TestCleanExitReportsNothing(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	started := time.Now().Add(-time.Hour)

	if err := MarkAlive(state, started); err != nil {
		t.Fatal(err)
	}
	if err := MarkCleanExit(state, started); err != nil {
		t.Fatal(err)
	}
	if f := UncleanShutdownFinding(state); f != nil {
		t.Errorf("a clean shutdown produced a finding: %s", f.Title)
	}
}

// A first run has no history and must not invent one.
func TestFirstRunReportsNothing(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	if f := UncleanShutdownFinding(state); f != nil {
		t.Errorf("a first run reported %s", f.RuleID)
	}
}

// The record is rewritten constantly; a torn file would itself look like a
// crash, so the write has to be atomic.
func TestLivenessWriteIsAtomic(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	started := time.Now()
	for i := 0; i < 50; i++ {
		if err := MarkAlive(state, started); err != nil {
			t.Fatal(err)
		}
		if _, err := PriorShutdown(state); err != nil {
			t.Fatalf("record unreadable after write %d: %v", i, err)
		}
	}
	// No temporary files may be left behind.
	entries, err := os.ReadDir(filepath.Dir(LivenessFile(state)))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
}

// last_alive is what bounds the blind window. If it never advanced, an operator
// could not tell whether the host was unwatched for a minute or a week.
func TestLastAliveAdvances(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	started := time.Now()
	if err := MarkAlive(state, started); err != nil {
		t.Fatal(err)
	}
	first, err := PriorShutdown(state)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := MarkAlive(state, started); err != nil {
		t.Fatal(err)
	}
	second, err := PriorShutdown(state)
	if err != nil {
		t.Fatal(err)
	}
	if !second.LastAlive.After(first.LastAlive) {
		t.Error("last_alive did not advance; the blind window cannot be bounded")
	}
}

// The uninstall path exists because of what tamper detection would otherwise do
// to routine work: once an unexplained disappearance is a security finding, an
// administrator decommissioning a site produces the exact signature of an
// intruder. An authorised removal must therefore leave a CLEAN exit behind.
func TestUninstallLeavesACleanExit(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(state, []byte(`{"agent_id":"ag_x","credential":"c"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkAlive(state, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The order the client uses: mark clean, then remove.
	if err := MarkCleanExit(state, time.Now()); err != nil {
		t.Fatal(err)
	}
	res := PerformUninstall(state)

	if len(res.Removed) == 0 {
		t.Error("uninstall removed nothing")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Error("the credential survived an uninstall; the host could still authenticate")
	}
}

// The agent must not delete its own executable. That is a shape this product
// spends its time detecting, and an agent doing it teaches an administrator
// that the behaviour is normal.
func TestUninstallDoesNotRemoveTheBinary(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	binary := filepath.Join(dir, "wordeye-agent")
	for _, p := range []string{state, binary} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	PerformUninstall(state)

	if _, err := os.Stat(binary); err != nil {
		t.Error("the agent deleted its own executable")
	}
}

// The final report is bookkeeping, not an incident. If it arrived as a critical
// every planned decommission would look like an attack.
func TestUninstallFindingIsInformational(t *testing.T) {
	f := UninstallFinding(UninstallResult{Removed: []string{"/home/u/.wordeye/state.json"}}, "console")
	if f.Severity != "info" {
		t.Errorf("severity %q; an authorised removal is not an incident", f.Severity)
	}
	if f.RuleID != "agent.uninstalled" {
		t.Errorf("rule %q", f.RuleID)
	}
}

// During an incident the newest detections are the ones an analyst needs.
//
// The requeue used to truncate from the front, keeping the oldest backlog and
// discarding everything the monitor found while the console was unreachable —
// so an intruder writing shells during an outage produced exactly the findings
// that got dropped.
func TestRequeueKeepsTheNewestDetections(t *testing.T) {
	c := &Client{}

	// The real flow: flushEvents took everything as `batch`, the POST failed,
	// and the monitor appended newer detections to c.pending meanwhile. So the
	// failed batch is the OLDER half.
	failed := make([]model.Finding, maxPendingFindings)
	for i := range failed {
		failed[i] = model.Finding{RuleID: "old", Path: fmt.Sprintf("old-%d.php", i)}
	}
	fresh := make([]model.Finding, 10)
	for i := range fresh {
		fresh[i] = model.Finding{RuleID: "fresh", Path: fmt.Sprintf("fresh-%d.php", i)}
	}
	c.pending = fresh

	c.requeue(failed)

	if len(c.pending) != maxPendingFindings {
		t.Fatalf("queue length %d, want %d", len(c.pending), maxPendingFindings)
	}
	var freshKept int
	for _, f := range c.pending {
		if f.RuleID == "fresh" {
			freshKept++
		}
	}
	if freshKept != len(fresh) {
		t.Errorf("kept %d of %d fresh detections; the newest are the ones that matter",
			freshKept, len(fresh))
	}
}
