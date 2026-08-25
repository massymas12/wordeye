package model

import (
	"strings"
	"testing"
)

// The verdict rollup is the integrity property of the whole tool.
//
// A scanner that cannot distinguish "checked and clean" from "could not check"
// manufactures false confidence, and false confidence is what lets an attacker
// survive a clean bill of health. These tests exist so that property cannot
// regress quietly.
//
// The original implementation had exactly this bug: CheckState carried three
// values, but only CheckError and CheckOK were consulted when computing the
// verdict, so every unavailable check silently reported as clean.

func report(checks ...CheckStatus) *Report {
	r := &Report{}
	for _, c := range checks {
		r.AddCheck(c)
	}
	return r
}

func TestUnavailableCheckNeverReportsClean(t *testing.T) {
	r := report(
		CheckStatus{ID: "fs.scan", State: CheckOK},
		CheckStatus{ID: "wp.dropins", State: CheckOK},
		// The canonical example: `crontab -l` produced nothing, which means
		// "no readable crontab, therefore unknown" — not "no cron, therefore fine".
		CheckStatus{ID: "osp.cron", State: CheckUnavailable, Reason: "no readable crontab"},
	)
	r.Finalize()

	if r.Verdict == "clean" {
		t.Fatal("a scan with an unreadable crontab reported CLEAN")
	}
	if r.Verdict != "partial" {
		t.Errorf("verdict = %q, want partial", r.Verdict)
	}
	if !strings.Contains(r.VerdictDetail, "could not be observed") {
		t.Errorf("verdict detail does not explain the gap: %q", r.VerdictDetail)
	}
}

// The opposite error would be just as bad: if every "nothing here" degraded the
// verdict, nothing would ever be clean and the signal would be worthless.
func TestNotApplicableDoesNotDegradeTheVerdict(t *testing.T) {
	r := report(
		CheckStatus{ID: "fs.scan", State: CheckOK},
		CheckStatus{ID: "osp.cron", State: CheckOK},
		// Genuinely observed absence: we looked, there is no redirect plugin.
		CheckStatus{ID: "db.redirects", State: CheckNotApplicable, Reason: "no redirect plugin tables present"},
		CheckStatus{ID: "db.options", State: CheckOK},
	)
	r.Finalize()

	if r.Verdict != "clean" {
		t.Errorf("verdict = %q, want clean: observed-absence is not blindness (%s)",
			r.Verdict, r.VerdictDetail)
	}
}

func TestErrorAlsoDegrades(t *testing.T) {
	r := report(
		CheckStatus{ID: "fs.scan", State: CheckOK},
		CheckStatus{ID: "db.options", State: CheckError, Reason: "connect refused"},
	)
	r.Finalize()
	if r.Verdict != "partial" {
		t.Errorf("verdict = %q, want partial", r.Verdict)
	}
}

// Findings still dominate, but the report must say when it ALSO could not see
// part of the system — otherwise remediation looks complete when it is not.
func TestDirtyStillReportsUnassessedLayers(t *testing.T) {
	r := report(
		CheckStatus{ID: "fs.scan", State: CheckOK},
		CheckStatus{ID: "osp.cron", State: CheckUnavailable, Reason: "no readable crontab"},
	)
	r.AddFinding(Finding{RuleID: "shell.x", Severity: SevCritical, Title: "shell"})
	r.Finalize()

	if r.Verdict != "dirty" {
		t.Fatalf("verdict = %q, want dirty", r.Verdict)
	}
	if !strings.Contains(r.VerdictDetail, "could not be assessed") {
		t.Errorf("a dirty verdict hid the unassessed layer: %q", r.VerdictDetail)
	}
}

// The layered view is what lets a container scan stay useful: the application
// layer is fully assessed even when the OS layer cannot be seen at all.
func TestLayersSeparateApplicationFromOS(t *testing.T) {
	r := report(
		CheckStatus{ID: "fs.scan", State: CheckOK},
		CheckStatus{ID: "wp.dropins", State: CheckOK},
		CheckStatus{ID: "wp.config", State: CheckOK},
		CheckStatus{ID: "osp.cron", State: CheckUnavailable},
		CheckStatus{ID: "osp.ssh", State: CheckUnavailable},
		CheckStatus{ID: "mem.mappings", State: CheckUnavailable},
		CheckStatus{ID: "db.options", State: CheckOK},
	)
	r.Finalize()

	byName := map[string]Layer{}
	for _, l := range r.Layers {
		byName[l.Name] = l
	}

	app, ok := byName["application"]
	if !ok || app.State != LayerChecked {
		t.Errorf("application layer = %+v, want fully checked", app)
	}
	os, ok := byName["operating system"]
	if !ok || os.State != LayerUnavailable {
		t.Errorf("operating system layer = %+v, want unavailable", os)
	}
	if len(os.Unavailable) != 3 {
		t.Errorf("expected 3 unobservable OS checks, got %v", os.Unavailable)
	}
	db, ok := byName["database"]
	if !ok || db.State != LayerChecked {
		t.Errorf("database layer = %+v, want checked", db)
	}

	// And the overall verdict reflects the gap rather than the clean layers.
	if r.Verdict != "partial" {
		t.Errorf("verdict = %q, want partial", r.Verdict)
	}
}

// A layer where SOME checks saw their subject is degraded, not unavailable —
// the distinction matters when deciding whether to re-run with more access.
func TestPartiallyObservedLayerIsDegraded(t *testing.T) {
	r := report(
		CheckStatus{ID: "osp.processes", State: CheckOK},
		CheckStatus{ID: "osp.cron", State: CheckUnavailable},
	)
	r.Finalize()

	for _, l := range r.Layers {
		if l.Name == "operating system" {
			if l.State != LayerDegraded {
				t.Errorf("layer state = %q, want degraded", l.State)
			}
			if l.Observed != 1 || l.Checks != 2 {
				t.Errorf("observed %d of %d, want 1 of 2", l.Observed, l.Checks)
			}
		}
	}
}

// CheckSkipped is retained as an alias so any call site missed during the
// migration fails SAFE — degrading the verdict rather than claiming coverage.
func TestSkippedAliasFailsSafe(t *testing.T) {
	if CheckSkipped != CheckUnavailable {
		t.Fatal("CheckSkipped must alias CheckUnavailable so missed call sites degrade the verdict")
	}
	r := report(
		CheckStatus{ID: "fs.scan", State: CheckOK},
		CheckStatus{ID: "osp.cron", State: CheckSkipped},
	)
	r.Finalize()
	if r.Verdict == "clean" {
		t.Error("a legacy skipped check reported clean")
	}
}
