package console

import (
	"net/http"
	"testing"
	"time"

	"wordeye/internal/store"
)

// An agent killed with SIGKILL sends nothing and never runs again to notice its
// own missing marker. From the host that death is unreportable; from the
// console it is loud — a machine checking in every minute stopped, said
// nothing, and did not come back. That is the case an intruder produces.
func TestWatchdogReportsASilentAgent(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, code, body := h.enrollAs(tok, false, "abandoned-host", "/www")
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}
	// Backdate its last contact well past the threshold.
	if err := h.srv.DB().SetAgentLastSeen(ag.AgentID, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	h.srv.checkForSilentAgents(time.Now())

	list, err := h.srv.DB().ListFindings(store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range list {
		if f.RuleID == "agent.went_silent" {
			found = true
			if f.Severity != "high" {
				t.Errorf("severity %q; an unexplained agent disappearance is not minor", f.Severity)
			}
		}
	}
	if !found {
		t.Error("a host that vanished without uninstalling was never reported")
	}
}

// A host that checked in recently is not missing.
func TestWatchdogIgnoresLiveAgents(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enrollAs(tok, false, "live-host", "/www")
	if err := h.srv.DB().SetAgentLastSeen(ag.AgentID, time.Now()); err != nil {
		t.Fatal(err)
	}

	h.srv.checkForSilentAgents(time.Now())

	list, _ := h.srv.DB().ListFindings(store.FindingFilter{})
	for _, f := range list {
		if f.RuleID == "agent.went_silent" {
			t.Error("a live agent was reported as silent")
		}
	}
}

// The watchdog only earns its keep if a legitimate decommission is silent. An
// administrator who removes a site properly must generate nothing, or every
// routine teardown looks like an intrusion and the finding stops being read.
func TestWatchdogIgnoresRetiredAgents(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enrollAs(tok, false, "decommissioned-host", "/www")
	if err := h.srv.DB().SetAgentLastSeen(ag.AgentID, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.DB().RetireAgent(ag.AgentID); err != nil {
		t.Fatal(err)
	}

	h.srv.checkForSilentAgents(time.Now())

	list, _ := h.srv.DB().ListFindings(store.FindingFilter{})
	for _, f := range list {
		if f.RuleID == "agent.went_silent" {
			t.Error("a retired agent was reported as silent; routine decommissions would cry wolf")
		}
	}
}

// The same silent host must not generate a finding on every tick.
func TestWatchdogRateLimitsPerHost(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enrollAs(tok, false, "quiet-host", "/www")
	if err := h.srv.DB().SetAgentLastSeen(ag.AgentID, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	h.srv.checkForSilentAgents(now)
	if h.srv.shouldReportSilence(ag.AgentID, now.Add(time.Minute)) {
		t.Error("the same host would be reported again a minute later")
	}
	if !h.srv.shouldReportSilence(ag.AgentID, now.Add(silenceRepeat+time.Minute)) {
		t.Error("the host was never reportable again, so a real re-check would be missed")
	}
}

// Uninstall blinds the estate. A console that can silently disable monitoring
// everywhere is exactly what someone who reached the console would use, so it
// must require a second human — the same rule as containment.
func TestUninstallRequiresApproval(t *testing.T) {
	if !store.DestructiveKinds["uninstall"] {
		t.Error("uninstall can be dispatched without approval")
	}
}
