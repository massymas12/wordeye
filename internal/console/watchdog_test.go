package console

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wordeye/internal/sign"
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

// The rate limiter fronting the internet-facing ingest listener is keyed on the
// client address BEFORE authentication. Trusting X-Forwarded-For there meant an
// unauthenticated attacker got a fresh limiter window per request — defeating
// the cap entirely — while inserting a new map entry each time, which is a
// memory-exhaustion primitive against the console the whole fleet reports to.
func TestForwardedForIsIgnoredWithoutATrustedProxy(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/enroll", nil)
	r.RemoteAddr = "203.0.113.7:44444"
	r.Header.Set("X-Forwarded-For", "10.9.9.9")

	if got := h.srv.clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want the peer address 203.0.113.7 — a spoofed header was believed", got)
	}
}

// Every request carrying a different forged header must still land on the same
// limiter key, or the cap does not exist.
func TestForgedForwardedForCannotSplitTheLimiterKey(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest(http.MethodPost, "/v1/enroll", nil)
		r.RemoteAddr = "203.0.113.7:44444"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		seen[h.srv.clientIP(r)] = true
	}
	if len(seen) != 1 {
		t.Errorf("50 forged headers produced %d distinct limiter keys; the cap is bypassable", len(seen))
	}
}

// Behind a proxy the operator actually configured, the header is the only way
// to see the real client, so it must be honoured there.
func TestForwardedForIsHonouredBehindAConfiguredProxy(t *testing.T) {
	h := newHarness(t)
	_, cidr, err := net.ParseCIDR("10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	h.srv.cfg.TrustedProxies = []*net.IPNet{cidr}

	r := httptest.NewRequest(http.MethodPost, "/v1/enroll", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.20, 10.1.2.3")
	if got := h.srv.clientIP(r); got != "198.51.100.20" {
		t.Errorf("clientIP = %q, want 198.51.100.20 from the trusted proxy", got)
	}
}

// A trusted proxy sending rubbish must not put rubbish in the audit trail.
func TestNonIPForwardedForIsRejected(t *testing.T) {
	h := newHarness(t)
	_, cidr, _ := net.ParseCIDR("10.1.0.0/16")
	h.srv.cfg.TrustedProxies = []*net.IPNet{cidr}

	r := httptest.NewRequest(http.MethodPost, "/v1/enroll", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("X-Forwarded-For", strings.Repeat("A", 900000))
	if got := h.srv.clientIP(r); got != "10.1.2.3" {
		t.Errorf("clientIP = %q; a non-IP header value was accepted as an address", got)
	}
}

// The scheduler's stagger must actually delay work.
//
// The offset used to be written into the command's params, which nothing reads:
// the agent ignores params by design and the dispatch query had no time
// predicate. Every host therefore collected its command on the next heartbeat
// and a "staggered" fleet-wide sweep landed inside one minute — the exact
// self-inflicted outage the jitter window exists to prevent.
func TestStaggeredCommandIsNotHandedOutEarly(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, code, body := h.enrollAs(tok, false, "staggered-host", "/www")
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}

	if _, err := h.srv.DB().CreateCommandAt(ag.AgentID, "scan", map[string]any{"scheduled": true},
		"scheduler", time.Hour, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.srv.DB().NextCommandForAgent(ag.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != nil {
		t.Errorf("a command deferred 30 minutes was handed out immediately (%s)", cmd.Kind)
	}
}

// And it must be handed out once its moment arrives, or the scan never runs.
func TestStaggeredCommandIsHandedOutWhenDue(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enrollAs(tok, false, "due-host", "/www")

	if _, err := h.srv.DB().CreateCommandAt(ag.AgentID, "scan", map[string]any{"scheduled": true},
		"scheduler", time.Hour, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.srv.DB().NextCommandForAgent(ag.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil {
		t.Fatal("a due command was withheld")
	}
	if cmd.Kind != "scan" {
		t.Errorf("kind %q", cmd.Kind)
	}
}

// Ordinary operator-issued work must not be delayed at all.
func TestUnstaggeredCommandIsImmediate(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enrollAs(tok, false, "now-host", "/www")

	if _, err := h.srv.DB().CreateCommand(ag.AgentID, "scan", nil, "operator", time.Hour); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.srv.DB().NextCommandForAgent(ag.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil {
		t.Error("an operator-issued scan was withheld")
	}
}

// Upgrade replaces the security control on every host it reaches — strictly
// more powerful than containment, which only removes a file an operator already
// reviewed. A console able to push code unattended would turn a console
// compromise into arbitrary execution across the estate.
func TestUpgradeRequiresApproval(t *testing.T) {
	if !store.DestructiveKinds["upgrade"] {
		t.Error("upgrade can be dispatched without a second approver")
	}
}

// The console must not be able to serve an unsigned release. Falling back to
// unsigned distribution would defeat the entire mechanism.
func TestUnsignedReleaseIsNotServed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wordeye-agent-linux-amd64"),
		[]byte("\x7fELF unsigned"), 0o755); err != nil {
		t.Fatal(err)
	}

	h := newHarness(t)
	h.srv.cfg.AgentBinaryDir = dir

	tok := h.mintToken(1, false)
	ag, code, body := h.enrollAs(tok, false, "upgrade-host", "/www")
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}

	code, body = h.getJSON(h.ingest.URL, "/v1/agent-release?os=linux&arch=amd64", ag.auth(), nil)
	if code == http.StatusOK {
		t.Errorf("an unsigned release was served to an agent: %d %s", code, body)
	}
}

// A signed release is served together with its detached signature, which is the
// only thing the agent will act on.
func TestSignedReleaseIsServedWithItsSignature(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "wordeye-agent-linux-amd64")
	payload := []byte("\x7fELF a signed build")
	if err := os.WriteFile(bin, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign.Sign(priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}

	h := newHarness(t)
	h.srv.cfg.AgentBinaryDir = dir
	tok := h.mintToken(1, false)
	ag, _, _ := h.enrollAs(tok, false, "signed-host", "/www")

	req, err := http.NewRequest(http.MethodGet, h.ingest.URL+"/v1/agent-release?os=linux&arch=amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", ag.auth())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	served := resp.Header.Get("X-WordEye-Signature")
	if served == "" {
		t.Fatal("no signature header; the agent would have nothing to verify")
	}
	if !sign.Verify(pub, got, served) {
		t.Error("the served bytes do not verify against the signature served with them")
	}
}
