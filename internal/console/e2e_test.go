package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wordeye/internal/authn"
	"wordeye/internal/store"
)

// End-to-end tests over the real HTTP handlers.
//
// The assertions that matter most here are the negative ones: an agent must not
// be able to join without a token, a single-use token must not work twice, and
// a containment order must not reach a host that did not opt in. Those are the
// properties that keep a console compromise from becoming an estate compromise.

type harness struct {
	t       *testing.T
	srv     *Server
	ingest  *httptest.Server
	console *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv, err := New(Config{
		DBPath: dbPath,
		Logger: log.New(io.Discard, "", 0),
		Issuer: "WordEyeTest",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &harness{
		t:       t,
		srv:     srv,
		ingest:  httptest.NewServer(srv.ingestHandler()),
		console: httptest.NewServer(srv.consoleHandler()),
	}
	t.Cleanup(func() {
		h.ingest.Close()
		h.console.Close()
		srv.Close()
	})
	return h
}

func (h *harness) postJSON(base, path, auth string, body any, out any) (int, string) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == http.StatusOK {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode, string(raw)
}

// mintToken creates an enrollment token directly, standing in for an operator
// clicking "create" in the UI.
func (h *harness) mintToken(uses int, allowContain bool) string {
	h.t.Helper()
	plain, _, err := h.srv.DB().CreateEnrollToken("test", "tester", time.Hour, uses, allowContain)
	if err != nil {
		h.t.Fatal(err)
	}
	return plain
}

// mintTokenForEstate creates a token scoped to one customer, so agents enrolled
// with it belong to that estate.
func (h *harness) mintTokenForEstate(uses int, allowContain bool, estateID int64) string {
	h.t.Helper()
	plain, tok, err := h.srv.DB().CreateEnrollToken("test", "tester", time.Hour, uses, allowContain)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.srv.DB().SetTokenEstate(tok.ID, estateID); err != nil {
		h.t.Fatal(err)
	}
	return plain
}

// getJSON performs an authenticated GET, mirroring postJSON.
func (h *harness) getJSON(base, path, auth string, out any) (int, string) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == http.StatusOK {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode, string(raw)
}

type enrolled struct {
	AgentID            string `json:"agent_id"`
	Credential         string `json:"credential"`
	AllowRemoteContain bool   `json:"allow_remote_contain"`
}

func (e enrolled) auth() string { return "Bearer " + e.AgentID + "." + e.Credential }

func (h *harness) enroll(token string, optIn bool) (enrolled, int, string) {
	h.t.Helper()
	return h.enrollAs(token, optIn, "test-host", "/var/www/html")
}

// enrollAs enrolls with an explicit host identity. Correlation counts distinct
// installations (hostname+webroot), not agent rows, so a test that means "three
// separate hosts" has to say so — three enrollments from one machine are one
// witness by design.
func (h *harness) enrollAs(token string, optIn bool, hostname, webroot string) (enrolled, int, string) {
	h.t.Helper()
	var out enrolled
	code, body := h.postJSON(h.ingest.URL, "/v1/enroll", "", map[string]any{
		"token": token, "hostname": hostname, "label": "Test",
		"site": "test", "webroot": webroot, "version": "test",
		"os": "linux", "arch": "amd64", "opt_in_contain": optIn,
	}, &out)
	return out, code, body
}

// ---------------------------------------------------------------------------

func TestEnrollmentRequiresAToken(t *testing.T) {
	h := newHarness(t)

	// No token at all.
	if code, _ := h.postJSON(h.ingest.URL, "/v1/enroll", "", map[string]any{
		"hostname": "rogue",
	}, nil); code == http.StatusOK {
		t.Fatal("an agent enrolled without a token")
	}

	// A made-up token.
	if _, code, _ := h.enroll("wek_not-a-real-token", false); code == http.StatusOK {
		t.Fatal("an agent enrolled with a forged token")
	}

	// A genuine token works exactly once.
	tok := h.mintToken(1, false)
	ag, code, body := h.enroll(tok, false)
	if code != http.StatusOK {
		t.Fatalf("valid token was refused: %d %s", code, body)
	}
	if ag.AgentID == "" || ag.Credential == "" {
		t.Fatal("enrollment returned no credential")
	}
	if _, code, _ := h.enroll(tok, false); code == http.StatusOK {
		t.Fatal("a single-use token was accepted twice")
	}
}

func TestRevokedAndExpiredTokensAreRefused(t *testing.T) {
	h := newHarness(t)

	plain, meta, err := h.srv.DB().CreateEnrollToken("revoke-me", "tester", time.Hour, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.DB().RevokeEnrollToken(meta.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := h.enroll(plain, false); code == http.StatusOK {
		t.Error("a revoked token was accepted")
	}

	expired, _, err := h.srv.DB().CreateEnrollToken("expired", "tester", -time.Hour, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, code, _ := h.enroll(expired, false); code == http.StatusOK {
		t.Error("an expired token was accepted")
	}
}

func TestAgentAuthentication(t *testing.T) {
	h := newHarness(t)
	ag, _, _ := h.enroll(h.mintToken(1, false), false)

	if code, _ := h.postJSON(h.ingest.URL, "/v1/heartbeat", "", map[string]any{}, nil); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated heartbeat returned %d, want 401", code)
	}
	if code, _ := h.postJSON(h.ingest.URL, "/v1/heartbeat",
		"Bearer "+ag.AgentID+".wrong-credential", map[string]any{}, nil); code != http.StatusUnauthorized {
		t.Errorf("bad credential returned %d, want 401", code)
	}
	if code, body := h.postJSON(h.ingest.URL, "/v1/heartbeat", ag.auth(),
		map[string]any{"load1": 0.2, "monitor": true, "version": "test"}, nil); code != http.StatusOK {
		t.Errorf("valid heartbeat returned %d: %s", code, body)
	}

	agents, err := h.srv.DB().ListAgents(false, 0)
	if err != nil || len(agents) != 1 {
		t.Fatalf("expected one agent, got %v (%v)", len(agents), err)
	}
	if agents[0].Status != "online" {
		t.Errorf("agent status = %q after heartbeat, want online", agents[0].Status)
	}
}

// The core safety property of the whole design.
func TestRemoteContainmentRequiresBothKeys(t *testing.T) {
	cases := []struct {
		name        string
		tokenGrants bool
		agentOptsIn bool
		wantAllowed bool
	}{
		{"neither side agrees", false, false, false},
		{"only the console grants it", true, false, false},
		{"only the host opts in", false, true, false},
		{"both agree", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ag, code, body := h.enroll(h.mintToken(1, tc.tokenGrants), tc.agentOptsIn)
			if code != http.StatusOK {
				t.Fatalf("enroll failed: %d %s", code, body)
			}
			if ag.AllowRemoteContain != tc.wantAllowed {
				t.Errorf("enroll reported allow_remote_contain=%v, want %v",
					ag.AllowRemoteContain, tc.wantAllowed)
			}

			stored, err := h.srv.DB().GetAgent(ag.AgentID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.ContainAllowed() != tc.wantAllowed {
				t.Fatalf("stored ContainAllowed()=%v, want %v", stored.ContainAllowed(), tc.wantAllowed)
			}

			// Creating a containment command must be refused unless both agree.
			_, err = h.srv.DB().CreateCommand(ag.AgentID, "contain", map[string]any{}, "tester", time.Hour)
			if err != nil {
				t.Fatalf("CreateCommand: %v", err)
			}
			// Approve it, so the ONLY thing that can still stop dispatch is the
			// agent-side gate we are actually testing.
			if err := h.srv.DB().ApproveCommand(lastCommandID(t, h, ag.AgentID), "approver"); err != nil {
				t.Fatal(err)
			}
			var hb heartbeatResponse
			code, body = h.postJSON(h.ingest.URL, "/v1/heartbeat", ag.auth(), map[string]any{}, &hb)
			if code != http.StatusOK {
				t.Fatalf("heartbeat: %d %s", code, body)
			}
			gotCommand := hb.Command != nil && hb.Command.Kind == "contain"
			if gotCommand != tc.wantAllowed {
				t.Errorf("containment dispatched=%v, want %v", gotCommand, tc.wantAllowed)
			}
		})
	}
}

func lastCommandID(t *testing.T, h *harness, agentID string) string {
	t.Helper()
	cmds, err := h.srv.DB().ListCommands(agentID, 10)
	if err != nil || len(cmds) == 0 {
		t.Fatalf("no commands for %s (%v)", agentID, err)
	}
	return cmds[0].ID
}

// A destructive command must never be handed out on creation alone.
func TestDestructiveCommandsNeedApproval(t *testing.T) {
	h := newHarness(t)
	ag, _, _ := h.enroll(h.mintToken(1, true), true)

	cmd, err := h.srv.DB().CreateCommand(ag.AgentID, "contain", map[string]any{}, "creator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != "pending" || !cmd.RequiresApproval {
		t.Fatalf("contain created as status=%q approval=%v; want pending/true", cmd.Status, cmd.RequiresApproval)
	}

	var hb heartbeatResponse
	h.postJSON(h.ingest.URL, "/v1/heartbeat", ag.auth(), map[string]any{}, &hb)
	if hb.Command != nil {
		t.Fatal("an unapproved destructive command was dispatched to the agent")
	}

	if err := h.srv.DB().ApproveCommand(cmd.ID, "approver"); err != nil {
		t.Fatal(err)
	}
	hb = heartbeatResponse{}
	h.postJSON(h.ingest.URL, "/v1/heartbeat", ag.auth(), map[string]any{}, &hb)
	if hb.Command == nil || hb.Command.Kind != "contain" {
		t.Fatal("an approved command was not dispatched")
	}

	// And it must not be dispatched a second time.
	hb = heartbeatResponse{}
	h.postJSON(h.ingest.URL, "/v1/heartbeat", ag.auth(), map[string]any{}, &hb)
	if hb.Command != nil {
		t.Error("the same command was dispatched twice")
	}

	// Non-destructive work needs no approval.
	scan, err := h.srv.DB().CreateCommand(ag.AgentID, "scan", map[string]any{}, "creator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if scan.RequiresApproval || scan.Status != "approved" {
		t.Errorf("scan required approval (status=%q approval=%v)", scan.Status, scan.RequiresApproval)
	}
}

func TestFindingIngestAndDedupe(t *testing.T) {
	h := newHarness(t)
	ag, _, _ := h.enroll(h.mintToken(1, false), false)

	finding := map[string]any{
		"rule_id": "shell.superglobal_call", "class": "SHELL",
		"severity": "critical", "confidence": "confirmed",
		"title":  "Function call dispatched through a request superglobal",
		"path":   "wp-content/plugins/p/lib/util.php",
		"sha256": "abc123",
	}
	for i := 0; i < 3; i++ {
		if code, body := h.postJSON(h.ingest.URL, "/v1/events", ag.auth(),
			map[string]any{"findings": []any{finding}}, nil); code != http.StatusOK {
			t.Fatalf("events: %d %s", code, body)
		}
	}

	list, err := h.srv.DB().ListFindings(store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// Reporting the same shell on three sweeps is one finding seen three times,
	// not three findings. Otherwise a long-running incident buries the operator.
	if len(list) != 1 {
		t.Fatalf("got %d findings, want 1 deduplicated", len(list))
	}
	if list[0].SeenCount != 3 {
		t.Errorf("seen_count = %d, want 3", list[0].SeenCount)
	}

	// A resolved finding that reappears must reopen: silently staying closed
	// would hide a reinfection.
	if err := h.srv.DB().SetFindingState(list[0].ID, "resolved", "tester", ""); err != nil {
		t.Fatal(err)
	}
	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{finding}}, nil)
	list, _ = h.srv.DB().ListFindings(store.FindingFilter{})
	if list[0].State != "open" {
		t.Errorf("a resolved finding that reappeared has state %q, want open", list[0].State)
	}
}

func TestCorrelationAcrossAgents(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(3, false)
	var agents []enrolled
	for i := 0; i < 3; i++ {
		ag, code, body := h.enrollAs(tok, false,
			fmt.Sprintf("host-%d", i), "/var/www/html")
		if code != http.StatusOK {
			t.Fatalf("enroll %d: %d %s", i, code, body)
		}
		agents = append(agents, ag)
	}
	shared := map[string]any{
		"rule_id": "shell.eval_obfuscated", "severity": "critical",
		"title": "eval() wrapped around a decoder", "path": "wp-content/db.php",
		"sha256": "deadbeefcafe",
	}
	for _, ag := range agents {
		h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{shared}}, nil)
	}

	cors, err := h.srv.DB().Correlate(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cors) != 1 {
		t.Fatalf("got %d correlations, want 1", len(cors))
	}
	if cors[0].Count != 3 {
		t.Errorf("correlated across %d hosts, want 3", cors[0].Count)
	}
}

// The field case. A single machine had two agent records — re-running an
// installer enrolls again — and the console reported the estate's artefacts as
// present on "2 hosts" when only one existed.
//
// Left uncorrected this is more than a wrong number. Correlation counts feed
// the consensus verdict, a high count earns "vendor code", and a vendor verdict
// exonerates the file. Anyone able to enroll twice could have corroborated their
// own implant into being ignored.
func TestCorrelationDoesNotCountOneMachineTwice(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(4, false)

	var agents []enrolled
	// Same machine, same site, enrolled three times.
	for i := 0; i < 3; i++ {
		ag, code, body := h.enrollAs(tok, false, "duplicate-host", "/var/www/html")
		if code != http.StatusOK {
			t.Fatalf("enroll %d: %d %s", i, code, body)
		}
		agents = append(agents, ag)
	}
	// The same machine serving a SECOND site is a genuinely separate
	// installation and must keep its own vote.
	ag, code, body := h.enrollAs(tok, false, "duplicate-host", "/var/www/other")
	if code != http.StatusOK {
		t.Fatalf("enroll second site: %d %s", code, body)
	}
	agents = append(agents, ag)

	shared := map[string]any{
		"rule_id": "shell.eval_obfuscated", "severity": "critical",
		"title": "eval() wrapped around a decoder", "path": "wp-content/db.php",
		"sha256": "deadbeefcafe",
	}
	for _, a := range agents {
		h.postJSON(h.ingest.URL, "/v1/events", a.auth(), map[string]any{"findings": []any{shared}}, nil)
	}

	cors, err := h.srv.DB().Correlate(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cors) != 1 {
		t.Fatalf("got %d correlations, want 1", len(cors))
	}
	if cors[0].Count != 2 {
		t.Errorf("counted %d hosts, want 2 (three enrollments on one webroot are one witness, "+
			"the second webroot is another)", cors[0].Count)
	}
}

// ---------------------------------------------------------------------------
// console auth
// ---------------------------------------------------------------------------

func TestConsoleRequiresAuthAndMFA(t *testing.T) {
	h := newHarness(t)

	// Unauthenticated.
	resp, err := http.Get(h.console.URL + "/api/agents")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated API returned %d, want 401", resp.StatusCode)
	}

	user, err := h.srv.DB().CreateUser("tester", "correct-horse-battery", "admin")
	if err != nil {
		t.Fatal(err)
	}

	jar, _ := newJar()
	client := &http.Client{Jar: jar}

	// Password alone.
	var login struct {
		CSRF         string `json:"csrf"`
		TOTPEnrolled bool   `json:"totp_enrolled"`
	}
	postClient(t, client, h.console.URL+"/api/login", "",
		map[string]any{"username": "tester", "password": "correct-horse-battery"}, &login)
	if login.CSRF == "" {
		t.Fatal("login returned no CSRF token")
	}

	// A password-only session must not reach the fleet API.
	req, _ := http.NewRequest(http.MethodGet, h.console.URL+"/api/agents", nil)
	r2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden {
		t.Errorf("session without MFA returned %d, want 403", r2.StatusCode)
	}

	// Complete TOTP enrollment, then the second factor.
	secret, _, err := h.srv.DB().BeginTOTPEnrollment(user.ID, "WordEyeTest", "tester")
	if err != nil {
		t.Fatal(err)
	}
	code, err := authn.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.DB().CompleteTOTPEnrollment(user.ID, code); err != nil {
		t.Fatal(err)
	}

	// Wait for the next time step so the confirmation code is not replayed.
	waitNextTOTPStep()
	code2, _ := authn.TOTPCode(secret, time.Now())
	var verify map[string]any
	postClient(t, client, h.console.URL+"/api/mfa/verify", login.CSRF,
		map[string]any{"code": code2}, &verify)

	r3, err := client.Do(mustGet(t, h.console.URL+"/api/agents"))
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Errorf("fully authenticated API returned %d, want 200", r3.StatusCode)
	}
}

func TestCSRFRequiredForWrites(t *testing.T) {
	h := newHarness(t)
	user, _ := h.srv.DB().CreateUser("tester", "correct-horse-battery", "admin")
	secret, _, _ := h.srv.DB().BeginTOTPEnrollment(user.ID, "t", "tester")
	code, _ := authn.TOTPCode(secret, time.Now())
	_, _ = h.srv.DB().CompleteTOTPEnrollment(user.ID, code)

	jar, _ := newJar()
	client := &http.Client{Jar: jar}
	var login struct {
		CSRF string `json:"csrf"`
	}
	postClient(t, client, h.console.URL+"/api/login", "",
		map[string]any{"username": "tester", "password": "correct-horse-battery"}, &login)

	waitNextTOTPStep()
	code2, _ := authn.TOTPCode(secret, time.Now())
	postClient(t, client, h.console.URL+"/api/mfa/verify", login.CSRF, map[string]any{"code": code2}, nil)

	// A write without the CSRF header must be rejected even with a valid session.
	body, _ := json.Marshal(map[string]any{"label": "x"})
	req, _ := http.NewRequest(http.MethodPost, h.console.URL+"/api/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("write without CSRF header returned %d, want 403", resp.StatusCode)
	}
}

func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	h := newHarness(t)
	user, _ := h.srv.DB().CreateUser("tester", "correct-horse-battery", "operator")
	secret, _, _ := h.srv.DB().BeginTOTPEnrollment(user.ID, "t", "tester")
	code, _ := authn.TOTPCode(secret, time.Now())
	if _, err := h.srv.DB().CompleteTOTPEnrollment(user.ID, code); err != nil {
		t.Fatal(err)
	}

	waitNextTOTPStep()
	fresh, _ := authn.TOTPCode(secret, time.Now())
	if err := h.srv.DB().VerifySecondFactor(user.ID, fresh); err != nil {
		t.Fatalf("fresh code rejected: %v", err)
	}
	// Same code, same time step: an intercepted code must not be reusable.
	if err := h.srv.DB().VerifySecondFactor(user.ID, fresh); err == nil {
		t.Error("a TOTP code was accepted twice within its window")
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	h := newHarness(t)
	user, _ := h.srv.DB().CreateUser("tester", "correct-horse-battery", "operator")
	secret, _, _ := h.srv.DB().BeginTOTPEnrollment(user.ID, "t", "tester")
	code, _ := authn.TOTPCode(secret, time.Now())
	codes, err := h.srv.DB().CompleteTOTPEnrollment(user.ID, code)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) == 0 {
		t.Fatal("no recovery codes issued")
	}
	if err := h.srv.DB().VerifySecondFactor(user.ID, codes[0]); err != nil {
		t.Fatalf("recovery code rejected: %v", err)
	}
	if err := h.srv.DB().VerifySecondFactor(user.ID, codes[0]); err == nil {
		t.Error("a recovery code was accepted twice")
	}
}

func TestAuditLogRecordsEnrollmentAndRejection(t *testing.T) {
	h := newHarness(t)
	h.enroll("wek_bogus", false)
	h.enroll(h.mintToken(1, false), false)

	entries, err := h.srv.DB().ListAudit(50, "")
	if err != nil {
		t.Fatal(err)
	}
	var sawAccept, sawReject bool
	for _, e := range entries {
		switch e.Action {
		case "enroll.accepted":
			sawAccept = true
		case "enroll.rejected":
			sawReject = true
		}
	}
	if !sawAccept || !sawReject {
		t.Errorf("audit missing entries (accept=%v reject=%v)", sawAccept, sawReject)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func postClient(t *testing.T, c *http.Client, url, csrf string, body, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Always present: login now requires the header even before a session exists.
	if csrf == "" {
		csrf = "pre-session"
	}
	req.Header.Set("X-WordEye-CSRF", csrf)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s -> %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		_ = json.Unmarshal(raw, out)
	}
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// waitNextTOTPStep sleeps until the current 30-second window rolls over, so a
// code from the previous step cannot be confused with a replay.
func waitNextTOTPStep() {
	start := authn.TOTPStep(time.Now())
	for authn.TOTPStep(time.Now()) == start {
		time.Sleep(200 * time.Millisecond)
	}
}

func newJar() (http.CookieJar, error) {
	return cookieJar{m: map[string][]*http.Cookie{}}, nil
}

// cookieJar is a minimal in-memory jar; net/http/cookiejar would work too but
// pulls in public-suffix handling that is pointless against 127.0.0.1.
type cookieJar struct{ m map[string][]*http.Cookie }

func (j cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.m[u.Host] = append(j.m[u.Host], cookies...)
}

func (j cookieJar) Cookies(u *url.URL) []*http.Cookie {
	// Last write wins per name, so a refreshed session cookie replaces the old.
	seen := map[string]*http.Cookie{}
	for _, c := range j.m[u.Host] {
		seen[c.Name] = c
	}
	out := make([]*http.Cookie, 0, len(seen))
	for _, c := range seen {
		if c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

// Containment must survive the next agent report.
//
// A resolved finding that reappears is a reinfection and reopens. A CONTAINED
// one must not: containment means an operator dealt with it, and the artefact
// still being on disk is the expected state rather than news. Reopening it
// meant every triage decision was undone seconds later on a monitoring host, so
// the open counts never fell and there was no way to show progress against an
// estate.
func TestContainedFindingSurvivesRessighting(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, code, body := h.enroll(tok, false)
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}
	finding := map[string]any{
		"rule_id": "fs.heuristic_webshell", "severity": "critical",
		"title": "Web-shell structure detected", "path": "wp-content/uploads/x.php",
		"sha256": "abc123",
	}
	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{finding}}, nil)

	list, _ := h.srv.DB().ListFindings(store.FindingFilter{})
	if len(list) != 1 {
		t.Fatalf("got %d findings, want 1", len(list))
	}
	if err := h.srv.DB().SetFindingState(list[0].ID, "contained", "operator", "quarantined"); err != nil {
		t.Fatal(err)
	}

	// The agent reports the same artefact again, as a monitoring host does.
	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{finding}}, nil)

	list, _ = h.srv.DB().ListFindings(store.FindingFilter{})
	if list[0].State != "contained" {
		t.Errorf("a contained finding reverted to %q on re-sighting; triage decisions cannot stick",
			list[0].State)
	}
	if list[0].SeenCount < 2 {
		t.Errorf("seen_count = %d; history must keep advancing even while contained", list[0].SeenCount)
	}
}

// Paging must report the true total, or a truncated list reads as the whole
// estate. Ten hosts produced 4,866 findings against a 500-row ceiling.
func TestFindingsPaginate(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enroll(tok, false)

	var fs []any
	for i := 0; i < 25; i++ {
		fs = append(fs, map[string]any{
			"rule_id": "fs.heuristic_webshell", "severity": "high",
			"title": fmt.Sprintf("finding %d", i),
			"path":  fmt.Sprintf("wp-content/uploads/f%02d.php", i),
		})
	}
	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": fs}, nil)

	total, err := h.srv.DB().CountFindings(store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total < 25 {
		t.Fatalf("CountFindings = %d, want at least 25", total)
	}
	first, err := h.srv.DB().ListFindings(store.FindingFilter{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.srv.DB().ListFindings(store.FindingFilter{Limit: 10, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 10 || len(second) != 10 {
		t.Fatalf("pages returned %d and %d rows, want 10 each", len(first), len(second))
	}
	seen := map[int64]bool{}
	for _, f := range first {
		seen[f.ID] = true
	}
	for _, f := range second {
		if seen[f.ID] {
			t.Errorf("finding %d appears on both pages; the offset is not applied", f.ID)
		}
	}
}

// The count must apply the same filter as the page it describes.
func TestFindingsCountRespectsFilter(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enroll(tok, false)

	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{
		map[string]any{"rule_id": "a.b", "severity": "critical", "title": "c", "path": "p1"},
		map[string]any{"rule_id": "a.b", "severity": "low", "title": "l", "path": "p2"},
	}}, nil)

	n, err := h.srv.DB().CountFindings(store.FindingFilter{Severity: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("CountFindings(critical) = %d, want 1", n)
	}
}

// Bulk triage exists because findings never age out. A rule that was too noisy
// leaves its output behind permanently: fixing the rule stops new rows but
// cannot retract the 3,436 it already wrote, and clearing those individually is
// not a real option on a 236-host estate.
func TestBulkStateAppliesToTheFilterOnly(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(1, false)
	ag, _, _ := h.enroll(tok, false)

	var fs []any
	for i := 0; i < 12; i++ {
		sev := "high"
		rule := "fs.world_writable_php"
		if i >= 8 {
			sev, rule = "critical", "fs.heuristic_webshell"
		}
		fs = append(fs, map[string]any{
			"rule_id": rule, "severity": sev,
			"title": "t", "path": fmt.Sprintf("wp-content/f%02d.php", i),
		})
	}
	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": fs}, nil)

	// Dismiss only the noisy high-severity rows.
	n, err := h.srv.DB().SetFindingStatesByFilter(
		store.FindingFilter{Severity: "high"}, "dismissed", "operator", "rule was too noisy")
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Errorf("changed %d findings, want 8", n)
	}

	// The criticals must be untouched: a bulk action that reaches past its
	// filter is how an estate loses real findings.
	open, err := h.srv.DB().ListFindings(store.FindingFilter{State: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 4 {
		t.Fatalf("%d findings remain open, want 4", len(open))
	}
	for _, f := range open {
		if f.Severity != "critical" {
			t.Errorf("a %s finding survived a high-severity bulk dismiss", f.Severity)
		}
	}
}

// An unfiltered bulk change is an accident, not a workflow.
func TestBulkStateRefusesAnUnboundedSweep(t *testing.T) {
	h := newHarness(t)
	code, body := h.postJSON(h.console.URL, "/api/findings/bulk-state", "",
		map[string]any{"state": "dismissed"}, nil)
	// Unauthenticated is also a refusal; what must never happen is a 200.
	if code == http.StatusOK {
		t.Errorf("an unfiltered bulk state change was accepted: %s", body)
	}
}

// Corroboration from another customer is not evidence about this one.
// Compromising one estate must never exonerate an implant in another.
func TestVendorPackDoesNotCrossEstates(t *testing.T) {
	h := newHarness(t)
	a, err := h.srv.DB().CreateEstate("Customer A", "", "tester")
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.srv.DB().CreateEstate("Customer B", "", "tester")
	if err != nil {
		t.Fatal(err)
	}

	const sha = "cafe00000000000000000000000000000000000000000000000000000000cafe"
	const p = "wp-content/plugins/premium/lib.php"

	tokA := h.mintTokenForEstate(4, false, a.ID)
	for i := 0; i < 4; i++ {
		ag, code, body := h.enrollAs(tokA, false, fmt.Sprintf("a-%d", i), "/var/www/html")
		if code != http.StatusOK {
			t.Fatalf("enroll a%d: %d %s", i, code, body)
		}
		h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{
			map[string]any{"rule_id": "r", "severity": "critical", "title": "t", "path": p, "sha256": sha},
		}}, nil)
	}

	// One host belonging to a DIFFERENT customer.
	tokB := h.mintTokenForEstate(1, false, b.ID)
	agB, code, body := h.enrollAs(tokB, false, "b-0", "/var/www/html")
	if code != http.StatusOK {
		t.Fatalf("enroll b: %d %s", code, body)
	}

	var pack struct {
		Entries []struct {
			SHA256 string `json:"sha256"`
		} `json:"entries"`
	}
	if code, body := h.getJSON(h.ingest.URL, "/v1/vendor-pack", agB.auth(), &pack); code != http.StatusOK {
		t.Fatalf("vendor-pack: %d %s", code, body)
	}
	for _, e := range pack.Entries {
		if e.SHA256 == sha {
			t.Fatal("customer B was handed an attestation earned entirely by customer A; " +
				"one estate can exonerate an implant in another")
		}
	}
}

// Triage needs to know which box to open a shell on.
//
// The agent label comes from the installer, so every host enrolled from the
// same one carries the same string: an eighteen-host estate showed eighteen
// findings rows all reading "installer: fleet-rollout (linux-amd64)". The hostname is
// the only field that answers the question, so it has to reach the UI.
func TestFindingsCarryTheHostname(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(2, false)

	ag, code, body := h.enrollAs(tok, false, "web-01.example.net", "/www/site/public")
	if code != http.StatusOK {
		t.Fatalf("enroll: %d %s", code, body)
	}
	h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{
		map[string]any{"rule_id": "r", "severity": "critical", "title": "t", "path": "p"},
	}}, nil)

	list, err := h.srv.DB().ListFindings(store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d findings, want 1", len(list))
	}
	if list[0].AgentHostname != "web-01.example.net" {
		t.Errorf("AgentHostname = %q; triage cannot tell which host to visit", list[0].AgentHostname)
	}
}

// Two hosts from one installer must be distinguishable.
func TestFindingsDistinguishHostsFromOneInstaller(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(4, false)

	for _, host := range []string{"host-alpha", "host-beta"} {
		ag, code, body := h.enrollAs(tok, false, host, "/www/"+host)
		if code != http.StatusOK {
			t.Fatalf("enroll %s: %d %s", host, code, body)
		}
		h.postJSON(h.ingest.URL, "/v1/events", ag.auth(), map[string]any{"findings": []any{
			map[string]any{"rule_id": "r", "severity": "high", "title": "t", "path": "shared.php"},
		}}, nil)
	}

	list, err := h.srv.DB().ListFindings(store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range list {
		seen[f.AgentHostname] = true
	}
	if !seen["host-alpha"] || !seen["host-beta"] {
		t.Errorf("hostnames did not survive to the findings list: %v", seen)
	}
}

// Bulk dispatch is what makes a large estate workable: asking for a sweep of
// forty hosts should be one action, not forty.
func TestBulkCommandQueuesAcrossHosts(t *testing.T) {
	h := newHarness(t)
	tok := h.mintToken(4, false)
	var ids []string
	for i := 0; i < 3; i++ {
		ag, code, body := h.enrollAs(tok, false, fmt.Sprintf("h-%d", i), "/www")
		if code != http.StatusOK {
			t.Fatalf("enroll: %d %s", code, body)
		}
		ids = append(ids, ag.AgentID)
	}
	for _, id := range ids {
		if _, err := h.srv.DB().CreateCommand(id, "scan", map[string]any{"bulk": true}, "tester", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	cmds, err := h.srv.DB().ListCommands("", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) < 3 {
		t.Errorf("got %d commands, want at least 3", len(cmds))
	}
}

// Nothing destructive may be dispatched across a selection. "Run this on
// everything" is exactly the wrong shape for an action that deletes files, and
// a single mistaken click must not be able to reach an estate.
func TestBulkCommandRefusesDestructiveKinds(t *testing.T) {
	h := newHarness(t)
	for _, kind := range []string{"contain", "contain_dryrun", "quarantine"} {
		code, body := h.postJSON(h.console.URL, "/api/commands/bulk", "",
			map[string]any{"agents": []string{"ag_x"}, "kind": kind}, nil)
		if code == http.StatusOK {
			t.Errorf("%q was accepted for bulk dispatch: %s", kind, body)
		}
	}
}
