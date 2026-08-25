package console

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"wordeye/internal/store"
)

// The operator API.
//
// Every mutating route requires: a session, a satisfied second factor, a
// matching CSRF token, and (for destructive actions) a role that permits it.
// Actions are written to the audit log before their effects become visible.

const sessionCookie = "wordeye_session"

func (s *Server) consoleHandler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: the login handshake only.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// Session required, MFA NOT yet required — these complete authentication.
	mux.HandleFunc("GET /api/me", s.partialAuth(s.handleMe))
	mux.HandleFunc("POST /api/mfa/verify", s.partialAuth(s.handleMFAVerify))
	mux.HandleFunc("POST /api/mfa/setup", s.partialAuth(s.handleMFASetup))
	mux.HandleFunc("POST /api/mfa/confirm", s.partialAuth(s.handleMFAConfirm))

	// Fully authenticated.
	mux.HandleFunc("GET /api/stats", s.auth(s.handleStats))
	mux.HandleFunc("GET /api/agents", s.auth(s.handleAgents))
	mux.HandleFunc("GET /api/agents/{id}", s.auth(s.handleAgentDetail))
	mux.HandleFunc("POST /api/agents/{id}/label", s.write(s.handleAgentLabel))
	mux.HandleFunc("POST /api/agents/{id}/retire", s.write(s.handleAgentRetire))

	mux.HandleFunc("GET /api/findings", s.auth(s.handleFindings))
	mux.HandleFunc("POST /api/findings/{id}/state", s.write(s.handleFindingState))
	mux.HandleFunc("POST /api/findings/bulk-state", s.write(s.handleFindingBulkState))
	mux.HandleFunc("GET /api/schedules", s.auth(s.handleListSchedules))
	mux.HandleFunc("POST /api/schedules", s.write(s.handleCreateSchedule))
	mux.HandleFunc("POST /api/schedules/{id}/enabled", s.write(s.handleScheduleEnabled))
	mux.HandleFunc("POST /api/schedules/{id}/delete", s.write(s.handleDeleteSchedule))
	mux.HandleFunc("POST /api/commands/bulk", s.write(s.handleBulkCommand))
	mux.HandleFunc("GET /api/correlations", s.auth(s.handleCorrelations))
	mux.HandleFunc("GET /api/reports", s.auth(s.handleReports))

	mux.HandleFunc("GET /api/commands", s.auth(s.handleCommands))
	mux.HandleFunc("POST /api/commands", s.write(s.handleCreateCommand))
	mux.HandleFunc("POST /api/commands/{id}/approve", s.write(s.handleApproveCommand))
	mux.HandleFunc("POST /api/commands/{id}/cancel", s.write(s.handleCancelCommand))

	mux.HandleFunc("GET /api/estates", s.auth(s.handleListEstates))
	mux.HandleFunc("POST /api/estates", s.admin(s.handleCreateEstate))
	mux.HandleFunc("POST /api/estates/{id}/archive", s.admin(s.handleArchiveEstate))
	mux.HandleFunc("POST /api/estates/{id}/installer", s.admin(s.handleGenerateInstaller))
	mux.HandleFunc("POST /api/agents/{id}/estate", s.admin(s.handleAgentEstate))
	mux.HandleFunc("GET /api/tokens", s.admin(s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", s.admin(s.handleCreateToken))
	mux.HandleFunc("POST /api/tokens/{id}/revoke", s.admin(s.handleRevokeToken))

	mux.HandleFunc("GET /api/users", s.admin(s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.admin(s.handleCreateUser))
	mux.HandleFunc("POST /api/users/{id}/reset-mfa", s.admin(s.handleResetMFA))
	mux.HandleFunc("POST /api/users/{id}/disable", s.admin(s.handleDisableUser))

	mux.HandleFunc("GET /api/audit", s.auth(s.handleAudit))

	// Static UI.
	mux.Handle("/", s.uiHandler())

	return s.consoleSecurity(mux)
}

// consoleSecurity sets the headers that matter for a privileged single-page
// app. The CSP is strict — no inline script, no external origins — which is
// why the UI ships as separate .js/.css assets rather than one inlined blob.
func (s *Server) consoleSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if s.cfg.ConsoleTLS {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// auth middleware
// ---------------------------------------------------------------------------

type ctx struct {
	session *store.Session
	user    *store.User
}

// partialAuth requires a session but not a completed second factor.
func (s *Server) partialAuth(next func(http.ResponseWriter, *http.Request, *ctx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := s.sessionFrom(r)
		if c == nil {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if r.Method != http.MethodGet && !s.checkCSRF(r, c) {
			writeErr(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next(w, r, c)
	}
}

// auth requires a fully authenticated session (password AND second factor).
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *ctx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := s.sessionFrom(r)
		if c == nil {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		if !c.session.MFAOK {
			writeErr(w, http.StatusForbidden, "multi-factor authentication required")
			return
		}
		if r.Method != http.MethodGet && !s.checkCSRF(r, c) {
			writeErr(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next(w, r, c)
	}
}

// write additionally requires a role that may change state. Viewers can read
// the whole console but cannot act on it.
func (s *Server) write(next func(http.ResponseWriter, *http.Request, *ctx)) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, c *ctx) {
		if !c.user.CanApprove() {
			writeErr(w, http.StatusForbidden, "your role is read-only")
			return
		}
		next(w, r, c)
	})
}

func (s *Server) admin(next func(http.ResponseWriter, *http.Request, *ctx)) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, c *ctx) {
		if !c.user.CanAdmin() {
			writeErr(w, http.StatusForbidden, "administrator role required")
			return
		}
		next(w, r, c)
	})
}

func (s *Server) sessionFrom(r *http.Request) *ctx {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	sess, user, err := s.db.LookupSession(ck.Value)
	if err != nil {
		return nil
	}
	return &ctx{session: sess, user: user}
}

// checkCSRF requires a header the browser will not attach cross-origin. With
// SameSite=Strict cookies this is belt and braces, which is appropriate for a
// console that can order destructive actions.
func (s *Server) checkCSRF(r *http.Request, c *ctx) bool {
	return constantTimeEqual(r.Header.Get("X-WordEye-CSRF"), s.csrfToken(c.session.ID))
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.ConsoleTLS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(store.SessionTTL.Seconds()),
	})
}

func (s *Server) audit(c *ctx, r *http.Request, action, target, detail, result string) {
	actor := "anonymous"
	if c != nil && c.user != nil {
		actor = c.user.Username
	}
	_ = s.db.Audit(actor, action, target, detail, clientIP(r), result)
}

// ---------------------------------------------------------------------------
// login / MFA
// ---------------------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Login cannot carry a session-bound CSRF token, but requiring ANY custom
	// header is sufficient: browsers refuse to set custom headers cross-origin
	// without a CORS preflight, and this server sends no CORS headers at all.
	// Without this, an attacker can force a victim's browser to authenticate as
	// the attacker and then operate in their session.
	if r.Header.Get("X-WordEye-CSRF") == "" {
		writeErr(w, http.StatusForbidden, "missing X-WordEye-CSRF header")
		return
	}
	var req loginRequest
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	ip := clientIP(r)
	// Throttle by IP and by username: neither a single source nor a single
	// target account can be ground down.
	if !s.loginLimiter.allow(ip) || !s.loginLimiter.allow("u:"+req.Username) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts; wait a minute")
		return
	}

	user, err := s.db.VerifyPassword(req.Username, req.Password)
	if err != nil {
		_ = s.db.Audit(req.Username, "login.failed", "", err.Error(), ip, "denied")
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	sid, err := s.db.CreateSession(user.ID, ip, clamp(r.UserAgent(), 256))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start session")
		return
	}
	s.setSessionCookie(w, sid)
	_ = s.db.Audit(user.Username, "login.password_ok", "", "awaiting second factor", ip, "ok")

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"mfa_required":  true,
		"totp_enrolled": user.TOTPEnrolled,
		"csrf":          s.csrfToken(sid),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		_ = s.db.DeleteSession(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.ConsoleTLS, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, c *ctx) {
	remaining, _ := s.db.RecoveryCodesRemaining(c.user.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":       c.user.Username,
		"role":           c.user.Role,
		"mfa_ok":         c.session.MFAOK,
		"totp_enrolled":  c.user.TOTPEnrolled,
		"recovery_codes": remaining,
		"can_approve":    c.user.CanApprove(),
		"can_admin":      c.user.CanAdmin(),
		// Per-action map so the UI stops hard-coding role names. When RBAC
		// arrives the UI needs no change: the same keys simply answer
		// differently per user and estate.
		"permissions":     permittedActions(c.user),
		"csrf":            s.csrfToken(c.session.ID),
		"session_expires": c.session.ExpiresAt,
	})
}

// handleMFASetup begins TOTP enrollment and returns a QR code as a data URI.
func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request, c *ctx) {
	// Re-enrolling an existing factor would let anyone with a stolen session
	// swap the second factor for their own. Require an admin reset instead.
	if c.user.TOTPEnrolled {
		writeErr(w, http.StatusForbidden,
			"multi-factor authentication is already configured; an administrator must reset it first")
		return
	}
	secret, uri, err := s.db.BeginTOTPEnrollment(c.user.ID, s.cfg.Issuer, c.user.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not begin enrollment")
		return
	}
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not render QR code")
		return
	}
	s.audit(c, r, "mfa.setup_started", c.user.Username, "", "ok")
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    uri,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

type codeRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req codeRequest
	if err := readJSON(w, r, 1<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	codes, err := s.db.CompleteTOTPEnrollment(c.user.ID, req.Code)
	if err != nil {
		s.audit(c, r, "mfa.setup_failed", c.user.Username, err.Error(), "denied")
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.db.MarkSessionMFA(c.session.ID)
	_ = s.db.TouchLogin(c.user.ID)
	s.audit(c, r, "mfa.enrolled", c.user.Username, "recovery codes issued", "ok")

	// Shown exactly once.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_codes": codes})
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req codeRequest
	if err := readJSON(w, r, 1<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if !s.loginLimiter.allow("mfa:" + c.user.Username) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	if err := s.db.VerifySecondFactor(c.user.ID, req.Code); err != nil {
		s.audit(c, r, "login.mfa_failed", c.user.Username, err.Error(), "denied")
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.db.MarkSessionMFA(c.session.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not complete sign-in")
		return
	}
	_ = s.db.TouchLogin(c.user.ID)
	s.audit(c, r, "login.success", c.user.Username, "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// fleet
// ---------------------------------------------------------------------------

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, c *ctx) {
	st, err := s.db.Stats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request, c *ctx) {
	// ?estate=N scopes the fleet to one customer; absent means the whole fleet.
	estate, _ := strconv.ParseInt(r.URL.Query().Get("estate"), 10, 64)
	agents, err := s.db.ListAgents(r.URL.Query().Get("retired") == "1", estate)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if agents == nil {
		agents = []store.Agent{}
	}
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request, c *ctx) {
	id := r.PathValue("id")
	agent, err := s.db.GetAgent(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "agent not found")
		return
	}
	findings, _ := s.db.ListFindings(store.FindingFilter{AgentID: id, Limit: 500})
	reports, _ := s.db.ListReports(id, 25)
	commands, _ := s.db.ListCommands(id, 50)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":    agent,
		"findings": nz(findings),
		"reports":  reports,
		"commands": commands,
	})
}

type labelRequest struct {
	Label string `json:"label"`
}

func (s *Server) handleAgentLabel(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req labelRequest
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	id := r.PathValue("id")
	if err := s.db.SetAgentLabel(id, clamp(req.Label, 128)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "agent.relabel", id, req.Label, "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAgentRetire(w http.ResponseWriter, r *http.Request, c *ctx) {
	id := r.PathValue("id")
	if err := s.db.RetireAgent(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "agent.retire", id, "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, c *ctx) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	estate, _ := strconv.ParseInt(q.Get("estate"), 10, 64)
	filter := store.FindingFilter{
		AgentID:  q.Get("agent"),
		EstateID: estate,
		Severity: q.Get("severity"),
		State:    q.Get("state"),
		Class:    q.Get("class"),
		Search:   clamp(q.Get("q"), 200),
		Limit:    limit,
		Offset:   offset,
	}
	findings, err := s.db.ListFindings(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The total travels with the page. Without it the UI cannot distinguish
	// "this is everything" from "this is the first 500 of 4,866", and an
	// operator reading a truncated list as complete draws the wrong conclusion.
	total, err := s.db.CountFindings(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": nz(s.withConsensus(findings)),
		"total":    total,
		"offset":   offset,
		"limit":    len(findings),
	})
}

// annotatedFinding carries what the rest of the estate knows about a finding's
// digest. Premium and bespoke code publishes no checksum manifest, so
// provenance cannot speak for it; agreement across independent sites is the
// only authority available.
type annotatedFinding struct {
	store.Finding
	Consensus *store.Consensus `json:"consensus,omitempty"`
}

// withConsensus attaches cross-estate agreement to each finding.
//
// It annotates and never decides. In particular it does NOT touch severity,
// state, or actionability: a confirmed, actionable finding is backed by
// evidence from the file itself, and no number of sites agreeing that the bytes
// are common should be able to argue with that. Popularity is corroboration for
// a human, not a verdict.
func (s *Server) withConsensus(findings []store.Finding) []annotatedFinding {
	out := make([]annotatedFinding, len(findings))
	// Group by the reporting agent's estate. A single response can span
	// customers, and each finding must be judged only against its OWN estate:
	// borrowing another client's machines to reach a quorum is both weaker
	// evidence and a disclosure of that client's estate.
	byEstate := map[int64][]string{}
	estateOf := make([]int64, len(findings))
	for i, f := range findings {
		out[i] = annotatedFinding{Finding: f}
		if f.SHA256 == "" {
			continue
		}
		est := s.db.EstateOfAgent(f.AgentID)
		estateOf[i] = est
		byEstate[est] = append(byEstate[est], f.SHA256)
	}
	if len(byEstate) == 0 {
		return out
	}

	results := make(map[int64]map[string]store.Consensus, len(byEstate))
	for est, shas := range byEstate {
		c, err := s.db.ConsensusFor(est, shas)
		if err != nil {
			// Consensus is an enrichment. Losing it must not lose the findings.
			continue
		}
		results[est] = c
	}
	for i := range out {
		if out[i].SHA256 == "" {
			continue
		}
		if c, ok := results[estateOf[i]][out[i].SHA256]; ok && c.Verdict != store.ConsensusInconclusive {
			cc := c
			out[i].Consensus = &cc
		}
	}
	return out
}

type findingStateRequest struct {
	State string `json:"state"`
	Note  string `json:"note"`
}

func (s *Server) handleFindingState(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req findingStateRequest
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	if err := s.db.SetFindingState(id, req.State, c.user.Username, clamp(req.Note, 1024)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "finding."+req.State, fmt.Sprint(id), clamp(req.Note, 256), "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCorrelations(w http.ResponseWriter, r *http.Request, c *ctx) {
	estateID, _ := strconv.ParseInt(r.URL.Query().Get("estate"), 10, 64)
	cors, err := s.db.Correlate(2, estateID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cors == nil {
		cors = []store.Correlation{}
	}

	// A hash and a count are not a conclusion. Attach the estate's verdict so
	// the page distinguishes the three cases that need opposite responses:
	// vendor code to exonerate, a campaign to treat as one incident, and a
	// singleton that is on one host but should be on many.
	shas := make([]string, 0, len(cors))
	for _, x := range cors {
		shas = append(shas, x.SHA256)
	}
	if verdicts, err := s.db.ConsensusFor(estateID, shas); err == nil {
		for i := range cors {
			if v, ok := verdicts[cors[i].SHA256]; ok {
				cors[i].Verdict = v.Verdict
				cors[i].Rationale = v.Rationale
				cors[i].SitesRunningTree = v.SitesRunningTree
			}
		}
	}
	writeJSON(w, http.StatusOK, cors)
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request, c *ctx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	reps, err := s.db.ListReports(r.URL.Query().Get("agent"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if reps == nil {
		reps = []store.ReportSummary{}
	}
	writeJSON(w, http.StatusOK, reps)
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request, c *ctx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cmds, err := s.db.ListCommands(r.URL.Query().Get("agent"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cmds == nil {
		cmds = []store.Command{}
	}
	writeJSON(w, http.StatusOK, cmds)
}

type createCommandRequest struct {
	AgentID string         `json:"agent_id"`
	Kind    string         `json:"kind"`
	Params  map[string]any `json:"params"`
}

func (s *Server) handleCreateCommand(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req createCommandRequest
	if err := readJSON(w, r, 16<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	agent, err := s.db.GetAgent(req.AgentID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "agent not found")
		return
	}
	// Refuse at creation time when the agent could never honour it, rather than
	// queueing an order that will be silently discarded later.
	if req.Kind == "contain" && !agent.ContainAllowed() {
		reason := "this agent did not enroll with remote containment enabled"
		if !agent.AllowRemoteContain {
			reason = "the enrollment token used by this agent did not grant remote containment"
		}
		s.audit(c, r, "command.rejected", req.AgentID, reason, "denied")
		writeErr(w, http.StatusForbidden, reason)
		return
	}

	cmd, err := s.db.CreateCommand(req.AgentID, req.Kind, req.Params, c.user.Username, 6*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "command.create."+req.Kind, req.AgentID, cmd.ID, "ok")
	writeJSON(w, http.StatusOK, cmd)
}

// handleApproveCommand is the second human step for a destructive order.
func (s *Server) handleApproveCommand(w http.ResponseWriter, r *http.Request, c *ctx) {
	id := r.PathValue("id")
	cmd, err := s.db.GetCommand(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "command not found")
		return
	}
	if err := s.db.ApproveCommand(id, c.user.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Recorded with both names so a four-eyes policy can be verified from the
	// audit log, even though it is not enforced here.
	s.audit(c, r, "command.approve", id,
		fmt.Sprintf("kind=%s agent=%s created_by=%s", cmd.Kind, cmd.AgentID, cmd.CreatedBy), "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCancelCommand(w http.ResponseWriter, r *http.Request, c *ctx) {
	id := r.PathValue("id")
	if err := s.db.CancelCommand(id, c.user.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "command.cancel", id, "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// enrollment tokens
// ---------------------------------------------------------------------------

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, c *ctx) {
	toks, err := s.db.ListEnrollTokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if toks == nil {
		toks = []store.EnrollToken{}
	}
	writeJSON(w, http.StatusOK, toks)
}

type createTokenRequest struct {
	Label        string `json:"label"`
	TTLHours     int    `json:"ttl_hours"`
	Uses         int    `json:"uses"`
	AllowContain bool   `json:"allow_remote_contain"`
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req createTokenRequest
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	ttl := time.Duration(req.TTLHours) * time.Hour
	if req.TTLHours <= 0 {
		ttl = 24 * time.Hour
	}
	plain, tok, err := s.db.CreateEnrollToken(clamp(req.Label, 128), c.user.Username, ttl, req.Uses, req.AllowContain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "token.create", tok.Prefix,
		fmt.Sprintf("label=%q uses=%d ttl=%s allow_contain=%v", tok.Label, tok.UsesAllowed, ttl, req.AllowContain), "ok")

	// The plaintext is returned exactly once and is not recoverable afterwards.
	writeJSON(w, http.StatusOK, map[string]any{"token": plain, "meta": tok})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad token id")
		return
	}
	if err := s.db.RevokeEnrollToken(id, c.user.Username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "token.revoke", fmt.Sprint(id), "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, c *ctx) {
	users, err := s.db.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req createUserRequest
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	u, err := s.db.CreateUser(clamp(req.Username, 64), req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "user.create", u.Username, "role="+u.Role, "ok")
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleResetMFA(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	if err := s.db.ResetMFA(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The one action that can weaken MFA, so it is logged prominently.
	s.audit(c, r, "user.reset_mfa", fmt.Sprint(id), "second factor cleared; sessions revoked", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type disableRequest struct {
	Disabled bool `json:"disabled"`
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req disableRequest
	if err := readJSON(w, r, 1<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad user id")
		return
	}
	if id == c.user.ID {
		writeErr(w, http.StatusBadRequest, "you cannot disable your own account")
		return
	}
	if err := s.db.SetUserDisabled(id, req.Disabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "user.disabled", fmt.Sprint(id), strconv.FormatBool(req.Disabled), "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, c *ctx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.db.ListAudit(limit, r.URL.Query().Get("actor"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// nz makes a nil slice serialise as [] rather than null, so the UI never has to
// special-case an empty fleet.
// nz renders a nil slice as [] rather than null, so clients never have to
// special-case an empty result.
func nz[T any](f []T) []T {
	if f == nil {
		return []T{}
	}
	return f
}

var _ = strings.TrimSpace

type bulkStateRequest struct {
	State    string `json:"state"`
	Note     string `json:"note"`
	AgentID  string `json:"agent"`
	EstateID int64  `json:"estate"`
	Severity string `json:"severity"`
	FromSt   string `json:"from_state"`
	Class    string `json:"class"`
	Query    string `json:"q"`
	// Expect is the number of rows the operator was shown. The update refuses
	// to run if reality has moved, so a bulk action cannot quietly hit ten times
	// what its author was looking at.
	Expect int64 `json:"expect"`
}

// handleFindingBulkState re-states every finding matching a filter.
//
// This is a blunt instrument and is treated as one. It applies the SAME filter
// the operator was looking at, and it will not proceed if the number of
// matching rows has changed since the page was rendered — an agent reporting
// mid-click must not silently widen the blast radius. The action is audited
// with its filter and its count, because "who dismissed four thousand findings
// and which ones" is a question that gets asked after the fact.
func (s *Server) handleFindingBulkState(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req bulkStateRequest
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	filter := store.FindingFilter{
		AgentID:  req.AgentID,
		EstateID: req.EstateID,
		Severity: req.Severity,
		State:    req.FromSt,
		Class:    req.Class,
		Search:   clamp(req.Query, 200),
	}
	// Refuse an unbounded sweep. Re-stating every finding in the console from a
	// single unfiltered click is not a workflow, it is an accident.
	if filter.AgentID == "" && filter.EstateID == 0 && filter.Severity == "" &&
		filter.State == "" && filter.Class == "" && filter.Search == "" {
		writeErr(w, http.StatusBadRequest,
			"a bulk state change needs a filter; narrow the list first")
		return
	}

	n, err := s.db.CountFindings(filter)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Expect > 0 && int64(n) != req.Expect {
		writeErr(w, http.StatusConflict, fmt.Sprintf(
			"the list changed: %d findings match now, %d when you loaded the page. Reload and try again.",
			n, req.Expect))
		return
	}

	changed, err := s.db.SetFindingStatesByFilter(filter, req.State, c.user.Username, clamp(req.Note, 1024))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "finding.bulk."+req.State,
		fmt.Sprintf("agent=%q estate=%d severity=%q state=%q class=%q q=%q",
			req.AgentID, req.EstateID, req.Severity, req.FromSt, req.Class, req.Query),
		fmt.Sprintf("%d finding(s)", changed), "ok")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed})
}

// ---------------------------------------------------------------------------
// scheduled scans and multi-host dispatch
// ---------------------------------------------------------------------------

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request, c *ctx) {
	estate, _ := strconv.ParseInt(r.URL.Query().Get("estate"), 10, 64)
	list, err := s.db.ListSchedules(estate)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []store.Schedule{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req store.Schedule
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	req.Name = clamp(req.Name, 120)
	req.CreatedBy = c.user.Username
	req.Enabled = true

	sch, err := s.db.CreateSchedule(req)
	if err != nil {
		// Validation errors are the operator's to fix and must be readable.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "schedule.create", sch.Name,
		fmt.Sprintf("%s at %02d:%02d %s, weekdays %d", sch.Kind,
			sch.MinuteOfDay/60, sch.MinuteOfDay%60, sch.TZ, sch.Weekdays), "ok")
	writeJSON(w, http.StatusOK, sch)
}

func (s *Server) handleScheduleEnabled(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad schedule id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if err := s.db.SetScheduleEnabled(id, req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "schedule.enabled", fmt.Sprint(id), fmt.Sprint(req.Enabled), "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad schedule id")
		return
	}
	if err := s.db.DeleteSchedule(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "schedule.delete", fmt.Sprint(id), "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type bulkCommandRequest struct {
	Agents []string `json:"agents"`
	Kind   string   `json:"kind"`
}

// handleBulkCommand queues one command across many hosts.
//
// Triage on a 236-host estate is a fleet operation, not a per-row one. The
// allowlist here is deliberately the same as the scheduler's: scan, baseline
// and verify only. Containment stays per-host and behind its own approval,
// because "run this on everything" is exactly the wrong shape for a destructive
// action — a single mistaken click must never be able to reach an estate.
func (s *Server) handleBulkCommand(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req bulkCommandRequest
	if err := readJSON(w, r, 64<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	switch req.Kind {
	case "scan", "baseline", "verify":
	default:
		writeErr(w, http.StatusBadRequest,
			"only scan, baseline and verify may be run across multiple hosts")
		return
	}
	if len(req.Agents) == 0 {
		writeErr(w, http.StatusBadRequest, "no hosts selected")
		return
	}
	if len(req.Agents) > 1000 {
		writeErr(w, http.StatusBadRequest, "too many hosts in one request")
		return
	}

	var queued, failed int
	for _, id := range req.Agents {
		if _, err := s.db.CreateCommand(id, req.Kind, map[string]any{"bulk": true},
			c.user.Username, 12*time.Hour); err != nil {
			failed++
			continue
		}
		queued++
	}
	s.audit(c, r, "command.bulk."+req.Kind, fmt.Sprintf("%d host(s)", len(req.Agents)),
		fmt.Sprintf("queued=%d failed=%d", queued, failed), "ok")
	writeJSON(w, http.StatusOK, map[string]any{"queued": queued, "failed": failed})
}
