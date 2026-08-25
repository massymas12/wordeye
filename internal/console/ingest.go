package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wordeye/internal/store"
)

// The agent-facing API.
//
// This listener faces the internet and talks to software running on hosts that
// may themselves be compromised. Every handler therefore assumes the body is
// hostile: bounded size, strict schema, unknown fields rejected, and no
// operator functionality reachable from here at all.

// Body limits per endpoint. A full report from a large estate can be sizeable;
// everything else is small and is capped tightly.
const (
	maxEnrollBody    = 8 << 10
	maxHeartbeatBody = 8 << 10
	maxEventsBody    = 4 << 20
	// Lowered from 32MB. The body is held in memory to parse, and was then
	// retained AGAIN as the raw column — roughly 2x per concurrent request, with
	// no per-agent cap. One valid credential could drive the console to OOM.
	maxReportBody = 12 << 20
	// Above this, the verbatim report is summarised rather than stored, so
	// database growth stays bounded regardless of estate size.
	maxRawRetained = 1 << 20
	maxResultBody  = 1 << 20
	// maxFindingsPerReport bounds the DATABASE WORK one report can demand,
	// which the body limit does not: ~44 bytes of JSON per minimal finding
	// means 12MB carries ~286,000 upserts against a single-writer database.
	// A real scan of a 68,000-file site produced 25 findings.
	maxFindingsPerReport = 5000
	// maxFindingMeta bounds one finding's free-form metadata. It is stored as
	// JSON in the row and is otherwise unclamped, unlike every other field.
	maxFindingMeta = 16 << 10
)

func (s *Server) ingestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/heartbeat", s.agentAuth(s.handleHeartbeat))
	mux.HandleFunc("POST /v1/events", s.agentAuth(s.handleEvents))
	mux.HandleFunc("POST /v1/report", s.agentAuth(s.handleReport))
	mux.HandleFunc("POST /v1/command/result", s.agentAuth(s.handleCommandResult))
	mux.HandleFunc("GET /v1/vendor-pack", s.agentAuth(s.handleVendorPack))
	mux.HandleFunc("GET /v1/agent-release", s.agentAuth(s.handleAgentRelease))
	mux.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"service": "wordeye-ingest"})
	})
	return s.ingestSecurity(mux)
}

// ingestSecurity applies transport-level hardening common to every agent route.
func (s *Server) ingestSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Nothing here is a browser surface; deny framing and referrers outright.
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		if !s.ingestLimiter.allow(s.clientIP(r)) {
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// agentCtxKey carries the authenticated agent through the handler chain.
type agentCtxKey struct{}

// agentAuth authenticates "Authorization: Bearer <agent_id>.<credential>".
func (s *Server) agentAuth(next func(http.ResponseWriter, *http.Request, *store.Agent)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing bearer credential")
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		id, cred, ok := strings.Cut(raw, ".")
		if !ok || id == "" || cred == "" {
			writeErr(w, http.StatusUnauthorized, "malformed credential")
			return
		}
		agent, err := s.db.AuthAgent(id, cred, s.clientIP(r))
		if err != nil {
			// Deliberately vague: a probing client learns nothing about which
			// agent ids exist.
			writeErr(w, http.StatusUnauthorized, "authentication failed")
			return
		}
		next(w, r, agent)
	}
}

// ---------------------------------------------------------------------------
// enrollment
// ---------------------------------------------------------------------------

type enrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	Label        string `json:"label"`
	Site         string `json:"site"`
	Webroot      string `json:"webroot"`
	Version      string `json:"version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	OptInContain bool   `json:"opt_in_contain"`
}

type enrollResponse struct {
	AgentID            string `json:"agent_id"`
	Credential         string `json:"credential"`
	AllowRemoteContain bool   `json:"allow_remote_contain"`
	HeartbeatSeconds   int    `json:"heartbeat_seconds"`
}

// handleEnroll is the only unauthenticated write endpoint, and it is gated
// entirely by a console-minted token. There is no self-registration: an agent
// cannot join the fleet unless an operator explicitly issued a token for it.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := readJSON(w, r, maxEnrollBody, &req); err != nil {
		// Deliberately generic. This endpoint is unauthenticated and internet
		// facing, and the decoder's error names internal struct fields and
		// types — free reconnaissance for anyone probing the port.
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Token == "" {
		writeErr(w, http.StatusBadRequest, "enrollment token is required")
		return
	}
	ip := s.clientIP(r)

	tok, err := s.db.ConsumeEnrollToken(req.Token)
	if err != nil {
		_ = s.db.Audit("agent:"+req.Hostname, "enroll.rejected", req.Hostname, err.Error(), ip, "denied")
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}

	// Clamp attacker-influenced strings: these come from a host we do not trust
	// and end up rendered in the console.
	req.Hostname = clamp(req.Hostname, 128)
	req.Label = clamp(req.Label, 128)
	req.Site = clamp(req.Site, 128)
	req.Webroot = clamp(req.Webroot, 512)
	req.Version = clamp(req.Version, 64)
	req.OS = clamp(req.OS, 32)
	req.Arch = clamp(req.Arch, 32)
	if req.Label == "" {
		req.Label = tok.Label
	}

	id, cred, err := s.db.EnrollAgent(store.EnrollRequest{
		Hostname: req.Hostname, Label: req.Label, Site: req.Site, Webroot: req.Webroot,
		Version: req.Version, OS: req.OS, Arch: req.Arch, OptInContain: req.OptInContain,
	}, tok, ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	_ = s.db.Audit("agent:"+id, "enroll.accepted", id,
		fmt.Sprintf("host=%s label=%q token=%s contain(token=%v agent=%v)",
			req.Hostname, req.Label, tok.Prefix, tok.AllowRemoteContain, req.OptInContain), ip, "ok")

	writeJSON(w, http.StatusOK, enrollResponse{
		AgentID:    id,
		Credential: cred,
		// Report the EFFECTIVE grant: containment needs both sides to agree, so
		// the agent learns immediately whether it will ever honour such an order.
		AllowRemoteContain: tok.AllowRemoteContain && req.OptInContain,
		HeartbeatSeconds:   60,
	})
}

// ---------------------------------------------------------------------------
// heartbeat + command poll
// ---------------------------------------------------------------------------

type heartbeatRequest struct {
	Load1        float64 `json:"load1"`
	Monitor      bool    `json:"monitor"`
	OpenFindings int     `json:"open_findings"`
	Version      string  `json:"version"`
}

type heartbeatResponse struct {
	OK               bool             `json:"ok"`
	ServerTime       int64            `json:"server_time"`
	HeartbeatSeconds int              `json:"heartbeat_seconds"`
	Command          *commandDispatch `json:"command,omitempty"`
}

type commandDispatch struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Params json.RawMessage `json:"params"`
}

// handleHeartbeat records liveness and, in the same round trip, hands back at
// most one queued command.
//
// Polling on heartbeat is why no client production server needs an inbound
// port or a firewall exception: the connection is always agent-initiated.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var req heartbeatRequest
	if err := readJSON(w, r, maxHeartbeatBody, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	_ = s.db.RecordHeartbeat(agent.ID, store.Heartbeat{
		Load1: req.Load1, Monitor: req.Monitor,
		OpenFindings: req.OpenFindings, Version: clamp(req.Version, 64),
	})

	resp := heartbeatResponse{OK: true, ServerTime: time.Now().Unix(), HeartbeatSeconds: 60}

	cmd, err := s.db.NextCommandForAgent(agent.ID)
	if err == nil && cmd != nil {
		// Second half of the two-key rule. Even if the console dispatched a
		// containment order, it is withheld unless this agent's own enrollment
		// opted in. A compromised console cannot destroy hosts that never
		// agreed to accept remote destruction.
		if cmd.Kind == "contain" && !agent.ContainAllowed() {
			_ = s.db.CompleteCommand(cmd.ID, "failed", "",
				"agent refused: this host did not enroll with remote containment enabled")
			_ = s.db.Audit("agent:"+agent.ID, "command.refused", cmd.ID,
				"remote containment not permitted for this agent", s.clientIP(r), "denied")
		} else {
			resp.Command = &commandDispatch{ID: cmd.ID, Kind: cmd.Kind, Params: cmd.Params}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// detections
// ---------------------------------------------------------------------------

type eventsRequest struct {
	Findings []store.FindingInput `json:"findings"`
}

// handleEvents ingests findings streamed by a monitor-mode agent.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	// Lenient decode, for the same reason handleReport uses one — and with more
	// at stake.
	//
	// readJSON rejects unknown fields. A streamed detection is a model.Finding,
	// which carries mtime, ctime, mode and other forensic context that
	// store.FindingInput does not model, so EVERY real-time detection was
	// rejected with 400 and silently dropped. An agent enrolled, heartbeated for
	// half an hour, detected six shells, handed them to the console, and the
	// console threw them away over field names.
	//
	// Strict decoding is right for operator input, where a typo should be
	// refused. It is wrong for agent telemetry, where the sender may be newer
	// than the receiver and the payload is evidence of a compromise. Unknown
	// fields are ignored; the fields that matter are still validated and
	// clamped by sanitizeFinding below.
	r.Body = http.MaxBytesReader(w, r.Body, maxEventsBody)
	raw, err := readAllLimited(r, maxEventsBody)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "event batch too large or unreadable")
		return
	}
	var req eventsRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	// Cap the batch: a compromised agent must not be able to flood the store in
	// a single request.
	const maxBatch = 2000
	if len(req.Findings) > maxBatch {
		req.Findings = req.Findings[:maxBatch]
	}
	accepted, failed := 0, 0
	for _, f := range req.Findings {
		sanitizeFinding(&f)
		if f.RuleID == "" {
			continue
		}
		if err := s.db.UpsertFinding(agent.ID, f); err != nil {
			failed++
			s.log.Printf("events from %s: storing %s on %s: %v", agent.ID, f.RuleID, f.Path, err)
			continue
		}
		accepted++
		s.fwd.ForwardFinding(agent, f)
	}
	// The agent is told how many it could NOT store, so "delivered" stops
	// meaning "the server returned 200".
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "accepted": accepted, "failed": failed})
}

// reportEnvelope is the subset of the agent report the console indexes. The
// full document is retained verbatim for drill-down.
type reportEnvelope struct {
	Schema     string    `json:"schema"`
	Mode       string    `json:"mode"`
	Verdict    string    `json:"verdict"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Stats      struct {
		FilesSeen int64 `json:"files_seen"`
		FilesRead int64 `json:"files_read"`
	} `json:"stats"`
	Errors   []string             `json:"errors"`
	Findings []store.FindingInput `json:"findings"`
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	// Throttle per agent, not just per IP: a whole estate can share one egress
	// address, so an IP-only limit would let one noisy agent starve the rest.
	if !s.reportLimiter.allow(agent.ID) {
		writeErr(w, http.StatusTooManyRequests, "report rate limit exceeded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxReportBody)
	raw, err := readAllLimited(r, maxReportBody)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "report too large or unreadable")
		return
	}
	// Lenient decode here (unlike other endpoints): the report schema evolves
	// with the agent, and an older console must still index a newer report
	// rather than discarding a compromise finding over an unknown field.
	var env reportEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed report")
		return
	}

	sum := store.ReportSummary{
		AgentID:    agent.ID,
		Mode:       clamp(env.Mode, 32),
		Verdict:    clamp(env.Verdict, 32),
		DurationMS: env.DurationMS,
		FilesSeen:  env.Stats.FilesSeen,
		FilesRead:  env.Stats.FilesRead,
		NErrors:    len(env.Errors),
	}
	// Retain the verbatim document only when it is small. Findings are indexed
	// separately either way, so nothing detection-relevant is lost.
	if len(raw) <= maxRawRetained {
		sum.Raw = string(raw)
	} else {
		sum.Raw = fmt.Sprintf(
			`{"note":"verbatim report omitted (%d bytes); findings were indexed"}`, len(raw))
	}
	if !env.StartedAt.IsZero() {
		sum.StartedAt = env.StartedAt.Unix()
	}
	for _, f := range env.Findings {
		switch f.Severity {
		case "critical":
			sum.NCritical++
		case "high":
			sum.NHigh++
		case "medium":
			sum.NMedium++
		case "low":
			sum.NLow++
		default:
			sum.NInfo++
		}
	}
	if _, err := s.db.InsertReport(sum); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store report")
		return
	}
	s.fwd.ForwardScan(agent, sum)

	// Bound the number of rows one report can create.
	//
	// The body limit alone is not a bound on WORK: a minimal finding is ~44
	// bytes of JSON, so a 12MB report can carry roughly 286,000 of them, and
	// each is an upsert against a database deliberately held to a SINGLE
	// writer. That would stall every other agent's check-in and the operator UI
	// behind one request.
	//
	// The agents sending these are customer WordPress hosts — precisely the
	// machines this product exists because they get compromised — so "the agent
	// is authenticated" is not a reason to trust its volume. A real scan of a
	// 68,000-file site produced 25 findings; anything approaching this cap is
	// either a broken agent or a hostile one, and both are better truncated
	// loudly than served.
	accepted, dropped, failed := 0, 0, 0
	for _, f := range env.Findings {
		if accepted >= maxFindingsPerReport {
			dropped = len(env.Findings) - accepted
			break
		}
		sanitizeFinding(&f)
		if f.RuleID == "" {
			continue
		}
		if err := s.db.UpsertFinding(agent.ID, f); err != nil {
			// Storing a detection is the one thing this endpoint exists to do.
			// Swallowing the error and counting it as accepted told the agent
			// its webshell had landed while the row was never written and the
			// SIEM never saw it — the scanner-reports-less-than-it-found
			// failure this file is most concerned with.
			failed++
			s.log.Printf("report from %s: storing %s on %s: %v", agent.ID, f.RuleID, f.Path, err)
			continue
		}
		s.fwd.ForwardFinding(agent, f)
		accepted++
	}
	if dropped > 0 {
		// Never silent. A truncated report that looked complete would be a
		// scanner reporting less than it found, which is the failure this
		// codebase is most concerned with.
		s.log.Printf("agent %s: report carried %d findings; stored %d and dropped %d over the per-report cap",
			agent.ID, len(env.Findings), accepted, dropped)
		_ = s.db.Audit("agent:"+agent.ID, "report.truncated", agent.ID,
			fmt.Sprintf("%d findings offered, %d stored", len(env.Findings), accepted), "", "warn")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "findings": accepted, "dropped": dropped, "failed": failed})
}

// ---------------------------------------------------------------------------
// command results
// ---------------------------------------------------------------------------

type commandResultRequest struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Result string `json:"result"`
	Error  string `json:"error"`
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var req commandResultRequest
	if err := readJSON(w, r, maxResultBody, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	cmd, err := s.db.GetCommand(req.ID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown command")
		return
	}
	// An agent may only report on its own work.
	if !constantTimeEqual(cmd.AgentID, agent.ID) {
		writeErr(w, http.StatusForbidden, "command does not belong to this agent")
		return
	}
	if err := s.db.CompleteCommand(req.ID, req.Status, clamp(req.Result, 256<<10), clamp(req.Error, 4096)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// A completed uninstall retires the agent.
	//
	// Without this the host stays in the fleet as a machine that stopped
	// reporting, which is precisely the shape the tamper watchdog treats as an
	// intrusion. An authorised removal has to be recorded as one, or every
	// routine decommission generates a security finding and the watchdog stops
	// being worth reading.
	if cmd.Kind == "uninstall" && req.Status == "done" {
		if err := s.db.RetireAgent(agent.ID); err != nil {
			s.log.Printf("retiring %s after uninstall: %v", agent.ID, err)
		}
		_ = s.db.Audit("agent:"+agent.ID, "agent.uninstalled", agent.ID,
			"agent confirmed uninstall and was retired", s.clientIP(r), "ok")
	}

	_ = s.db.Audit("agent:"+agent.ID, "command."+req.Status, req.ID, clamp(req.Error, 512), s.clientIP(r), req.Status)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------

// sanitizeFinding bounds every attacker-influenceable string. Findings contain
// content lifted from malware — file paths, code snippets — and are rendered in
// the operator's browser, so length is capped here and escaping happens at
// render time.
func sanitizeFinding(f *store.FindingInput) {
	f.RuleID = clamp(f.RuleID, 128)
	f.Class = clamp(f.Class, 32)
	f.Severity = clampSeverity(f.Severity)
	f.Confidence = clampConfidence(f.Confidence)
	f.Title = clamp(f.Title, 512)
	f.Detail = clamp(f.Detail, 8192)
	f.Path = clamp(f.Path, 1024)
	f.SHA256 = clamp(f.SHA256, 64)
	f.Evidence = clamp(f.Evidence, 4096)
	f.Remediation = clamp(f.Remediation, 2048)

	// Meta is free-form and reaches the database as marshalled JSON. Every
	// other field is clamped; leaving this one open meant a single finding
	// could carry megabytes into a row. Replace an oversized map rather than
	// truncating its JSON, which would store an unparseable fragment.
	if f.Meta != nil {
		if b, err := json.Marshal(f.Meta); err != nil || len(b) > maxFindingMeta {
			size := 0
			if err == nil {
				size = len(b)
			}
			f.Meta = map[string]any{
				"wordeye_note": fmt.Sprintf(
					"metadata omitted: %d bytes exceeds the %d-byte limit", size, maxFindingMeta),
			}
		}
	}
}

func clampSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	}
	return "info"
}

func clamp(s string, n int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	// Strip control characters: they corrupt logs and terminal output.
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// handleVendorPack serves the estate's attestations to an agent.
//
// This closes the loop that cross-site correlation exists for. The console can
// see what every site runs; a single agent cannot. Premium and bespoke code has
// no published manifest, so without this the agent has no authority to compare
// it against and reports the same benign Divi and Gravity Forms files on every
// host, forever.
//
// The pack is scoped to the agent's own estate. Corroboration from a different
// customer is not evidence about this one, and letting it cross that line would
// mean compromising one estate could exonerate an implant in another.
//
// Attestation is weaker than a publisher manifest and stays distinct from it
// everywhere: the agent counts these separately and the report says "the estate
// agrees" rather than "the publisher shipped this".
func (s *Server) handleVendorPack(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	entries, err := s.db.VendorAttestations(a.EstateID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.Attestation{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         "estate-consensus",
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"source":       "console cross-site correlation",
		"min_sites":    2,
		"entries":      entries,
	})
}

// clampConfidence maps an agent-supplied confidence onto the known set.
//
// Severity was validated against an enum while confidence was merely trimmed to
// 32 characters, which is a meaningful gap: confidence is load-bearing.
// "confirmed" is the level that gates automated action, so a compromised agent
// could post fabricated findings at the confidence that authorises deleting a
// customer's file — or an arbitrary string that matches no branch and falls
// silently through every comparison in the console and the UI.
//
// Anything unrecognised becomes "review", the level that asks a human to look.
func clampConfidence(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "confirmed":
		return "confirmed"
	case "likely":
		return "likely"
	case "review":
		return "review"
	default:
		return "review"
	}
}

// handleAgentRelease serves the signed release binary for an agent's platform.
//
// The console distributes code but does not vouch for it. It has no signing
// key — deliberately, because it is the internet-facing component — so all it
// can do is hand over bytes and the detached signature that came with them from
// the build machine. The agent verifies that signature against a public key
// stamped in at install time before it will execute anything.
//
// That division is what keeps a console compromise from becoming a fleet
// compromise: an attacker who owns this server can serve any binary they like
// and every agent will refuse it.
//
// A release with no .sig file is not served at all. Falling back to unsigned
// distribution "just this once" would defeat the entire mechanism, and the
// failure an operator sees — an upgrade that will not start — is far better
// than one they do not.
func (s *Server) handleAgentRelease(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	if s.cfg.AgentBinaryDir == "" {
		writeErr(w, http.StatusNotImplemented, "this console does not distribute agent binaries")
		return
	}
	goos, arch := a.OS, a.Arch
	if v := r.URL.Query().Get("os"); v != "" {
		goos = v
	}
	if v := r.URL.Query().Get("arch"); v != "" {
		arch = v
	}
	if !validPlatform(goos + "-" + arch) {
		writeErr(w, http.StatusBadRequest, "unsupported platform")
		return
	}

	name := "wordeye-agent-" + goos + "-" + arch
	if goos == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(s.cfg.AgentBinaryDir, name)
	raw, err := os.ReadFile(bin)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no release for this platform")
		return
	}
	sigRaw, err := os.ReadFile(bin + ".sig")
	if err != nil {
		// Refuse rather than degrade. An unsigned release is one an agent must
		// not run, so serving it would only produce a confusing failure later.
		s.log.Printf("agent-release: %s has no signature; refusing to serve", name)
		writeErr(w, http.StatusConflict,
			"this release is not signed; sign it on the build machine with `wordeye sign-release`")
		return
	}

	sum := sha256.Sum256(raw)
	w.Header().Set("X-WordEye-Signature", strings.TrimSpace(string(sigRaw)))
	w.Header().Set("X-WordEye-SHA256", hex.EncodeToString(sum[:]))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	_, _ = w.Write(raw)
}
