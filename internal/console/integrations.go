package console

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"wordeye/internal/store"
)

// The Integrations view exists because a delivery path whose health is
// invisible is one nobody can trust.
//
// SIEM forwarding was configurable only on the command line and its counters —
// sent, dropped, errors — were displayed nowhere, so an operator had no way to
// tell a working forwarder from one that had been silently discarding events
// since a collector restart. That is the same failure the agent's flush
// telemetry was built to avoid: a pipeline that reports nothing looks identical
// to one with nothing to report.

type integrationsResponse struct {
	Syslog   *syslogStatus    `json:"syslog"`
	Webhooks []webhookSummary `json:"webhooks"`
}

type syslogStatus struct {
	Configured bool   `json:"configured"`
	Target     string `json:"target,omitempty"`
	Sent       int64  `json:"sent"`
	Dropped    int64  `json:"dropped"`
	Errors     int64  `json:"errors"`
	Note       string `json:"note,omitempty"`
}

type webhookSummary struct {
	store.Webhook
	// Health is a plain-language verdict, so the page answers "is this working"
	// without an operator having to interpret three counters.
	Health string `json:"health"`
}

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request, c *ctx) {
	out := integrationsResponse{Webhooks: []webhookSummary{}}

	st := &syslogStatus{Configured: s.cfg.Forward.Target != "", Target: redactURL(s.cfg.Forward.Target)}
	if !st.Configured {
		st.Note = "Not configured. Start the console with --syslog tls://collector:6514 to forward " +
			"every finding and audit event to a SIEM."
	} else if s.fwd != nil {
		sent, dropped, errs := s.fwd.Stats()
		st.Sent, st.Dropped, st.Errors = sent, dropped, errs
		switch {
		case dropped > 0:
			st.Note = fmt.Sprintf("%d event(s) were dropped because the queue filled faster than the "+
				"collector accepted them. Those detections are not in your SIEM.", dropped)
		case errs > 0 && sent == 0:
			st.Note = "Nothing has been delivered successfully. Check the collector address and its certificate."
		}
	}
	out.Syslog = st

	hooks, err := s.db.ListWebhooks()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, h := range hooks {
		out.Webhooks = append(out.Webhooks, webhookSummary{Webhook: h, Health: webhookHealth(h)})
	}
	writeJSON(w, http.StatusOK, out)
}

// webhookHealth turns counters into a sentence.
func webhookHealth(h store.Webhook) string {
	switch {
	case !h.Enabled:
		return "paused"
	case h.FailCount > 0 && h.LastOK.IsZero():
		return fmt.Sprintf("never delivered — %d consecutive failure(s)", h.FailCount)
	case h.FailCount > 0:
		return fmt.Sprintf("failing — %d since the last success %s ago",
			h.FailCount, time.Since(h.LastOK).Round(time.Minute))
	case h.LastOK.IsZero():
		return "no deliveries yet"
	default:
		return "last delivered " + time.Since(h.LastOK).Round(time.Minute).String() + " ago"
	}
}

type createWebhookRequest struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	EstateID    int64  `json:"estate_id"`
	MinSeverity string `json:"min_severity"`
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req createWebhookRequest
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	hook, err := s.db.CreateWebhook(store.Webhook{
		Name:        clamp(req.Name, 120),
		URL:         clamp(req.URL, 2000),
		EstateID:    req.EstateID,
		MinSeverity: req.MinSeverity,
		CreatedBy:   c.user.Username,
	})
	if err != nil {
		// URL validation failures are the operator's to fix and must be readable.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "webhook.create", hook.Name,
		fmt.Sprintf("min_severity=%s estate=%d", hook.MinSeverity, hook.EstateID), "ok")

	// The signing secret is returned exactly once, here, so it can be configured
	// on the receiving end. It is never served again.
	writeJSON(w, http.StatusOK, map[string]any{
		"webhook": hook,
		"secret":  hook.Secret,
		"note": "Store this signing secret now — it is shown once. Verify X-WordEye-Signature " +
			"as HMAC-SHA256 over the raw request body to prove a delivery came from this console.",
	})
}

func (s *Server) handleWebhookEnabled(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad webhook id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if err := s.db.SetWebhookEnabled(id, req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "webhook.enabled", fmt.Sprint(id), fmt.Sprint(req.Enabled), "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad webhook id")
		return
	}
	if err := s.db.DeleteWebhook(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "webhook.delete", fmt.Sprint(id), "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTestWebhook sends one synthetic delivery.
//
// Configuring a ticket integration and discovering three days later that
// nothing arrived is the common failure, and it is entirely avoidable: this
// proves the URL, the TLS, the auth and the signature end to end before an
// operator relies on it. The payload is clearly marked as a test so nobody
// works a ticket for a shell that does not exist.
func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad webhook id")
		return
	}
	hooks, err := s.db.ListWebhooks()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var hook *store.Webhook
	for i := range hooks {
		if hooks[i].ID == id {
			hook = &hooks[i]
			break
		}
	}
	if hook == nil {
		writeErr(w, http.StatusNotFound, "no such webhook")
		return
	}

	sample := store.Artefact{
		DedupeKey: fmt.Sprintf("wordeye.test|%d", time.Now().UnixNano()),
		RuleID:    "wordeye.test",
		Artefact:  "test",
		Severity:  "info",
		Title:     "WordEye test delivery — no action required",
		Detail: "This is a test sent from the Integrations page to prove the webhook is reachable " +
			"and its signature verifies. It does not describe a real finding.",
		Remediation: "None. Close this ticket.",
		Path:        "(test)",
		Hosts:       0,
		Hostnames:   []string{},
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
	}
	sendErr := s.postWebhook(r.Context(), *hook, sample)
	_ = s.db.RecordWebhookResult(hook.ID, sendErr)
	s.audit(c, r, "webhook.test", hook.Name, errText(sendErr), okOrFailed(sendErr))

	if sendErr != nil {
		writeErr(w, http.StatusBadGateway, sendErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func errText(err error) string {
	if err == nil {
		return "delivered"
	}
	return err.Error()
}

func okOrFailed(err error) string {
	if err == nil {
		return "ok"
	}
	return "failed"
}
