package console

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"wordeye/internal/store"
)

// Raising tickets from findings.
//
// Two decisions shape this, and both are about not drowning the person on the
// other end:
//
// The unit is an ARTEFACT, not a finding. A digest seen on six hosts is one
// incident and becomes one ticket naming six hosts. An estate that produced 438
// open findings would otherwise produce 438 tickets, which is indistinguishable
// from producing none.
//
// Delivery is idempotent forever. A monitoring fleet re-reports a shell that is
// still on disk every few minutes, so "send when we see it" means a new ticket
// every few minutes for the same file. Each (webhook, artefact) pair is
// recorded once and never sent again.
//
// Deliveries are signed. The receiver can then prove a payload came from this
// console rather than from anyone who learned the URL — which matters because
// the payload names which of a customer's sites is compromised.

const (
	webhookTick    = 60 * time.Second
	webhookTimeout = 20 * time.Second
	// webhookBatch bounds work per tick so a large backlog cannot monopolise
	// the single database connection or the ticket system.
	webhookBatch = 25
)

func (s *Server) startWebhooks(ctx context.Context) {
	go func() {
		t := time.NewTicker(webhookTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.deliverWebhooks(ctx)
			}
		}
	}()
}

func (s *Server) deliverWebhooks(ctx context.Context) {
	hooks, err := s.db.ListWebhooks()
	if err != nil {
		s.log.Printf("webhooks: %v", err)
		return
	}
	for _, w := range hooks {
		if !w.Enabled {
			continue
		}
		items, err := s.db.PendingWebhookArtefacts(w, webhookBatch)
		if err != nil {
			s.log.Printf("webhooks: %s: %v", w.Name, err)
			continue
		}
		for _, a := range items {
			claimed, err := s.db.ClaimDelivery(w.ID, a.DedupeKey)
			if err != nil || !claimed {
				continue
			}
			sendErr := s.postWebhook(ctx, w, a)
			_ = s.db.MarkDelivered(w.ID, a.DedupeKey, sendErr)
			_ = s.db.RecordWebhookResult(w.ID, sendErr)
			if sendErr != nil {
				s.log.Printf("webhooks: %s: %v", w.Name, sendErr)
				// Stop on the first failure for this hook. Hammering a ticket
				// system that is down turns one outage into two.
				break
			}
			_ = s.db.Audit("webhook", "webhook.sent", w.Name,
				fmt.Sprintf("%s on %d host(s)", a.RuleID, a.Hosts), "local", "ok")
		}
	}
}

// webhookPayload is the delivered document.
//
// Deliberately flat and generic. Every ticket system wants different fields, so
// this carries the facts and lets the receiver map them, rather than pretending
// to speak Jira.
type webhookPayload struct {
	Event       string    `json:"event"`
	DedupeKey   string    `json:"dedupe_key"`
	Rule        string    `json:"rule_id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Remediation string    `json:"remediation"`
	Path        string    `json:"path"`
	Artefact    string    `json:"artefact"`
	HostCount   int       `json:"host_count"`
	Hostnames   []string  `json:"hostnames"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ConsoleURL  string    `json:"console_url,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

func (s *Server) postWebhook(ctx context.Context, w store.Webhook, a store.Artefact) error {
	payload := webhookPayload{
		Event:       "finding",
		DedupeKey:   a.DedupeKey,
		Rule:        a.RuleID,
		Severity:    a.Severity,
		Title:       a.Title,
		Detail:      a.Detail,
		Remediation: a.Remediation,
		Path:        a.Path,
		Artefact:    a.Artefact,
		HostCount:   a.Hosts,
		Hostnames:   a.Hostnames,
		FirstSeen:   a.FirstSeen,
		LastSeen:    a.LastSeen,
		SentAt:      time.Now().UTC(),
	}
	// A deep link, so the ticket is one click from the evidence.
	if s.cfg.PublicURL != "" {
		payload.ConsoleURL = strings.TrimRight(s.cfg.PublicURL, "/") +
			"/?q=" + urlQueryEscape("rule:"+a.RuleID) + "#/findings"
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	cctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "wordeye-console")
	// Idempotency key AND signature. The first lets a receiver discard a
	// duplicate if we ever send one; the second lets it refuse a payload that
	// did not come from this console.
	req.Header.Set("X-WordEye-Delivery", a.DedupeKey)
	req.Header.Set("X-WordEye-Signature", signPayload(w.Secret, body))

	resp, err := s.webhookClient().Do(req)
	if err != nil {
		return fmt.Errorf("posting to %s: %w", redactURL(w.URL), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", redactURL(w.URL), resp.Status)
	}
	return nil
}

func (s *Server) webhookClient() *http.Client {
	return &http.Client{Timeout: webhookTimeout}
}

// signPayload produces an HMAC over the exact bytes sent, so a receiver can
// verify both origin and integrity.
func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// redactURL keeps credentials and tokens out of logs and error messages. A
// webhook URL frequently carries a token in its path or query.
func redactURL(raw string) string {
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i] + "?…"
	}
	parts := strings.SplitN(raw, "://", 2)
	if len(parts) != 2 {
		return "the configured URL"
	}
	host := parts[1]
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return parts[0] + "://" + host + "/…"
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
