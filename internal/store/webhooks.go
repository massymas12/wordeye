package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Outbound webhooks, for raising tickets.
//
// Deduplicated by ARTEFACT, not by finding. A digest seen on six hosts is one
// incident and should be one ticket naming six hosts; six tickets is how an
// estate of 438 findings buries the four that matter. Re-delivery is suppressed
// permanently for an artefact already sent, because a monitoring fleet
// re-reports a shell that is still on disk every few minutes.

// Webhook is a configured delivery target.
type Webhook struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	EstateID    int64     `json:"estate_id,omitempty"`
	MinSeverity string    `json:"min_severity"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	LastOK      time.Time `json:"last_ok"`
	LastError   string    `json:"last_error"`
	FailCount   int       `json:"fail_count"`
	// Secret is never serialised. It signs deliveries; exposing it through the
	// API would let anyone who can read the config forge them.
	Secret string `json:"-"`
}

// severityRank orders severities for the minimum-severity filter.
var severityRank = map[string]int{
	"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}

// MeetsThreshold reports whether a severity is at or above the webhook floor.
func (w *Webhook) MeetsThreshold(sev string) bool {
	got, ok1 := severityRank[strings.ToLower(sev)]
	floor, ok2 := severityRank[strings.ToLower(w.MinSeverity)]
	if !ok1 || !ok2 {
		// An unrecognised severity must not silently pass a filter. Ticketing
		// every unknown value is noisy; suppressing it hides findings. Refuse,
		// and let the severity validation upstream be the thing that fixes it.
		return false
	}
	return got >= floor
}

// validateWebhookURL refuses targets that would leak the payload or point the
// console at itself.
//
// A delivery says which of a customer's sites is compromised and what was found
// on it, so plaintext is not an option. The loopback exception exists because a
// self-hosted ticket system on the same host is a legitimate deployment, and
// refusing it would push operators towards disabling verification instead.
func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			return fmt.Errorf("refusing plaintext http to %s: a delivery names which client is "+
				"compromised and what was found, so it must not cross a network unencrypted", host)
		}
	default:
		return fmt.Errorf("unsupported scheme %q; use https", u.Scheme)
	}
	if host == "" {
		return fmt.Errorf("no host in URL")
	}
	return nil
}

func (db *DB) CreateWebhook(w Webhook) (*Webhook, error) {
	if err := validateWebhookURL(w.URL); err != nil {
		return nil, err
	}
	if _, ok := severityRank[strings.ToLower(w.MinSeverity)]; !ok {
		w.MinSeverity = "high"
	}
	if w.Secret == "" {
		s, err := NewSecret(32)
		if err != nil {
			return nil, err
		}
		w.Secret = s
	}
	now := time.Now()
	res, err := db.sql.Exec(
		`INSERT INTO webhooks (name, url, secret, estate_id, min_severity, enabled, created_at, created_by)
		 VALUES (?,?,?,?,?,?,?,?)`,
		w.Name, strings.TrimSpace(w.URL), w.Secret, nullIfZero(w.EstateID),
		strings.ToLower(w.MinSeverity), boolInt(true), now.Unix(), w.CreatedBy)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	w.ID, w.CreatedAt, w.Enabled = id, now, true
	return &w, nil
}

func (db *DB) ListWebhooks() ([]Webhook, error) {
	rows, err := db.sql.Query(
		`SELECT id, name, url, secret, COALESCE(estate_id,0), min_severity, enabled,
		        created_at, created_by, last_ok, last_error, fail_count
		   FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Webhook
	for rows.Next() {
		var w Webhook
		var enabled int
		var created, lastOK int64
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Secret, &w.EstateID, &w.MinSeverity,
			&enabled, &created, &w.CreatedBy, &lastOK, &w.LastError, &w.FailCount); err != nil {
			return nil, err
		}
		w.Enabled = enabled != 0
		w.CreatedAt = time.Unix(created, 0).UTC()
		if lastOK > 0 {
			w.LastOK = time.Unix(lastOK, 0).UTC()
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (db *DB) SetWebhookEnabled(id int64, enabled bool) error {
	_, err := db.sql.Exec(`UPDATE webhooks SET enabled = ? WHERE id = ?`, boolInt(enabled), id)
	return err
}

func (db *DB) DeleteWebhook(id int64) error {
	_, err := db.sql.Exec(`DELETE FROM webhooks WHERE id = ?`, id)
	return err
}

// RecordWebhookResult updates health after a delivery attempt.
//
// Both outcomes are recorded. A webhook that has been failing for a week must
// look different from one that has never fired, or an operator concludes their
// ticketing works when nothing has arrived since Tuesday.
func (db *DB) RecordWebhookResult(id int64, err error) error {
	if err == nil {
		_, e := db.sql.Exec(
			`UPDATE webhooks SET last_ok = ?, last_error = '', fail_count = 0 WHERE id = ?`,
			time.Now().Unix(), id)
		return e
	}
	_, e := db.sql.Exec(
		`UPDATE webhooks SET last_error = ?, fail_count = fail_count + 1 WHERE id = ?`,
		clampStr(err.Error(), 500), id)
	return e
}

// ClaimDelivery reserves an artefact for delivery, returning false if this
// webhook has already sent it.
//
// The row is written BEFORE the HTTP call. A console that dies mid-delivery
// therefore risks one duplicate ticket rather than an unbounded loop of them,
// which is the right way round: a duplicate is an annoyance, a loop is an
// outage of the operator's attention.
func (db *DB) ClaimDelivery(webhookID int64, dedupeKey string) (bool, error) {
	var delivered int
	err := db.sql.QueryRow(
		`SELECT delivered FROM webhook_deliveries WHERE webhook_id = ? AND dedupe_key = ?`,
		webhookID, dedupeKey).Scan(&delivered)
	switch {
	case err == sql.ErrNoRows:
		now := time.Now().Unix()
		_, e := db.sql.Exec(
			`INSERT INTO webhook_deliveries (webhook_id, dedupe_key, first_sent, last_sent, attempts)
			 VALUES (?,?,?,?,1)`, webhookID, dedupeKey, now, now)
		return e == nil, e
	case err != nil:
		return false, err
	case delivered != 0:
		return false, nil // already ticketed
	default:
		// A previous attempt failed. Retry, counting the attempt.
		_, e := db.sql.Exec(
			`UPDATE webhook_deliveries SET last_sent = ?, attempts = attempts + 1
			  WHERE webhook_id = ? AND dedupe_key = ?`,
			time.Now().Unix(), webhookID, dedupeKey)
		return e == nil, e
	}
}

// MarkDelivered records a successful send so the artefact is never ticketed
// again by this webhook.
func (db *DB) MarkDelivered(webhookID int64, dedupeKey string, sendErr error) error {
	if sendErr != nil {
		_, e := db.sql.Exec(
			`UPDATE webhook_deliveries SET last_error = ? WHERE webhook_id = ? AND dedupe_key = ?`,
			clampStr(sendErr.Error(), 500), webhookID, dedupeKey)
		return e
	}
	_, e := db.sql.Exec(
		`UPDATE webhook_deliveries SET delivered = 1, last_error = '' WHERE webhook_id = ? AND dedupe_key = ?`,
		webhookID, dedupeKey)
	return e
}

// PendingWebhookArtefacts returns artefacts a webhook has not yet ticketed.
//
// Grouped by (rule, digest) across the estate, so the unit of a ticket is the
// thing an analyst investigates rather than each host that happens to carry it.
// Dismissed findings are excluded: an operator who judged something benign
// should not be handed a ticket about it.
func (db *DB) PendingWebhookArtefacts(w Webhook, limit int) ([]Artefact, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	floor := severityRank[strings.ToLower(w.MinSeverity)]

	q := `SELECT f.rule_id,
	             COALESCE(NULLIF(f.sha256,''), f.path) AS artefact,
	             MIN(f.severity), MIN(f.title), MIN(f.detail), MIN(f.remediation),
	             MIN(f.path), COUNT(DISTINCT f.agent_id),
	             GROUP_CONCAT(DISTINCT COALESCE(NULLIF(a.hostname,''), a.id)),
	             MIN(f.first_seen), MAX(f.last_seen)
	        FROM findings f
	        JOIN agents a ON a.id = f.agent_id AND a.retired = 0
	       WHERE f.state = 'open'`
	args := []any{}
	if w.EstateID != 0 {
		q += ` AND a.estate_id = ?`
		args = append(args, w.EstateID)
	}
	q += ` GROUP BY f.rule_id, artefact ORDER BY MAX(f.last_seen) DESC LIMIT ?`
	args = append(args, limit*4) // over-fetch; severity and dedupe filter below

	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Artefact
	for rows.Next() {
		var a Artefact
		var hosts sql.NullString
		var first, last int64
		if err := rows.Scan(&a.RuleID, &a.Artefact, &a.Severity, &a.Title, &a.Detail,
			&a.Remediation, &a.Path, &a.Hosts, &hosts, &first, &last); err != nil {
			return nil, err
		}
		if severityRank[strings.ToLower(a.Severity)] < floor {
			continue
		}
		if hosts.Valid {
			a.Hostnames = strings.Split(hosts.String, ",")
		}
		a.FirstSeen = time.Unix(first, 0).UTC()
		a.LastSeen = time.Unix(last, 0).UTC()
		a.DedupeKey = a.RuleID + "|" + a.Artefact
		out = append(out, a)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// Artefact is one thing worth a ticket: a rule and a digest, plus every host it
// was found on.
type Artefact struct {
	DedupeKey   string    `json:"dedupe_key"`
	RuleID      string    `json:"rule_id"`
	Artefact    string    `json:"artefact"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Remediation string    `json:"remediation"`
	Path        string    `json:"path"`
	Hosts       int       `json:"host_count"`
	Hostnames   []string  `json:"hostnames"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

func clampStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
