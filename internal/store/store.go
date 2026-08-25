package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Agent status thresholds. An agent heartbeats every 60s by default, so a
// couple of missed beats is "stale" rather than "gone" — a WordPress host under
// load can easily drop one.
const (
	OnlineWindow = 3 * time.Minute
	StaleWindow  = 20 * time.Minute
)

type DB struct {
	sql *sql.DB

	// OnAudit, when set, is invoked for every audit entry. The SIEM forwarder
	// uses this so that adding a new audited action never means remembering to
	// forward it too.
	OnAudit func(AuditEntry)
}

func Open(path string) (*DB, error) {
	// _txlock=immediate avoids SQLITE_BUSY upgrade deadlocks when the ingest
	// listener and the console write concurrently.
	//
	// WAL matters once an estate is more than a handful of hosts. Under the
	// default rollback journal every write takes an exclusive lock on the whole
	// database and fsyncs twice, so a single agent posting a few thousand
	// findings stalls every heartbeat queued behind it. WAL lets readers
	// proceed against the last committed snapshot while that write is in
	// flight, which is the difference between a console that degrades and one
	// that times out as hosts are added.
	//
	// synchronous=NORMAL is the documented companion to WAL: durable across a
	// process crash, and on power loss it can cost the most recent commits.
	// That trade is right here — the agents re-report on their next sweep, so
	// the loss is transient, and the alternative is an fsync per finding.
	d, err := sql.Open("sqlite",
		path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	// SQLite takes a single writer; more connections buy contention, not speed.
	d.SetMaxOpenConns(1)
	if _, err := d.Exec(schema); err != nil {
		d.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	if err := addColumns(d); err != nil {
		d.Close()
		return nil, err
	}
	return &DB{sql: d}, nil
}

// addColumns brings an existing database up to date.
//
// CREATE TABLE IF NOT EXISTS does nothing for a table that already exists, so
// new columns need ALTER TABLE. SQLite has no "ADD COLUMN IF NOT EXISTS", and
// re-adding an existing column is an error rather than a no-op — so each is
// attempted and a duplicate-column error is the expected outcome on any console
// that has already been upgraded. Anything else is a real failure.
func addColumns(d *sql.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE agents ADD COLUMN estate_id INTEGER REFERENCES estates(id) ON DELETE SET NULL`,
		`ALTER TABLE enroll_tokens ADD COLUMN estate_id INTEGER REFERENCES estates(id) ON DELETE SET NULL`,
		`ALTER TABLE commands ADD COLUMN not_before INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := d.Exec(stmt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
				continue
			}
			return fmt.Errorf("migrating: %s: %w", stmt, err)
		}
	}
	_, _ = d.Exec(`CREATE INDEX IF NOT EXISTS agents_estate ON agents(estate_id)`)
	return nil
}

func (db *DB) Close() error { return db.sql.Close() }
func (db *DB) SQL() *sql.DB { return db.sql }

func now() int64 { return time.Now().Unix() }

// HashToken is used for every bearer secret the console stores: enrollment
// tokens, agent credentials, recovery codes. Stored hashed so a database
// disclosure does not hand over working credentials.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// NewSecret returns a URL-safe random secret.
func NewSecret(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
	Result string    `json:"result"`
}

// Audit appends to the audit log. Deliberately best-effort at the call site
// (errors are returned but callers generally proceed): failing an operator
// action because the log write failed would be a worse outcome than a gap,
// provided the gap itself is visible.
func (db *DB) Audit(actor, action, target, detail, ip, result string) error {
	if result == "" {
		result = "ok"
	}
	_, err := db.sql.Exec(
		`INSERT INTO audit (at, actor, action, target, detail, ip, result) VALUES (?,?,?,?,?,?,?)`,
		now(), actor, action, target, detail, ip, result)
	if db.OnAudit != nil {
		db.OnAudit(AuditEntry{
			At: time.Now().UTC(), Actor: actor, Action: action,
			Target: target, Detail: detail, IP: ip, Result: result,
		})
	}
	return err
}

func (db *DB) ListAudit(limit int, actor string) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT at, actor, action, target, detail, ip, result FROM audit`
	var args []any
	if actor != "" {
		q += ` WHERE actor = ?`
		args = append(args, actor)
	}
	q += ` ORDER BY at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.IP, &e.Result); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Enrollment tokens
// ---------------------------------------------------------------------------

type EnrollToken struct {
	ID                 int64     `json:"id"`
	Prefix             string    `json:"prefix"`
	Label              string    `json:"label"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	UsesAllowed        int       `json:"uses_allowed"`
	UsesConsumed       int       `json:"uses_consumed"`
	AllowRemoteContain bool      `json:"allow_remote_contain"`
	Revoked            bool      `json:"revoked"`
	// EstateID scopes the token to one customer. Agents enrolled with it
	// inherit the estate, so a generated installer lands in the right place
	// without the person running it supplying anything.
	EstateID int64 `json:"estate_id,omitempty"`
}

// CreateEnrollToken mints a token. The plaintext is returned exactly once; only
// its hash is persisted, so it cannot be recovered from the console later.
func (db *DB) CreateEnrollToken(label, createdBy string, ttl time.Duration, uses int, allowContain bool) (string, *EnrollToken, error) {
	if uses <= 0 {
		uses = 1
	}
	secret, err := NewSecret(32)
	if err != nil {
		return "", nil, err
	}
	// A recognisable prefix makes tokens greppable in logs and identifiable in
	// the UI without exposing the secret.
	plain := "wek_" + secret
	prefix := plain[:12]

	// ttl == 0 means "never expires". A NEGATIVE ttl must yield an
	// already-expired token, not an eternal one — treating it as "no expiry"
	// would turn a caller's arithmetic slip into a permanent credential.
	var expires int64
	if ttl != 0 {
		expires = time.Now().Add(ttl).Unix()
	}
	res, err := db.sql.Exec(
		`INSERT INTO enroll_tokens (token_hash, prefix, label, created_by, created_at, expires_at, uses_allowed, allow_remote_contain)
		 VALUES (?,?,?,?,?,?,?,?)`,
		HashToken(plain), prefix, label, createdBy, now(), expires, uses, boolInt(allowContain))
	if err != nil {
		return "", nil, err
	}
	id, _ := res.LastInsertId()
	return plain, &EnrollToken{
		ID: id, Prefix: prefix, Label: label, CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(), ExpiresAt: unixOrZero(expires),
		UsesAllowed: uses, AllowRemoteContain: allowContain,
	}, nil
}

// ConsumeEnrollToken validates a presented token and burns one use.
//
// Runs in a transaction so two agents racing on a single-use token cannot both
// succeed.
func (db *DB) ConsumeEnrollToken(plain string) (*EnrollToken, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var (
		t                EnrollToken
		expires, created int64
		revoked, contain int
	)
	err = tx.QueryRow(
		`SELECT id, prefix, label, created_by, created_at, expires_at, uses_allowed, uses_consumed, allow_remote_contain, revoked, COALESCE(estate_id, 0)
		 FROM enroll_tokens WHERE token_hash = ?`, HashToken(plain)).
		Scan(&t.ID, &t.Prefix, &t.Label, &t.CreatedBy, &created, &expires,
			&t.UsesAllowed, &t.UsesConsumed, &contain, &revoked, &t.EstateID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("unknown enrollment token")
	}
	if err != nil {
		return nil, err
	}
	if revoked != 0 {
		return nil, fmt.Errorf("enrollment token has been revoked")
	}
	if expires != 0 && time.Now().Unix() > expires {
		return nil, fmt.Errorf("enrollment token has expired")
	}
	if t.UsesConsumed >= t.UsesAllowed {
		return nil, fmt.Errorf("enrollment token has no uses remaining")
	}
	if _, err := tx.Exec(`UPDATE enroll_tokens SET uses_consumed = uses_consumed + 1 WHERE id = ?`, t.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	t.ExpiresAt = unixOrZero(expires)
	t.AllowRemoteContain = contain != 0
	t.UsesConsumed++
	return &t, nil
}

func (db *DB) ListEnrollTokens() ([]EnrollToken, error) {
	rows, err := db.sql.Query(
		`SELECT id, prefix, label, created_by, created_at, expires_at, uses_allowed, uses_consumed, allow_remote_contain, revoked
		 FROM enroll_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollToken
	for rows.Next() {
		var t EnrollToken
		var created, expires int64
		var contain, revoked int
		if err := rows.Scan(&t.ID, &t.Prefix, &t.Label, &t.CreatedBy, &created, &expires,
			&t.UsesAllowed, &t.UsesConsumed, &contain, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		t.ExpiresAt = unixOrZero(expires)
		t.AllowRemoteContain = contain != 0
		t.Revoked = revoked != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) RevokeEnrollToken(id int64, by string) error {
	_, err := db.sql.Exec(
		`UPDATE enroll_tokens SET revoked = 1, revoked_by = ?, revoked_at = ? WHERE id = ?`,
		by, now(), id)
	return err
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

type Agent struct {
	ID                 string    `json:"id"`
	Hostname           string    `json:"hostname"`
	Label              string    `json:"label"`
	Site               string    `json:"site"`
	Webroot            string    `json:"webroot"`
	Version            string    `json:"version"`
	OS                 string    `json:"os"`
	Arch               string    `json:"arch"`
	EnrolledAt         time.Time `json:"enrolled_at"`
	LastSeen           time.Time `json:"last_seen"`
	LastIP             string    `json:"last_ip"`
	AllowRemoteContain bool      `json:"allow_remote_contain"`
	AgentOptsIn        bool      `json:"agent_opts_in_contain"`
	MonitorActive      bool      `json:"monitor_active"`
	Retired            bool      `json:"retired"`
	EstateID           int64     `json:"estate_id,omitempty"`

	// Derived for display.
	Status       string `json:"status"`
	OpenCritical int    `json:"open_critical"`
	OpenHigh     int    `json:"open_high"`
	OpenTotal    int    `json:"open_total"`
}

// ContainAllowed reports whether remote containment may be ordered for this
// agent. Both the enrollment token's grant and the agent's own opt-in are
// required: neither the console alone nor the host alone can enable it.
func (a *Agent) ContainAllowed() bool { return a.AllowRemoteContain && a.AgentOptsIn }

func statusFor(lastSeen int64) string {
	if lastSeen == 0 {
		return "never"
	}
	age := time.Since(time.Unix(lastSeen, 0))
	switch {
	case age <= OnlineWindow:
		return "online"
	case age <= StaleWindow:
		return "stale"
	}
	return "offline"
}

type EnrollRequest struct {
	Hostname     string `json:"hostname"`
	Label        string `json:"label"`
	Site         string `json:"site"`
	Webroot      string `json:"webroot"`
	Version      string `json:"version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	OptInContain bool   `json:"opt_in_contain"`
}

// EnrollAgent registers a new agent and returns its id and plaintext
// credential. The credential is shown once and stored hashed.
func (db *DB) EnrollAgent(req EnrollRequest, tok *EnrollToken, ip string) (id, cred string, err error) {
	rawID, err := NewSecret(12)
	if err != nil {
		return "", "", err
	}
	id = "ag_" + rawID
	credSecret, err := NewSecret(32)
	if err != nil {
		return "", "", err
	}
	cred = "wac_" + credSecret

	_, err = db.sql.Exec(
		`INSERT INTO agents (id, hostname, label, site, webroot, version, os, arch,
		    cred_hash, enrolled_at, enrolled_via_token, last_seen, last_ip,
		    allow_remote_contain, agent_opts_in_contain, estate_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, req.Hostname, req.Label, req.Site, req.Webroot, req.Version, req.OS, req.Arch,
		HashToken(cred), now(), tok.ID, now(), ip,
		boolInt(tok.AllowRemoteContain), boolInt(req.OptInContain), nullIfZero(tok.EstateID))
	if err != nil {
		return "", "", err
	}
	return id, cred, nil
}

// AuthAgent validates an agent credential in constant time and returns the
// agent. Also refreshes last_seen, so authentication doubles as liveness.
func (db *DB) AuthAgent(id, cred, ip string) (*Agent, error) {
	var storedHash string
	a := &Agent{ID: id}
	var enrolled, lastSeen int64
	var allow, optIn, monitor, retired int
	// estate_id is selected here deliberately. Anything served to an agent on
	// the strength of this authentication has to be scoped to its own customer,
	// and a zero estate means "every estate" to the queries downstream. Leaving
	// it unpopulated would have let one customer's cross-site corroboration
	// exonerate a file on another customer's host.
	var estate sql.NullInt64
	err := db.sql.QueryRow(
		`SELECT hostname, label, site, webroot, version, os, arch, cred_hash,
		        enrolled_at, last_seen, last_ip, allow_remote_contain,
		        agent_opts_in_contain, monitor_active, retired, estate_id
		 FROM agents WHERE id = ?`, id).
		Scan(&a.Hostname, &a.Label, &a.Site, &a.Webroot, &a.Version, &a.OS, &a.Arch,
			&storedHash, &enrolled, &lastSeen, &a.LastIP, &allow, &optIn, &monitor, &retired,
			&estate)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("unknown agent")
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(HashToken(cred))) != 1 {
		return nil, fmt.Errorf("invalid agent credential")
	}
	a.EstateID = estate.Int64
	if retired != 0 {
		return nil, fmt.Errorf("agent has been retired")
	}
	a.EnrolledAt = time.Unix(enrolled, 0).UTC()
	a.LastSeen = time.Unix(lastSeen, 0).UTC()
	a.AllowRemoteContain = allow != 0
	a.AgentOptsIn = optIn != 0
	a.MonitorActive = monitor != 0
	a.Status = statusFor(lastSeen)

	if ip != "" {
		_, _ = db.sql.Exec(`UPDATE agents SET last_seen = ?, last_ip = ? WHERE id = ?`, now(), ip, id)
	}
	return a, nil
}

type Heartbeat struct {
	Load1        float64 `json:"load1"`
	Monitor      bool    `json:"monitor"`
	OpenFindings int     `json:"open_findings"`
	Version      string  `json:"version"`
}

func (db *DB) RecordHeartbeat(agentID string, hb Heartbeat) error {
	if _, err := db.sql.Exec(
		`INSERT INTO heartbeats (agent_id, at, load1, monitor, open_findings, version) VALUES (?,?,?,?,?,?)`,
		agentID, now(), hb.Load1, boolInt(hb.Monitor), hb.OpenFindings, hb.Version); err != nil {
		return err
	}
	_, err := db.sql.Exec(
		`UPDATE agents SET last_seen = ?, monitor_active = ?, version = CASE WHEN ? != '' THEN ? ELSE version END WHERE id = ?`,
		now(), boolInt(hb.Monitor), hb.Version, hb.Version, agentID)
	return err
}

// PruneHeartbeats keeps the table bounded. Heartbeats are only interesting in
// aggregate and recently.
func (db *DB) PruneHeartbeats(keep time.Duration) error {
	_, err := db.sql.Exec(`DELETE FROM heartbeats WHERE at < ?`, time.Now().Add(-keep).Unix())
	return err
}

// ListAgents returns the fleet. estateID scopes it to one customer; zero
// returns every agent.
func (db *DB) ListAgents(includeRetired bool, estateID int64) ([]Agent, error) {
	q := `SELECT a.id, a.hostname, a.label, a.site, a.webroot, a.version, a.os, a.arch,
	             a.enrolled_at, a.last_seen, a.last_ip, a.allow_remote_contain,
	             a.agent_opts_in_contain, a.monitor_active, a.retired,
	             COALESCE(SUM(CASE WHEN f.state='open' AND f.severity='critical' THEN 1 ELSE 0 END),0),
	             COALESCE(SUM(CASE WHEN f.state='open' AND f.severity='high'     THEN 1 ELSE 0 END),0),
	             COALESCE(SUM(CASE WHEN f.state='open' THEN 1 ELSE 0 END),0)
	      FROM agents a LEFT JOIN findings f ON f.agent_id = a.id WHERE 1=1`
	var args []any
	if !includeRetired {
		q += ` AND a.retired = 0`
	}
	if estateID != 0 {
		q += ` AND a.estate_id = ?`
		args = append(args, estateID)
	}
	q += ` GROUP BY a.id ORDER BY a.label, a.hostname`

	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Agent
	for rows.Next() {
		var a Agent
		var enrolled, lastSeen int64
		var allow, optIn, monitor, retired int
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Label, &a.Site, &a.Webroot, &a.Version,
			&a.OS, &a.Arch, &enrolled, &lastSeen, &a.LastIP, &allow, &optIn, &monitor, &retired,
			&a.OpenCritical, &a.OpenHigh, &a.OpenTotal); err != nil {
			return nil, err
		}
		a.EnrolledAt = time.Unix(enrolled, 0).UTC()
		a.LastSeen = time.Unix(lastSeen, 0).UTC()
		a.AllowRemoteContain = allow != 0
		a.AgentOptsIn = optIn != 0
		a.MonitorActive = monitor != 0
		a.Retired = retired != 0
		a.Status = statusFor(lastSeen)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (db *DB) GetAgent(id string) (*Agent, error) {
	agents, err := db.ListAgents(true, 0)
	if err != nil {
		return nil, err
	}
	for i := range agents {
		if agents[i].ID == id {
			return &agents[i], nil
		}
	}
	return nil, fmt.Errorf("agent not found")
}

func (db *DB) RetireAgent(id string) error {
	_, err := db.sql.Exec(`UPDATE agents SET retired = 1 WHERE id = ?`, id)
	return err
}

func (db *DB) SetAgentLabel(id, label string) error {
	_, err := db.sql.Exec(`UPDATE agents SET label = ? WHERE id = ?`, label, id)
	return err
}

// ---------------------------------------------------------------------------
// Reports and findings
// ---------------------------------------------------------------------------

type FindingInput struct {
	RuleID      string         `json:"rule_id"`
	Class       string         `json:"class"`
	Severity    string         `json:"severity"`
	Confidence  string         `json:"confidence"`
	Title       string         `json:"title"`
	Detail      string         `json:"detail"`
	Path        string         `json:"path"`
	SHA256      string         `json:"sha256"`
	Size        int64          `json:"size"`
	Line        int            `json:"line"`
	Evidence    string         `json:"evidence"`
	Remediation string         `json:"remediation"`
	Actionable  bool           `json:"actionable"`
	ContainPID  int            `json:"contain_pid"`
	Meta        map[string]any `json:"meta"`
}

// DedupeKey identifies "the same finding" across sweeps. Rule plus location
// plus digest: a shell that is modified in place gets a new digest and so
// registers as a new finding, which is the correct behaviour.
func (f FindingInput) DedupeKey() string {
	return strings.Join([]string{f.RuleID, f.Path, f.SHA256, fmt.Sprint(f.ContainPID)}, "|")
}

type Finding struct {
	ID      int64  `json:"id"`
	AgentID string `json:"agent_id"`
	// AgentLabel is the installer's label — "installer: fleet-rollout (linux-amd64)" —
	// which is shared by every host enrolled from the same installer and so
	// identifies a batch, not a machine.
	AgentLabel string `json:"agent_label"`
	// AgentHostname is the box an analyst has to actually open a shell on. It
	// is what triage needs and the label is not: an estate of eighteen hosts
	// enrolled from one installer showed eighteen identical agent names.
	AgentHostname string    `json:"agent_hostname"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	SeenCount     int       `json:"seen_count"`
	State         string    `json:"state"`
	StateBy       string    `json:"state_by"`
	StateNote     string    `json:"state_note"`
	FindingInput
}

// UpsertFinding records a finding, merging with an existing one from a prior
// sweep.
//
// A finding marked RESOLVED that reappears is reopened. An operator said they
// fixed it and the artefact is back, which is a reinfection — precisely the
// event the console exists to catch, and silently keeping it closed would hide
// it.
//
// A finding marked CONTAINED is NOT reopened, and that distinction matters.
// Containment means an operator has dealt with it; the artefact still being on
// disk is the expected state, not news. Reopening it meant every triage
// decision was undone by the next agent report — seconds later on a monitoring
// host — so the open counts could never fall and there was no way to show
// progress against an estate. The history is not lost: last_seen and seen_count
// keep advancing, so "contained but still present" remains visible and
// queryable.
func (db *DB) UpsertFinding(agentID string, f FindingInput) error {
	meta, _ := json.Marshal(f.Meta)
	key := f.DedupeKey()
	ts := now()

	res, err := db.sql.Exec(
		`UPDATE findings
		    SET last_seen = ?, seen_count = seen_count + 1,
		        state = CASE WHEN state = 'resolved' THEN 'open' ELSE state END,
		        severity = ?, confidence = ?, title = ?, detail = ?, evidence = ?,
		        remediation = ?, actionable = ?, meta = ?
		  WHERE agent_id = ? AND dedupe_key = ?`,
		ts, f.Severity, f.Confidence, f.Title, f.Detail, f.Evidence,
		f.Remediation, boolInt(f.Actionable), string(meta), agentID, key)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}

	_, err = db.sql.Exec(
		`INSERT INTO findings (agent_id, dedupe_key, first_seen, last_seen, rule_id, class,
		    severity, confidence, title, detail, path, sha256, size, line, evidence,
		    remediation, actionable, contain_pid, meta)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		agentID, key, ts, ts, f.RuleID, f.Class, f.Severity, f.Confidence, f.Title,
		f.Detail, f.Path, f.SHA256, f.Size, f.Line, f.Evidence, f.Remediation,
		boolInt(f.Actionable), f.ContainPID, string(meta))
	return err
}

type FindingFilter struct {
	AgentID string
	// EstateID scopes results to one customer. Zero means every estate, which
	// is what a single-tenant console wants.
	EstateID int64
	Severity string
	State    string
	Class    string
	Search   string
	Limit    int
	// Offset pages through a result set larger than Limit. A ten-host estate
	// produced 4,866 findings against a 500-row ceiling with no way to reach the
	// rest, which silently presents a truncated list as the whole truth.
	Offset int
}

// findingsWhere builds the shared WHERE fragment and its bound arguments, so
// the list and its total cannot drift apart. A count that applies different
// filters from the page it describes is worse than no count.
func (db *DB) findingsWhere(fl FindingFilter) (string, []any, error) {
	q := ""
	var args []any
	if fl.AgentID != "" {
		q += ` AND f.agent_id = ?`
		args = append(args, fl.AgentID)
	}
	if fl.EstateID != 0 {
		q += ` AND a.estate_id = ?`
		args = append(args, fl.EstateID)
	}
	if fl.Severity != "" {
		q += ` AND f.severity = ?`
		args = append(args, fl.Severity)
	}
	if fl.State != "" {
		q += ` AND f.state = ?`
		args = append(args, fl.State)
	}
	if fl.Class != "" {
		q += ` AND f.class = ?`
		args = append(args, fl.Class)
	}
	if fl.Search != "" {
		// Field-scoped query language; see query.go. Values are bound, field
		// names are allowlisted, and a parse error is returned to the operator
		// rather than silently matching everything — a search that quietly
		// ignores half its own query is worse than one that says it is wrong.
		frag, qargs, err := CompileQuery(fl.Search)
		if err != nil {
			return "", nil, fmt.Errorf("search: %w", err)
		}
		if frag != "" {
			q += ` AND ` + frag
			args = append(args, qargs...)
		}
	}
	return q, args, nil
}

func (db *DB) ListFindings(fl FindingFilter) ([]Finding, error) {
	if fl.Limit <= 0 || fl.Limit > 2000 {
		fl.Limit = 500
	}
	where, args, err := db.findingsWhere(fl)
	if err != nil {
		return nil, err
	}
	q := `SELECT f.id, f.agent_id, COALESCE(NULLIF(a.label,''), a.hostname), a.hostname, f.first_seen, f.last_seen,
	             f.seen_count, f.state, f.state_by, f.state_note, f.rule_id, f.class, f.severity,
	             f.confidence, f.title, f.detail, f.path, f.sha256, f.size, f.line, f.evidence,
	             f.remediation, f.actionable, f.contain_pid, f.meta
	      FROM findings f JOIN agents a ON a.id = f.agent_id WHERE 1=1` + where

	// Severity ordering is explicit: alphabetical would put "critical" after
	// "high", which is exactly wrong for a triage list.
	q += ` ORDER BY CASE f.severity
	                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	                  WHEN 'low' THEN 3 ELSE 4 END,
	                f.last_seen DESC LIMIT ? OFFSET ?`
	if fl.Offset < 0 {
		fl.Offset = 0
	}
	args = append(args, fl.Limit, fl.Offset)

	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		var first, last int64
		var actionable int
		var meta string
		if err := rows.Scan(&f.ID, &f.AgentID, &f.AgentLabel, &f.AgentHostname, &first, &last, &f.SeenCount,
			&f.State, &f.StateBy, &f.StateNote, &f.RuleID, &f.Class, &f.Severity,
			&f.Confidence, &f.Title, &f.Detail, &f.Path, &f.SHA256, &f.Size, &f.Line,
			&f.Evidence, &f.Remediation, &actionable, &f.ContainPID, &meta); err != nil {
			return nil, err
		}
		f.FirstSeen = time.Unix(first, 0).UTC()
		f.LastSeen = time.Unix(last, 0).UTC()
		f.Actionable = actionable != 0
		_ = json.Unmarshal([]byte(meta), &f.Meta)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) SetFindingState(id int64, state, by, note string) error {
	switch state {
	case "open", "contained", "dismissed", "resolved":
	default:
		return fmt.Errorf("invalid finding state %q", state)
	}
	_, err := db.sql.Exec(
		`UPDATE findings SET state = ?, state_by = ?, state_at = ?, state_note = ? WHERE id = ?`,
		state, by, now(), note, id)
	return err
}

// Correlation is one artefact seen on more than one agent.
type Correlation struct {
	SHA256   string   `json:"sha256"`
	Title    string   `json:"title"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Agents   []string `json:"agents"`
	Paths    []string `json:"paths"`
	Count    int      `json:"count"`
	// FirstSeen and LastSeen bound the spread. "Appeared on nine hosts within
	// four minutes" and "accumulated over two years" are the same row without
	// them, and they call for opposite responses.
	FirstSeen int64 `json:"first_seen"`
	LastSeen  int64 `json:"last_seen"`
	// Verdict and Rationale carry the estate's opinion — vendor, campaign,
	// singleton or inconclusive — so the page states what the correlation MEANS
	// rather than leaving an analyst to infer it from a hash and a count.
	Verdict   string `json:"verdict,omitempty"`
	Rationale string `json:"rationale,omitempty"`
	// SitesRunningTree is the denominator behind a singleton verdict: this file
	// is on 1 of N hosts that run the same plugin.
	SitesRunningTree int `json:"sites_running_tree,omitempty"`
}

// correlationHost is the SQL expression identifying one site installation.
//
// Counting agent rows was wrong in a way that mattered. Re-running an installer
// enrolls a second agent for the same machine, so a single-host estate reported
// "2 hosts" and every correlation denominator was inflated. Because a high
// count is what earns a vendor verdict — and a vendor verdict EXONERATES —
// duplicate enrollments were a route to suppressing detection of an implant.
//
// hostname+webroot, not hostname alone: one machine legitimately serves many
// sites, and each of those is an independent witness. Where a host reported no
// hostname the agent id is used, which can never over-count.
const correlationHost = `COALESCE(NULLIF(a.hostname,'') || '|' || a.webroot, f.agent_id)`

// Correlate finds byte-identical artefacts across the estate. This is the
// question a per-site scanner structurally cannot answer.
// Retired agents are excluded throughout: a decommissioned host is not evidence
// about what the estate runs today, and stale test enrollments would otherwise
// pad every count.
func (db *DB) Correlate(minHosts int, estateID int64) ([]Correlation, error) {
	if minHosts < 2 {
		minHosts = 2
	}
	estateFilter := ""
	args := []any{}
	if estateID != 0 {
		estateFilter = ` AND a.estate_id = ?`
		args = append(args, estateID)
	}
	args = append(args, minHosts)

	rows, err := db.sql.Query(`
		SELECT f.sha256,
		       MIN(f.title), MIN(f.rule_id), MIN(f.severity),
		       COUNT(DISTINCT `+correlationHost+`),
		       GROUP_CONCAT(DISTINCT COALESCE(NULLIF(a.label,''), NULLIF(a.hostname,''), a.id)),
		       GROUP_CONCAT(DISTINCT f.path),
		       MIN(f.first_seen), MAX(f.last_seen)
		  FROM findings f JOIN agents a ON a.id = f.agent_id AND a.retired = 0
		 WHERE f.sha256 != '' AND f.state != 'dismissed'`+estateFilter+`
		 GROUP BY f.sha256
		HAVING COUNT(DISTINCT `+correlationHost+`) >= ?
		 ORDER BY COUNT(DISTINCT `+correlationHost+`) DESC, MAX(f.last_seen) DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Correlation
	for rows.Next() {
		var c Correlation
		var agents, paths sql.NullString
		var first, last sql.NullInt64
		if err := rows.Scan(&c.SHA256, &c.Title, &c.RuleID, &c.Severity, &c.Count,
			&agents, &paths, &first, &last); err != nil {
			return nil, err
		}
		c.FirstSeen, c.LastSeen = first.Int64, last.Int64
		if agents.Valid {
			c.Agents = strings.Split(agents.String, ",")
		}
		if paths.Valid {
			c.Paths = strings.Split(paths.String, ",")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type ReportSummary struct {
	AgentID    string `json:"agent_id"`
	ReceivedAt int64  `json:"received_at"`
	Mode       string `json:"mode"`
	Verdict    string `json:"verdict"`
	DurationMS int64  `json:"duration_ms"`
	FilesSeen  int64  `json:"files_seen"`
	FilesRead  int64  `json:"files_read"`
	NCritical  int    `json:"n_critical"`
	NHigh      int    `json:"n_high"`
	NMedium    int    `json:"n_medium"`
	NLow       int    `json:"n_low"`
	NInfo      int    `json:"n_info"`
	NErrors    int    `json:"n_errors"`
	StartedAt  int64  `json:"started_at"`
	Raw        string `json:"-"`
}

func (db *DB) InsertReport(r ReportSummary) (int64, error) {
	res, err := db.sql.Exec(
		`INSERT INTO reports (agent_id, received_at, started_at, mode, verdict, duration_ms,
		    files_seen, files_read, n_critical, n_high, n_medium, n_low, n_info, n_errors, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.AgentID, now(), r.StartedAt, r.Mode, r.Verdict, r.DurationMS,
		r.FilesSeen, r.FilesRead, r.NCritical, r.NHigh, r.NMedium, r.NLow, r.NInfo, r.NErrors, r.Raw)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListReports(agentID string, limit int) ([]ReportSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT agent_id, received_at, started_at, mode, verdict, duration_ms,
	             files_seen, files_read, n_critical, n_high, n_medium, n_low, n_info, n_errors
	      FROM reports`
	var args []any
	if agentID != "" {
		q += ` WHERE agent_id = ?`
		args = append(args, agentID)
	}
	q += ` ORDER BY received_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportSummary
	for rows.Next() {
		var r ReportSummary
		if err := rows.Scan(&r.AgentID, &r.ReceivedAt, &r.StartedAt, &r.Mode, &r.Verdict,
			&r.DurationMS, &r.FilesSeen, &r.FilesRead, &r.NCritical, &r.NHigh,
			&r.NMedium, &r.NLow, &r.NInfo, &r.NErrors); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

type Command struct {
	ID               string          `json:"id"`
	AgentID          string          `json:"agent_id"`
	Kind             string          `json:"kind"`
	Params           json.RawMessage `json:"params"`
	CreatedAt        time.Time       `json:"created_at"`
	CreatedBy        string          `json:"created_by"`
	RequiresApproval bool            `json:"requires_approval"`
	ApprovedBy       string          `json:"approved_by"`
	ApprovedAt       time.Time       `json:"approved_at"`
	Status           string          `json:"status"`
	SentAt           time.Time       `json:"sent_at"`
	CompletedAt      time.Time       `json:"completed_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	Result           string          `json:"result"`
	Error            string          `json:"error"`
}

// DestructiveKinds are the commands that change a client's production server.
// They never dispatch on creation alone; a human must approve them separately.
// uninstall is here for a different reason from contain. It destroys nothing on
// the customer's server, but it BLINDS the estate — and a console that can
// silently disable monitoring everywhere is exactly what an intruder who
// reaches the console would use it for. Requiring a second human makes that
// impossible from a single stolen session.
var DestructiveKinds = map[string]bool{"contain": true, "uninstall": true}

func (db *DB) CreateCommand(agentID, kind string, params any, createdBy string, ttl time.Duration) (*Command, error) {
	switch kind {
	case "scan", "baseline", "verify", "contain", "contain_dryrun", "update_packs", "uninstall":
	default:
		return nil, fmt.Errorf("unknown command kind %q", kind)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	idSecret, err := NewSecret(12)
	if err != nil {
		return nil, err
	}
	id := "cmd_" + idSecret

	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	needsApproval := DestructiveKinds[kind]
	status := "approved"
	if needsApproval {
		// Created in a state that will never be handed to an agent.
		status = "pending"
	}
	expires := time.Now().Add(ttl).Unix()

	if _, err := db.sql.Exec(
		`INSERT INTO commands (id, agent_id, kind, params, created_at, created_by,
		    requires_approval, status, expires_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		id, agentID, kind, string(raw), now(), createdBy,
		boolInt(needsApproval), status, expires); err != nil {
		return nil, err
	}
	return db.GetCommand(id)
}

// CountApprovers returns how many enabled accounts could approve a destructive
// command.
func (db *DB) CountApprovers() (int, error) {
	var n int
	err := db.sql.QueryRow(
		`SELECT COUNT(*) FROM users WHERE disabled = 0 AND role IN ('admin','operator')`).Scan(&n)
	return n, err
}

// ApproveCommand is the second human step for a destructive command.
//
// Four eyes are ENFORCED whenever the deployment has more than one operator who
// could approve. A single compromised session must not be able to both order
// and authorise estate-wide destruction. On a genuinely single-operator install
// self-approval is permitted, because the alternative is a control nobody can
// ever satisfy — but the audit entry records that it happened.
func (db *DB) ApproveCommand(id, by string) error {
	var createdBy, status string
	err := db.sql.QueryRow(
		`SELECT created_by, status FROM commands WHERE id = ?`, id).Scan(&createdBy, &status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no such command")
	}
	if err != nil {
		return err
	}
	if status != "pending" {
		return fmt.Errorf("command is not awaiting approval")
	}
	if createdBy == by {
		approvers, err := db.CountApprovers()
		if err != nil {
			return err
		}
		if approvers > 1 {
			return fmt.Errorf(
				"%s created this command; a different operator must approve it", by)
		}
	}
	res, err := db.sql.Exec(
		`UPDATE commands SET status = 'approved', approved_by = ?, approved_at = ?
		  WHERE id = ? AND status = 'pending'`, by, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("command is not awaiting approval")
	}
	return nil
}

func (db *DB) CancelCommand(id, by string) error {
	_, err := db.sql.Exec(
		`UPDATE commands SET status = 'cancelled', completed_at = ?, error = ?
		  WHERE id = ? AND status IN ('pending','approved')`, now(), "cancelled by "+by, id)
	return err
}

// NextCommandForAgent hands out at most one approved, unexpired command and
// marks it sent, so a poll cannot dispatch the same command twice.
func (db *DB) NextCommandForAgent(agentID string) (*Command, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Expire stale work first: a command approved yesterday should not execute
	// when a long-offline agent reconnects.
	if _, err := tx.Exec(
		`UPDATE commands SET status='expired' WHERE agent_id=? AND status IN ('pending','approved') AND expires_at < ?`,
		agentID, now()); err != nil {
		return nil, err
	}

	// not_before is what actually staggers a scheduled sweep.
	//
	// The scheduler computes a per-agent offset so that a nightly scan does not
	// start on every host in the same instant — beginning a full sweep on 236
	// machines at once is a self-inflicted outage on shared infrastructure. That
	// offset used to be written into the command's params, which nothing reads:
	// the agent deliberately ignores params, and this query had no time
	// predicate, so every host collected its command on the next heartbeat and
	// the whole fleet swept inside one minute. Filtering here is what makes the
	// stagger real.
	var id string
	err = tx.QueryRow(
		`SELECT id FROM commands
		  WHERE agent_id = ? AND status = 'approved' AND not_before <= ?
		  ORDER BY created_at LIMIT 1`,
		agentID, now()).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE commands SET status='sent', sent_at=? WHERE id=?`, now(), id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCommand(id)
}

func (db *DB) CompleteCommand(id, status, result, errMsg string) error {
	switch status {
	case "done", "failed", "running":
	default:
		return fmt.Errorf("invalid completion status %q", status)
	}
	completed := now()
	if status == "running" {
		completed = 0
	}
	// Only a command that was actually dispatched may be completed. Otherwise an
	// agent could mark a still-PENDING destructive order as done and make it
	// look as though approval had happened.
	res, err := db.sql.Exec(
		`UPDATE commands SET status = ?, result = ?, error = ?, completed_at = ?
		  WHERE id = ? AND status IN ('sent','running')`,
		status, result, errMsg, completed, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("command is not in a dispatched state")
	}
	return nil
}

func (db *DB) GetCommand(id string) (*Command, error) {
	var c Command
	var params string
	var created, approved, sent, completed, expires int64
	var requires int
	err := db.sql.QueryRow(
		`SELECT id, agent_id, kind, params, created_at, created_by, requires_approval,
		        approved_by, approved_at, status, sent_at, completed_at, expires_at, result, error
		 FROM commands WHERE id = ?`, id).
		Scan(&c.ID, &c.AgentID, &c.Kind, &params, &created, &c.CreatedBy, &requires,
			&c.ApprovedBy, &approved, &c.Status, &sent, &completed, &expires, &c.Result, &c.Error)
	if err != nil {
		return nil, err
	}
	c.Params = json.RawMessage(params)
	c.CreatedAt = time.Unix(created, 0).UTC()
	c.ApprovedAt = unixOrZero(approved)
	c.SentAt = unixOrZero(sent)
	c.CompletedAt = unixOrZero(completed)
	c.ExpiresAt = unixOrZero(expires)
	c.RequiresApproval = requires != 0
	return &c, nil
}

func (db *DB) ListCommands(agentID string, limit int) ([]Command, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id FROM commands`
	var args []any
	if agentID != "" {
		q += ` WHERE agent_id = ?`
		args = append(args, agentID)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()

	out := make([]Command, 0, len(ids))
	for _, id := range ids {
		c, err := db.GetCommand(id)
		if err != nil {
			continue
		}
		out = append(out, *c)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

type FleetStats struct {
	Agents       int `json:"agents"`
	Online       int `json:"online"`
	Stale        int `json:"stale"`
	Offline      int `json:"offline"`
	OpenCritical int `json:"open_critical"`
	OpenHigh     int `json:"open_high"`
	OpenTotal    int `json:"open_total"`
	PendingCmds  int `json:"pending_commands"`
	Correlated   int `json:"correlated_artifacts"`
}

func (db *DB) Stats(ctx context.Context) (*FleetStats, error) {
	s := &FleetStats{}
	agents, err := db.ListAgents(false, 0)
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		s.Agents++
		switch a.Status {
		case "online":
			s.Online++
		case "stale":
			s.Stale++
		default:
			s.Offline++
		}
		s.OpenCritical += a.OpenCritical
		s.OpenHigh += a.OpenHigh
		s.OpenTotal += a.OpenTotal
	}
	_ = db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM commands WHERE status = 'pending'`).Scan(&s.PendingCmds)
	if c, err := db.Correlate(2, 0); err == nil {
		s.Correlated = len(c)
	}
	return s, nil
}

// ---------------------------------------------------------------------------

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unixOrZero(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

// Setting reads a persisted value. Missing keys return an empty string.
func (db *DB) Setting(key string) (string, error) {
	var v string
	err := db.sql.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetSetting stores a value, replacing any previous one.
func (db *DB) SetSetting(key, value string) error {
	_, err := db.sql.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// CountFindings returns how many rows the filter matches, ignoring Limit and
// Offset.
//
// A paged list without a total cannot tell an operator whether they are looking
// at everything. On an estate that produced 4,866 findings against a 500-row
// page, the difference between "these are the findings" and "these are the
// first 500 of 4,866" is the difference between a conclusion and a mistake.
func (db *DB) CountFindings(fl FindingFilter) (int, error) {
	fl.Limit, fl.Offset = 0, 0
	q, args, err := db.findingsWhere(fl)
	if err != nil {
		return 0, err
	}
	var n int
	err = db.sql.QueryRow(
		`SELECT COUNT(*) FROM findings f JOIN agents a ON a.id = f.agent_id WHERE 1=1`+q,
		args...).Scan(&n)
	return n, err
}

// SetFindingStatesByFilter applies one state to every finding a filter matches,
// and returns how many rows changed.
//
// Findings never age out. Once recorded, a row stays open until somebody says
// otherwise, which is correct — an agent that stops reporting a shell has not
// necessarily had it removed; it may simply have stopped scanning that path,
// and auto-resolving on absence would quietly close real intrusions.
//
// The consequence is that a rule which was too noisy leaves its output behind
// permanently. An estate of ten hosts accumulated 4,866 high findings, 3,436 of
// them one-per-file world-writable rows; fixing the rule stops new ones but
// cannot retract the old, and clearing them one at a time through the UI is not
// a real option at that scale.
//
// The filter is the same one the list uses, so an operator dismisses exactly
// what they are looking at — the count they were shown is the count that
// changes.
func (db *DB) SetFindingStatesByFilter(fl FindingFilter, state, by, note string) (int64, error) {
	switch state {
	case "open", "contained", "dismissed", "resolved":
	default:
		return 0, fmt.Errorf("invalid finding state %q", state)
	}
	fl.Limit, fl.Offset = 0, 0
	where, args, err := db.findingsWhere(fl)
	if err != nil {
		return 0, err
	}
	// The subquery carries the agents join the filter may reference; the
	// UPDATE itself cannot join in SQLite.
	q := `UPDATE findings SET state = ?, state_by = ?, state_at = ?, state_note = ?
	       WHERE id IN (SELECT f.id FROM findings f JOIN agents a ON a.id = f.agent_id
	                     WHERE 1=1` + where + `)`
	full := append([]any{state, by, now(), note}, args...)
	res, err := db.sql.Exec(q, full...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetAgentLastSeen overrides an agent's last-contact time.
//
// Exported so the silence watchdog can be tested without waiting fifteen
// minutes of real time for a host to go quiet. A watchdog that is impractical
// to test is a watchdog whose thresholds drift unnoticed.
func (db *DB) SetAgentLastSeen(id string, at time.Time) error {
	_, err := db.sql.Exec(`UPDATE agents SET last_seen = ? WHERE id = ?`, at.Unix(), id)
	return err
}

// CreateCommandAt queues work that must not start before a given time.
//
// Used by the scheduler to spread a fleet-wide sweep across its jitter window.
// Everything else goes through CreateCommand, which is this with no delay.
func (db *DB) CreateCommandAt(agentID, kind string, params any, createdBy string, ttl time.Duration, notBefore time.Time) (*Command, error) {
	c, err := db.CreateCommand(agentID, kind, params, createdBy, ttl)
	if err != nil {
		return nil, err
	}
	if !notBefore.IsZero() {
		if _, err := db.sql.Exec(`UPDATE commands SET not_before = ? WHERE id = ?`,
			notBefore.Unix(), c.ID); err != nil {
			return nil, err
		}
	}
	return c, nil
}
