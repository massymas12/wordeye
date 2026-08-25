// Package store is the console's persistence layer.
//
// SQLite via a pure-Go driver, so the controller keeps CGO_ENABLED=0 and stays
// a single static binary. It also means the database is one file you can copy,
// back up, or open with the sqlite3 CLI mid-incident — which matters, because
// the questions that come up during an engagement are rarely the ones the UI
// anticipated.
package store

// schema is applied idempotently at open.
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ---------------------------------------------------------------------------
-- Customers
-- ---------------------------------------------------------------------------

-- An estate is one customer's set of sites. Everything an operator looks at is
-- scoped to one: a consultancy runs many clients through one console, and a
-- finding on one client's site must never be presented as context for another.
--
-- It also bounds cross-site consensus. "The same file on twenty sites" is only
-- evidence about vendor code if those sites are related enough to run the same
-- software, and mixing customers to reach a quorum would leak one client's
-- estate shape into another's report.
CREATE TABLE IF NOT EXISTS estates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    slug        TEXT NOT NULL UNIQUE,
    notes       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL DEFAULT '',
    archived    INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- Fleet
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agents (
    id                    TEXT PRIMARY KEY,
    hostname              TEXT NOT NULL DEFAULT '',
    label                 TEXT NOT NULL DEFAULT '',
    site                  TEXT NOT NULL DEFAULT '',
    webroot               TEXT NOT NULL DEFAULT '',
    version               TEXT NOT NULL DEFAULT '',
    os                    TEXT NOT NULL DEFAULT '',
    arch                  TEXT NOT NULL DEFAULT '',
    -- Credential issued at enrollment. Only the hash is stored: a stolen
    -- database must not yield working agent credentials.
    cred_hash             TEXT NOT NULL,
    enrolled_at           INTEGER NOT NULL,
    enrolled_via_token    INTEGER,
    last_seen             INTEGER NOT NULL DEFAULT 0,
    last_ip               TEXT NOT NULL DEFAULT '',
    -- Remote containment requires BOTH the token's grant and the agent's own
    -- opt-in. Console compromise alone must not be enough to destroy an estate.
    allow_remote_contain  INTEGER NOT NULL DEFAULT 0,
    agent_opts_in_contain INTEGER NOT NULL DEFAULT 0,
    monitor_active        INTEGER NOT NULL DEFAULT 0,
    retired               INTEGER NOT NULL DEFAULT 0,
    meta                  TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (enrolled_via_token) REFERENCES enroll_tokens(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS agents_last_seen ON agents(last_seen);

CREATE TABLE IF NOT EXISTS heartbeats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL,
    at            INTEGER NOT NULL,
    load1         REAL NOT NULL DEFAULT 0,
    monitor       INTEGER NOT NULL DEFAULT 0,
    open_findings INTEGER NOT NULL DEFAULT 0,
    version       TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS heartbeats_agent_at ON heartbeats(agent_id, at DESC);

-- ---------------------------------------------------------------------------
-- Detections
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    started_at  INTEGER NOT NULL DEFAULT 0,
    mode        TEXT NOT NULL DEFAULT 'scan',
    verdict     TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    files_seen  INTEGER NOT NULL DEFAULT 0,
    files_read  INTEGER NOT NULL DEFAULT 0,
    n_critical  INTEGER NOT NULL DEFAULT 0,
    n_high      INTEGER NOT NULL DEFAULT 0,
    n_medium    INTEGER NOT NULL DEFAULT 0,
    n_low       INTEGER NOT NULL DEFAULT 0,
    n_info      INTEGER NOT NULL DEFAULT 0,
    n_errors    INTEGER NOT NULL DEFAULT 0,
    raw         TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS reports_agent_at ON reports(agent_id, received_at DESC);

-- Findings are deduplicated per agent. A shell rediscovered on every sweep is
-- one row with a moving last_seen, not fifty: an operator needs to see what is
-- true now, and how long it has been true.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL,
    dedupe_key  TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    rule_id     TEXT NOT NULL,
    class       TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    confidence  TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    sha256      TEXT NOT NULL DEFAULT '',
    size        INTEGER NOT NULL DEFAULT 0,
    line        INTEGER NOT NULL DEFAULT 0,
    evidence    TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    actionable  INTEGER NOT NULL DEFAULT 0,
    contain_pid INTEGER NOT NULL DEFAULT 0,
    meta        TEXT NOT NULL DEFAULT '{}',
    state       TEXT NOT NULL DEFAULT 'open',
    state_by    TEXT NOT NULL DEFAULT '',
    state_at    INTEGER NOT NULL DEFAULT 0,
    state_note  TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_dedupe ON findings(agent_id, dedupe_key);
CREATE INDEX IF NOT EXISTS findings_sev ON findings(severity, last_seen DESC);
CREATE INDEX IF NOT EXISTS findings_state ON findings(state, severity);
-- Drives cross-estate correlation: the same digest on many agents is one
-- campaign, not many coincidences.
CREATE INDEX IF NOT EXISTS findings_sha ON findings(sha256);

-- ---------------------------------------------------------------------------
-- Command channel. Agents poll; nothing ever connects inbound to an agent, so
-- no client production server needs an open port or a firewall exception.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS commands (
    id                TEXT PRIMARY KEY,
    agent_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    params            TEXT NOT NULL DEFAULT '{}',
    created_at        INTEGER NOT NULL,
    created_by        TEXT NOT NULL DEFAULT '',
    -- Destructive commands require an explicit second step by a human.
    requires_approval INTEGER NOT NULL DEFAULT 0,
    approved_by       TEXT NOT NULL DEFAULT '',
    approved_at       INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'pending',
    sent_at           INTEGER NOT NULL DEFAULT 0,
    completed_at      INTEGER NOT NULL DEFAULT 0,
    expires_at        INTEGER NOT NULL DEFAULT 0,
    result            TEXT NOT NULL DEFAULT '',
    error             TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS commands_agent_status ON commands(agent_id, status);
CREATE INDEX IF NOT EXISTS commands_created ON commands(created_at DESC);

-- ---------------------------------------------------------------------------
-- Operators and enrollment
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Scheduled scans.
--
-- A full sweep is the expensive operation, and the EDR split makes it an
-- explicit choice: monitoring evaluates what changes, and a deep scan runs when
-- someone asks for one. "Someone" should be able to be a clock, because the
-- right time to sweep a production estate is 03:00 on its own timezone, not
-- whenever an analyst happens to be at a keyboard.
--
-- Scope is an estate OR a single agent, never both. Estate-wide is the useful
-- default for a managed fleet; per-agent exists for the one host that needs
-- different treatment.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL DEFAULT '',
    estate_id   INTEGER REFERENCES estates(id) ON DELETE CASCADE,
    agent_id    TEXT REFERENCES agents(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL DEFAULT 'scan',
    -- Minutes past midnight, in the timezone below. A single integer is enough
    -- for "run at 03:00" and cannot express a malformed cron expression.
    minute_of_day INTEGER NOT NULL DEFAULT 180,
    -- Bitmask, Sunday = bit 0. 127 is every day.
    weekdays    INTEGER NOT NULL DEFAULT 127,
    tz          TEXT NOT NULL DEFAULT 'UTC',
    enabled     INTEGER NOT NULL DEFAULT 1,
    -- Staggering. Firing a sweep on 236 hosts at the same instant is a
    -- self-inflicted outage on shared infrastructure; each agent's start is
    -- spread deterministically across this window.
    jitter_minutes INTEGER NOT NULL DEFAULT 30,
    last_run    INTEGER NOT NULL DEFAULT 0,
    next_run    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS schedules_due ON schedules(enabled, next_run);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    pass_hash     TEXT NOT NULL,
    pass_salt     TEXT NOT NULL,
    pass_iter     INTEGER NOT NULL,
    -- MFA is mandatory. An account that has not completed TOTP enrollment can
    -- log in only far enough to complete it, and can do nothing else.
    totp_secret   TEXT NOT NULL DEFAULT '',
    totp_enrolled INTEGER NOT NULL DEFAULT 0,
    -- Last accepted TOTP time step. A code is valid for 30s, so without
    -- pinning the step an intercepted code can be replayed until it expires.
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    role          TEXT NOT NULL DEFAULT 'operator',
    created_at    INTEGER NOT NULL,
    last_login    INTEGER NOT NULL DEFAULT 0,
    disabled      INTEGER NOT NULL DEFAULT 0,
    -- Throttles credential stuffing without external infrastructure.
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  INTEGER NOT NULL DEFAULT 0
);

-- Single-use codes for a lost authenticator. Hashed: they are
-- password-equivalent.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used_at   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    -- A session is only usable once the second factor has been presented.
    mfa_ok     INTEGER NOT NULL DEFAULT 0,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);

-- Agents may only enroll with a token minted here. Only the hash is stored, so
-- the token is unrecoverable after it is shown once at creation.
CREATE TABLE IF NOT EXISTS enroll_tokens (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash           TEXT NOT NULL UNIQUE,
    -- Shown in the UI so a token is identifiable without revealing it.
    prefix               TEXT NOT NULL DEFAULT '',
    label                TEXT NOT NULL DEFAULT '',
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL DEFAULT 0,
    uses_allowed         INTEGER NOT NULL DEFAULT 1,
    uses_consumed        INTEGER NOT NULL DEFAULT 0,
    -- Capability conferred on agents enrolled with this token.
    allow_remote_contain INTEGER NOT NULL DEFAULT 0,
    revoked              INTEGER NOT NULL DEFAULT 0,
    revoked_by           TEXT NOT NULL DEFAULT '',
    revoked_at           INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

-- Append-only by convention and by API: nothing in this codebase updates or
-- deletes from this table. If the console can order destruction across an
-- estate, every such order must leave a trace.
-- Small key/value store for values that must outlive a process but are not
-- domain data. The CSRF signing key lives here: deriving it per process meant
-- every console restart invalidated the tokens of sessions that were still
-- perfectly valid in this table, so an open browser tab could read pages but
-- failed every write with "invalid CSRF token".
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     INTEGER NOT NULL,
    actor  TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ip     TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at DESC);
CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor, at DESC);
`
