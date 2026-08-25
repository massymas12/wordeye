package store

import (
	"database/sql"
	"fmt"
	"time"

	"wordeye/internal/authn"
)

// Operator accounts, sessions, and the mandatory second factor.

const (
	// SessionTTL bounds how long a console session lives. Short, because this
	// console can order destructive actions across client production servers.
	SessionTTL = 12 * time.Hour
	// MaxFailedLogins before a temporary lockout.
	MaxFailedLogins = 8
	LockoutDuration = 15 * time.Minute
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	TOTPEnrolled bool      `json:"totp_enrolled"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
	Disabled     bool      `json:"disabled"`
	LockedUntil  time.Time `json:"locked_until"`
}

// CanApprove reports whether the role may approve destructive commands.
func (u *User) CanApprove() bool { return u.Role == "admin" || u.Role == "operator" }

// CanAdmin reports whether the role may manage users and enrollment tokens.
func (u *User) CanAdmin() bool { return u.Role == "admin" }

func (db *DB) CountUsers() (int, error) {
	var n int
	err := db.sql.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (db *DB) CreateUser(username, password, role string) (*User, error) {
	switch role {
	case "admin", "operator", "viewer":
	default:
		return nil, fmt.Errorf("invalid role %q", role)
	}
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := authn.PasswordPolicy(password); err != nil {
		return nil, err
	}
	hash, salt, iter, err := authn.HashPassword(password)
	if err != nil {
		return nil, err
	}
	res, err := db.sql.Exec(
		`INSERT INTO users (username, pass_hash, pass_salt, pass_iter, role, created_at)
		 VALUES (?,?,?,?,?,?)`, username, hash, salt, iter, role, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, Role: role, CreatedAt: time.Now().UTC()}, nil
}

func (db *DB) GetUser(id int64) (*User, error) {
	var u User
	var created, last, locked int64
	var disabled, enrolled int
	err := db.sql.QueryRow(
		`SELECT id, username, role, totp_enrolled, created_at, last_login, disabled, locked_until
		 FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &enrolled, &created, &last, &disabled, &locked)
	if err != nil {
		return nil, err
	}
	u.TOTPEnrolled = enrolled != 0
	u.Disabled = disabled != 0
	u.CreatedAt = time.Unix(created, 0).UTC()
	u.LastLogin = unixOrZero(last)
	u.LockedUntil = unixOrZero(locked)
	return &u, nil
}

func (db *DB) ListUsers() ([]User, error) {
	rows, err := db.sql.Query(
		`SELECT id, username, role, totp_enrolled, created_at, last_login, disabled, locked_until
		 FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var created, last, locked int64
		var disabled, enrolled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &enrolled, &created, &last, &disabled, &locked); err != nil {
			return nil, err
		}
		u.TOTPEnrolled = enrolled != 0
		u.Disabled = disabled != 0
		u.CreatedAt = time.Unix(created, 0).UTC()
		u.LastLogin = unixOrZero(last)
		u.LockedUntil = unixOrZero(locked)
		out = append(out, u)
	}
	return out, rows.Err()
}

// VerifyPassword performs the FIRST factor only. A successful return means the
// caller must still complete MFA before the session is usable.
func (db *DB) VerifyPassword(username, password string) (*User, error) {
	var (
		id                     int64
		hash, salt, role       string
		iter, disabled, failed int
		locked                 int64
		enrolled               int
	)
	err := db.sql.QueryRow(
		`SELECT id, pass_hash, pass_salt, pass_iter, role, disabled, failed_logins, locked_until, totp_enrolled
		 FROM users WHERE username = ?`, username).
		Scan(&id, &hash, &salt, &iter, &role, &disabled, &failed, &locked, &enrolled)
	if err == sql.ErrNoRows {
		// Spend comparable time on an unknown user so the response does not
		// reveal which usernames exist.
		authn.VerifyPassword(password, "00", "00", 1000)
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, err
	}
	if disabled != 0 {
		return nil, fmt.Errorf("account is disabled")
	}
	if locked != 0 && time.Now().Unix() < locked {
		return nil, fmt.Errorf("account is temporarily locked; try again later")
	}
	if !authn.VerifyPassword(password, hash, salt, iter) {
		failed++
		if failed >= MaxFailedLogins {
			_, _ = db.sql.Exec(`UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?`,
				time.Now().Add(LockoutDuration).Unix(), id)
		} else {
			_, _ = db.sql.Exec(`UPDATE users SET failed_logins = ? WHERE id = ?`, failed, id)
		}
		return nil, fmt.Errorf("invalid credentials")
	}
	_, _ = db.sql.Exec(`UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?`, id)

	return &User{ID: id, Username: username, Role: role, TOTPEnrolled: enrolled != 0}, nil
}

// BeginTOTPEnrollment generates and stores a secret, returning the secret and
// the otpauth:// URI. Not marked enrolled until a code is verified, so a
// half-finished enrollment cannot lock anyone out.
// BeginTOTPEnrollment returns the secret to be shown as a QR code.
//
// An enrollment ALREADY in progress is resumed rather than restarted. This used
// to mint a fresh secret on every call and overwrite the stored one, which made
// enrollment impossible in practice: the console re-renders on a fifteen-second
// timer, so the secret behind the QR code was replaced while the user was still
// typing the six digits from it, and every code was rejected as invalid. The
// audit log showed setup_started firing on a timer with no user action at all.
//
// Regenerating is still correct when there is no enrollment underway. An
// administrator reset clears the secret, and the next call issues a new one.
func (db *DB) BeginTOTPEnrollment(userID int64, issuer, account string) (secret, uri string, err error) {
	var existing string
	var enrolled int
	err = db.sql.QueryRow(
		`SELECT COALESCE(totp_secret,''), COALESCE(totp_enrolled,0) FROM users WHERE id = ?`,
		userID).Scan(&existing, &enrolled)
	if err != nil {
		return "", "", err
	}
	// Resume: the QR already on screen must keep working.
	if existing != "" && enrolled == 0 {
		return existing, authn.OTPAuthURL(issuer, account, existing), nil
	}

	secret, err = authn.NewTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if _, err := db.sql.Exec(
		`UPDATE users SET totp_secret = ?, totp_enrolled = 0 WHERE id = ?`, secret, userID); err != nil {
		return "", "", err
	}
	return secret, authn.OTPAuthURL(issuer, account, secret), nil
}

// CompleteTOTPEnrollment verifies the first code and issues recovery codes,
// which are returned in plaintext exactly once.
func (db *DB) CompleteTOTPEnrollment(userID int64, code string) ([]string, error) {
	var secret string
	if err := db.sql.QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, userID).Scan(&secret); err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, fmt.Errorf("no enrollment in progress")
	}
	if !authn.VerifyTOTP(secret, code) {
		return nil, fmt.Errorf("that code is not valid")
	}
	codes, err := authn.NewRecoveryCodes(10)
	if err != nil {
		return nil, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`UPDATE users SET totp_enrolled = 1, totp_last_step = ? WHERE id = ?`,
		authn.TOTPStep(time.Now()), userID); err != nil {
		return nil, err
	}
	// Re-enrollment invalidates any previous codes.
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	for _, c := range codes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes (user_id, code_hash) VALUES (?,?)`,
			userID, authn.HashRecoveryCode(c)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifySecondFactor accepts either a TOTP code or an unused recovery code.
//
// TOTP codes are pinned to their time step and refused on reuse: a code remains
// valid for up to 30 seconds, and without this an intercepted code could be
// replayed within that window.
func (db *DB) VerifySecondFactor(userID int64, code string) error {
	var secret string
	var lastStep int64
	var enrolled int
	if err := db.sql.QueryRow(
		`SELECT totp_secret, totp_enrolled, totp_last_step FROM users WHERE id = ?`, userID).
		Scan(&secret, &enrolled, &lastStep); err != nil {
		return err
	}
	if enrolled == 0 {
		return fmt.Errorf("multi-factor authentication is not set up for this account")
	}

	if authn.VerifyTOTP(secret, code) {
		step := authn.TOTPStep(time.Now())
		if step <= lastStep {
			return fmt.Errorf("that code has already been used")
		}
		_, err := db.sql.Exec(`UPDATE users SET totp_last_step = ? WHERE id = ?`, step, userID)
		return err
	}

	// Recovery code fallback.
	hash := authn.HashRecoveryCode(code)
	res, err := db.sql.Exec(
		`UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at = 0`,
		now(), userID, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	return fmt.Errorf("invalid code")
}

func (db *DB) RecoveryCodesRemaining(userID int64) (int, error) {
	var n int
	err := db.sql.QueryRow(
		`SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at = 0`, userID).Scan(&n)
	return n, err
}

// ResetMFA clears a user's second factor so they can re-enroll. Admin-only, and
// audited by the caller: this is the one operation that can bypass MFA.
func (db *DB) ResetMFA(userID int64) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE users SET totp_secret = '', totp_enrolled = 0, totp_last_step = 0 WHERE id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	// Existing sessions must not survive an MFA reset.
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) SetUserDisabled(userID int64, disabled bool) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), userID); err != nil {
		return err
	}
	if disabled {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ChangePassword(userID int64, newPassword string) error {
	if err := authn.PasswordPolicy(newPassword); err != nil {
		return err
	}
	hash, salt, iter, err := authn.HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = db.sql.Exec(
		`UPDATE users SET pass_hash = ?, pass_salt = ?, pass_iter = ? WHERE id = ?`,
		hash, salt, iter, userID)
	return err
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type Session struct {
	ID        string
	UserID    int64
	MFAOK     bool
	ExpiresAt time.Time
}

// CreateSession issues a session that is NOT yet MFA-satisfied. It grants
// nothing beyond the ability to present a second factor.
func (db *DB) CreateSession(userID int64, ip, ua string) (string, error) {
	secret, err := NewSecret(32)
	if err != nil {
		return "", err
	}
	id := "ses_" + secret
	_, err = db.sql.Exec(
		`INSERT INTO sessions (id, user_id, created_at, expires_at, mfa_ok, ip, user_agent)
		 VALUES (?,?,?,?,0,?,?)`,
		id, userID, now(), time.Now().Add(SessionTTL).Unix(), ip, ua)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (db *DB) MarkSessionMFA(id string) error {
	_, err := db.sql.Exec(`UPDATE sessions SET mfa_ok = 1 WHERE id = ?`, id)
	return err
}

// LookupSession returns the session and its user, or an error if expired.
func (db *DB) LookupSession(id string) (*Session, *User, error) {
	var s Session
	var expires int64
	var mfa int
	err := db.sql.QueryRow(
		`SELECT id, user_id, mfa_ok, expires_at FROM sessions WHERE id = ?`, id).
		Scan(&s.ID, &s.UserID, &mfa, &expires)
	if err == sql.ErrNoRows {
		return nil, nil, fmt.Errorf("no session")
	}
	if err != nil {
		return nil, nil, err
	}
	if time.Now().Unix() > expires {
		_, _ = db.sql.Exec(`DELETE FROM sessions WHERE id = ?`, id)
		return nil, nil, fmt.Errorf("session expired")
	}
	s.MFAOK = mfa != 0
	s.ExpiresAt = time.Unix(expires, 0).UTC()

	u, err := db.GetUser(s.UserID)
	if err != nil {
		return nil, nil, err
	}
	if u.Disabled {
		return nil, nil, fmt.Errorf("account is disabled")
	}
	return &s, u, nil
}

func (db *DB) DeleteSession(id string) error {
	_, err := db.sql.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (db *DB) PruneSessions() error {
	_, err := db.sql.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now())
	return err
}

func (db *DB) TouchLogin(userID int64) error {
	_, err := db.sql.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, now(), userID)
	return err
}
