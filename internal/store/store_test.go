package store

import (
	"strings"
	"testing"
)

// WAL is not a preference. Under the default rollback journal every write takes
// an exclusive lock on the whole database and fsyncs twice, so one agent
// posting a few thousand findings stalls every heartbeat queued behind it.
//
// That failure mode does not appear in a two-host test; it appears as an estate
// grows, which is exactly when a console must not start timing out.
func TestDatabaseUsesWAL(t *testing.T) {
	db := consensusDB(t)
	var mode string
	if err := db.sql.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

// Enrollment must survive the console re-rendering.
//
// This function used to mint a fresh secret on every call and overwrite the
// stored one. The console refreshes on a fifteen-second timer, so the secret
// behind the QR code was replaced while the user was still typing the six
// digits from it, and every code came back "not valid". The audit log showed
// mfa.setup_started firing on a timer with no user action at all — enrollment
// was not merely awkward, it was impossible.
func TestEnrollmentResumesRatherThanRestarting(t *testing.T) {
	db := consensusDB(t)
	u, err := db.CreateUser("alice", "correct horse battery staple", "admin")
	if err != nil {
		t.Fatal(err)
	}

	first, uri1, err := db.BeginTOTPEnrollment(u.ID, "WordEye", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// The page re-renders, several times, as it does on the refresh timer.
	for i := 0; i < 3; i++ {
		again, uri2, err := db.BeginTOTPEnrollment(u.ID, "WordEye", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("call %d issued a new secret; the QR already on screen is now dead", i+2)
		}
		if uri2 != uri1 {
			t.Errorf("call %d changed the otpauth URI", i+2)
		}
	}
}

// After an administrator resets the factor there is no enrollment in progress,
// so a new secret is correct — otherwise a reset would hand back the old one.
func TestEnrollmentRegeneratesAfterReset(t *testing.T) {
	db := consensusDB(t)
	u, err := db.CreateUser("bob", "correct horse battery staple", "admin")
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := db.BeginTOTPEnrollment(u.ID, "WordEye", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE users SET totp_secret = '', totp_enrolled = 0 WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	second, _, err := db.BeginTOTPEnrollment(u.ID, "WordEye", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Error("a reset factor handed back the previous secret")
	}
}
