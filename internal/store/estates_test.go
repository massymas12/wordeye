package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Estates scope a console to one customer at a time, and carry a generated
// installer's enrollment through to the right place with no operator input on
// the host.

func estateDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateAndListEstates(t *testing.T) {
	db := estateDB(t)
	e, err := db.CreateEstate("Acme Hospitality Ltd", "retainer client", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if e.Slug != "acme-hospitality-ltd" {
		t.Errorf("slug = %q", e.Slug)
	}
	list, err := db.ListEstates(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "Acme Hospitality Ltd" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestEstateNamesAreUnique(t *testing.T) {
	db := estateDB(t)
	if _, err := db.CreateEstate("Acme", "", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateEstate("Acme", "", "bob"); err == nil {
		t.Error("a duplicate estate name was accepted")
	}
}

// Archiving must preserve the agents and their findings: that history is the
// engagement record.
func TestArchiveEstateKeepsAgents(t *testing.T) {
	db := estateDB(t)
	e, _ := db.CreateEstate("Acme", "", "alice")
	_, tok, err := db.CreateEnrollToken("t", "alice", time.Hour, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTokenEstate(tok.ID, e.ID); err != nil {
		t.Fatal(err)
	}
	tok.EstateID = e.ID
	if _, _, err := db.EnrollAgent(EnrollRequest{Hostname: "web01"}, tok, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := db.ArchiveEstate(e.ID, true); err != nil {
		t.Fatal(err)
	}
	agents, err := db.ListAgents(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Errorf("archiving an estate removed its agents (%d remain)", len(agents))
	}
}

// The point of the whole feature: an installer's token carries the estate, so
// the host lands under the right customer with no input from whoever ran it.
func TestEnrolledAgentInheritsTokenEstate(t *testing.T) {
	db := estateDB(t)
	e, _ := db.CreateEstate("Acme", "", "alice")
	plain, tok, err := db.CreateEnrollToken("installer: Acme", "alice", time.Hour, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTokenEstate(tok.ID, e.ID); err != nil {
		t.Fatal(err)
	}

	// Consume by the plaintext, exactly as the ingest handler does.
	consumed, err := db.ConsumeEnrollToken(plain)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.EstateID != e.ID {
		t.Fatalf("consumed token lost its estate: got %d want %d", consumed.EstateID, e.ID)
	}
	id, _, err := db.EnrollAgent(EnrollRequest{Hostname: "web01"}, consumed, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := db.EstateOfAgent(id); got != e.ID {
		t.Errorf("agent estate = %d, want %d", got, e.ID)
	}
}

// An unscoped token must leave the agent with no estate rather than a dangling
// reference to id 0.
func TestUnscopedTokenLeavesAgentUnassigned(t *testing.T) {
	db := estateDB(t)
	_, tok, err := db.CreateEnrollToken("manual", "alice", time.Hour, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := db.EnrollAgent(EnrollRequest{Hostname: "web02"}, tok, "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if got := db.EstateOfAgent(id); got != 0 {
		t.Errorf("agent estate = %d, want 0", got)
	}
}

func TestSetAgentEstateRejectsUnknown(t *testing.T) {
	db := estateDB(t)
	_, tok, _ := db.CreateEnrollToken("t", "alice", time.Hour, 1, false)
	id, _, err := db.EnrollAgent(EnrollRequest{Hostname: "web03"}, tok, "10.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetAgentEstate(id, 9999); err == nil {
		t.Error("moving an agent to a non-existent estate was allowed")
	}
}

// Slugs reach a download filename, so they must never carry path separators.
func TestSlugifyIsFilenameSafe(t *testing.T) {
	cases := map[string]string{
		"Acme Ltd":           "acme-ltd",
		"../../etc/passwd":   "etc-passwd",
		"Client (UK) & Co.":  "client-uk-co",
		"   spaced   out   ": "spaced-out",
		"...":                "",
		"a/b\\c":             "a-b-c",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

// Re-opening an existing database must apply the new columns without error,
// and must be safe to repeat.
func TestMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	for i := 0; i < 3; i++ {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if _, err := db.CreateEstate("Acme"+string(rune('a'+i)), "", "alice"); err != nil {
			t.Fatalf("create after reopen %d: %v", i, err)
		}
		db.Close()
	}
}
