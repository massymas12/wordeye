package store

import (
	"strings"
	"testing"
	"time"
)

// Estate isolation for cross-site consensus.
//
// A security review found that estates.go asserted consensus was bounded by
// customer while ConsensusFor applied no such filter. Documentation claiming a
// property the code does not implement is worse than silence: a reviewer reads
// the comment and stops looking.
//
// Two things were wrong once the filter was missing. The evidence was weaker
// (unrelated customers' software has no reason to agree, so agreement means
// less), and the verdict disclosed how many OTHER clients run a given file.

// sightIn records a finding for an agent belonging to an estate.
func sightIn(t *testing.T, db *DB, estateID int64, agent, path, sha string, at time.Time) {
	t.Helper()
	_, err := db.sql.Exec(
		`INSERT OR IGNORE INTO agents (id, hostname, site, label, enrolled_at, last_seen, cred_hash, estate_id)
		 VALUES (?, ?, '', '', ?, ?, '', ?)`,
		agent, agent, at.Unix(), at.Unix(), nullIfZero(estateID))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.sql.Exec(
		`INSERT INTO findings (agent_id, dedupe_key, first_seen, last_seen, rule_id, path, sha256, severity, state)
		 VALUES (?, ?, ?, ?, 'test.rule', ?, ?, 'critical', 'open')`,
		agent, agent+"|"+path+"|"+sha, at.Unix(), at.Unix(), path, sha)
	if err != nil {
		t.Fatal(err)
	}
}

// A quorum must not be assembled from another customer's machines.
func TestConsensusDoesNotBorrowAnotherEstatesSites(t *testing.T) {
	db := consensusDB(t)
	acme, _ := db.CreateEstate("Acme", "", "alice")
	other, _ := db.CreateEstate("Globex", "", "alice")

	const p = "wp-content/plugins/premium/x.php"
	base := time.Now().Add(-300 * 24 * time.Hour)

	// One site at Acme, four at Globex. Unscoped, that is five and would
	// corroborate; scoped to Acme it is one and must not.
	sightIn(t, db, acme.ID, "acme-1", p, "shared", base)
	for i := 0; i < 4; i++ {
		sightIn(t, db, other.ID, "globex-"+string(rune('a'+i)), p, "shared",
			base.Add(time.Duration(i+1)*30*24*time.Hour))
	}

	got, err := db.ConsensusFor(acme.ID, []string{"shared"})
	if err != nil {
		t.Fatal(err)
	}
	c := got["shared"]
	if c.Sites != 1 {
		t.Errorf("Acme consensus counted %d sites — another customer's machines leaked in", c.Sites)
	}
	if c.Corroborates() {
		t.Errorf("corroborated using another estate's sites: %s", c.Rationale)
	}

	// Globex has four of its own and should reach a verdict on its own merits.
	got2, err := db.ConsensusFor(other.ID, []string{"shared"})
	if err != nil {
		t.Fatal(err)
	}
	if got2["shared"].Sites != 4 {
		t.Errorf("Globex consensus counted %d sites, want 4", got2["shared"].Sites)
	}
}

// The singleton denominator must also be estate-scoped, or a file present on
// one Acme site would look unremarkable because Globex runs the same plugin.
func TestSingletonDenominatorIsEstateScoped(t *testing.T) {
	db := consensusDB(t)
	acme, _ := db.CreateEstate("Acme", "", "alice")
	other, _ := db.CreateEstate("Globex", "", "alice")

	const tree = "wp-content/themes/Divi"
	base := time.Now().Add(-300 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		sightIn(t, db, other.ID, "globex-"+string(rune('a'+i)),
			tree+"/functions.php", "vend0r", base)
	}
	sightIn(t, db, acme.ID, "acme-1", tree+"/functions.php", "vend0r", base)
	sightIn(t, db, acme.ID, "acme-1", tree+"/.hidden.php", "0dd", time.Now())

	got, err := db.ConsensusFor(acme.ID, []string{"0dd"})
	if err != nil {
		t.Fatal(err)
	}
	// Acme runs one site under that tree, so it has nothing to compare against
	// and must say so rather than borrowing Globex's five.
	if n := got["0dd"].SitesRunningTree; n != 1 {
		t.Errorf("sites_running_tree = %d, want 1 — the denominator crossed customers", n)
	}
}

// Estate 0 means "no scoping", which is the correct behaviour on a
// single-tenant console where no estates have been created.
func TestConsensusUnscopedStillWorks(t *testing.T) {
	db := consensusDB(t)
	const p = "wp-content/plugins/acme/x.php"
	base := time.Now().Add(-300 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		sightIn(t, db, 0, "s"+string(rune('a'+i)), p, "unsc",
			base.Add(time.Duration(i)*30*24*time.Hour))
	}
	got, err := db.ConsensusFor(0, []string{"unsc"})
	if err != nil {
		t.Fatal(err)
	}
	if got["unsc"].Sites != 4 {
		t.Errorf("unscoped consensus counted %d sites, want 4", got["unsc"].Sites)
	}
}

// A vendor tree is derived from an agent-reported path, so it can contain LIKE
// metacharacters. Unescaped, a directory named "%" matches every path in the
// table and inflates the singleton denominator into a fabricated verdict.
func TestSitesRunningTreeEscapesLikeWildcards(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-300 * 24 * time.Hour)

	// Plenty of unrelated findings that a "%" pattern would sweep up.
	for i := 0; i < 6; i++ {
		sightIn(t, db, 0, "s"+string(rune('a'+i)),
			"wp-content/plugins/real/file.php", "other", base)
	}
	// One site with a plugin directory literally named "%".
	sightIn(t, db, 0, "evil", `wp-content/plugins/%/payload.php`, "wild", time.Now())

	n, err := db.sitesRunningTree(`wp-content/plugins/%`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("sitesRunningTree matched %d agents — the LIKE wildcard was not escaped", n)
	}
}

func TestLikeEscape(t *testing.T) {
	cases := map[string]string{
		`plain`:      `plain`,
		`100%`:       `100\%`,
		`a_b`:        `a\_b`,
		`back\slash`: `back\\slash`,
	}
	for in, want := range cases {
		if got := likeEscape(in); got != want {
			t.Errorf("likeEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

// Clicking an estate must show only that customer's agents.
func TestListAgentsFiltersByEstate(t *testing.T) {
	db := estateDB(t)
	acme, _ := db.CreateEstate("Acme", "", "alice")
	globex, _ := db.CreateEstate("Globex", "", "alice")
	now := time.Now()

	sightIn(t, db, acme.ID, "acme-web1", "wp-content/plugins/p/a.php", "h1", now)
	sightIn(t, db, acme.ID, "acme-web2", "wp-content/plugins/p/b.php", "h2", now)
	sightIn(t, db, globex.ID, "globex-web1", "wp-content/plugins/p/c.php", "h3", now)
	sightIn(t, db, 0, "unassigned", "wp-content/plugins/p/d.php", "h4", now)

	all, err := db.ListAgents(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Errorf("unscoped list returned %d agents, want 4", len(all))
	}

	only, err := db.ListAgents(false, acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 2 {
		t.Fatalf("Acme returned %d agents, want 2", len(only))
	}
	for _, a := range only {
		if !strings.HasPrefix(a.ID, "acme-") {
			t.Errorf("Acme's fleet contains %q from another customer", a.ID)
		}
	}

	// Findings must scope the same way, or the two views disagree.
	f, err := db.ListFindings(FindingFilter{EstateID: acme.ID, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 {
		t.Errorf("Acme findings returned %d, want 2", len(f))
	}
}
