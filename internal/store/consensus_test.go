package store

import (
	"path/filepath"
	"testing"
	"time"
)

// Cross-estate consensus.
//
// The premise: premium code (Divi, ACF Pro, Gravity Forms) publishes no
// checksum manifest, so provenance cannot verify it. Agreement across
// independent sites is the only remaining authority.
//
// The danger: the same query is how campaigns are detected. If "seen widely"
// meant "safe", an operator who compromised enough of the estate would
// exonerate their own shell — and the more sites they took, the more thoroughly
// it would be cleared. These tests exist mostly to hold that line.

func consensusDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// sight records a finding for an agent, creating the agent if needed.
func sight(t *testing.T, db *DB, agent, path, sha string, at time.Time) {
	t.Helper()
	_, err := db.sql.Exec(
		`INSERT OR IGNORE INTO agents (id, hostname, site, label, enrolled_at, last_seen, cred_hash)
		 VALUES (?, ?, '', '', ?, ?, '')`,
		agent, agent, at.Unix(), at.Unix())
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

func consensusOf(t *testing.T, db *DB, sha string) Consensus {
	t.Helper()
	m, err := db.ConsensusFor(0, []string{sha})
	if err != nil {
		t.Fatal(err)
	}
	return m[sha]
}

// The case this feature exists for: a premium plugin file identical across the
// estate is the publisher's code.
func TestConsensusVendorCodeIsCorroborated(t *testing.T) {
	db := consensusDB(t)
	const p = "wp-content/themes/Divi/core/components/Portability.php"
	base := time.Now().Add(-365 * 24 * time.Hour)
	for i, agent := range []string{"a1", "a2", "a3", "a4", "a5"} {
		// Installed over months, as an installed base actually accumulates.
		sight(t, db, agent, p, "deadbeef", base.Add(time.Duration(i)*30*24*time.Hour))
	}
	c := consensusOf(t, db, "deadbeef")
	if c.Verdict != ConsensusVendor {
		t.Fatalf("verdict = %s (%s), want vendor", c.Verdict, c.Rationale)
	}
	if !c.Corroborates() {
		t.Error("vendor verdict does not corroborate")
	}
	if c.Sites != 5 {
		t.Errorf("sites = %d, want 5", c.Sites)
	}
	t.Logf("%s: %s", c.Verdict, c.Rationale)
}

// THE POISONING CASE. A shell dropped on many sites must never be cleared by
// its own success. Nothing in a vendor tree, so nothing to corroborate.
func TestConsensusRefusesToExonerateAWidespreadShell(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-200 * 24 * time.Hour)
	// Twenty sites, same bytes, but dropped in uploads — not a vendor tree.
	for i := 0; i < 20; i++ {
		sight(t, db, string(rune('a'+i))+"-site",
			"wp-content/uploads/2026/07/x.php", "5he11", base.Add(time.Duration(i)*24*time.Hour))
	}
	c := consensusOf(t, db, "5he11")
	if c.Corroborates() {
		t.Fatalf("a shell on 20 sites was corroborated as vendor code: %s", c.Rationale)
	}
	if c.Verdict != ConsensusCampaign {
		t.Errorf("verdict = %s, want campaign", c.Verdict)
	}
	t.Logf("%s: %s", c.Verdict, c.Rationale)
}

// Same bytes at different paths is not vendor code however many sites have it:
// a publisher ships a file to one location.
func TestConsensusRejectsMovingPaths(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-300 * 24 * time.Hour)
	paths := []string{
		"wp-content/plugins/acme/a.php",
		"wp-content/plugins/acme/inc/b.php",
		"wp-content/plugins/acme/lib/c.php",
		"wp-content/plugins/acme/d.php",
	}
	for i, p := range paths {
		sight(t, db, string(rune('a'+i))+"-site", p, "m0ving", base.Add(time.Duration(i)*30*24*time.Hour))
	}
	c := consensusOf(t, db, "m0ving")
	if c.Corroborates() {
		t.Fatalf("a digest at %d paths was corroborated: %s", len(paths), c.Rationale)
	}
	t.Logf("%s: %s", c.Verdict, c.Rationale)
}

// A burst arrival is a deployment, not an installed base — even in a vendor
// tree and even on many sites.
func TestConsensusRejectsSimultaneousArrival(t *testing.T) {
	db := consensusDB(t)
	const p = "wp-content/plugins/acme/inc/util.php"
	base := time.Now().Add(-3 * 24 * time.Hour)
	for i := 0; i < 8; i++ {
		sight(t, db, string(rune('a'+i))+"-site", p, "burst", base.Add(time.Duration(i)*time.Hour))
	}
	c := consensusOf(t, db, "burst")
	if c.Corroborates() {
		t.Fatalf("a simultaneous arrival was corroborated: %s", c.Rationale)
	}
	if c.Verdict != ConsensusCampaign {
		t.Errorf("verdict = %s, want campaign", c.Verdict)
	}
	t.Logf("%s: %s", c.Verdict, c.Rationale)
}

// The most valuable verdict: a file unique to one site inside a plugin that
// many sites run. This RAISES suspicion rather than lowering it.
func TestConsensusFlagsSingletonInSharedTree(t *testing.T) {
	db := consensusDB(t)
	const tree = "wp-content/themes/Divi"
	base := time.Now().Add(-300 * 24 * time.Hour)
	// Six sites all run Divi and all report the same ordinary vendor file.
	for i := 0; i < 6; i++ {
		sight(t, db, string(rune('a'+i))+"-site",
			tree+"/functions.php", "vend0r", base.Add(time.Duration(i)*20*24*time.Hour))
	}
	// One of them has an extra file nobody else does.
	sight(t, db, "a-site", tree+"/includes/.cache.php", "0dd", time.Now().Add(-time.Hour))

	c := consensusOf(t, db, "0dd")
	if c.Verdict != ConsensusSingleton {
		t.Fatalf("verdict = %s (%s), want singleton", c.Verdict, c.Rationale)
	}
	if c.Corroborates() {
		t.Error("a singleton must never corroborate")
	}
	if c.SitesRunningTree < 6 {
		t.Errorf("sites_running_tree = %d, want >= 6", c.SitesRunningTree)
	}
	t.Logf("%s: %s", c.Verdict, c.Rationale)
}

// A lone site proves nothing either way — there is no estate to compare with.
func TestConsensusSingleSiteEstateIsInconclusive(t *testing.T) {
	db := consensusDB(t)
	sight(t, db, "only", "wp-content/plugins/acme/x.php", "l0ne", time.Now())
	c := consensusOf(t, db, "l0ne")
	if c.Verdict != ConsensusInconclusive {
		t.Errorf("verdict = %s (%s), want inconclusive", c.Verdict, c.Rationale)
	}
}

// Two agreeing sites are below the floor: they can share an operator, a backup
// image, or a compromise.
func TestConsensusBelowFloorIsInconclusive(t *testing.T) {
	db := consensusDB(t)
	const p = "wp-content/plugins/acme/x.php"
	base := time.Now().Add(-300 * 24 * time.Hour)
	sight(t, db, "a", p, "tw0", base)
	sight(t, db, "b", p, "tw0", base.Add(60*24*time.Hour))
	c := consensusOf(t, db, "tw0")
	if c.Corroborates() {
		t.Errorf("%d sites corroborated below the floor of %d: %s",
			c.Sites, consensusMinSites, c.Rationale)
	}
}

// Dismissed findings must not prop up a consensus.
func TestConsensusIgnoresDismissed(t *testing.T) {
	db := consensusDB(t)
	const p = "wp-content/plugins/acme/x.php"
	base := time.Now().Add(-300 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		sight(t, db, string(rune('a'+i))+"-s", p, "dism", base.Add(time.Duration(i)*30*24*time.Hour))
	}
	if _, err := db.sql.Exec(`UPDATE findings SET state='dismissed' WHERE sha256='dism'`); err != nil {
		t.Fatal(err)
	}
	c := consensusOf(t, db, "dism")
	if c.Sites != 0 {
		t.Errorf("dismissed findings counted toward consensus: sites = %d", c.Sites)
	}
}

// The same agent reporting repeatedly is one site, not many.
func TestConsensusCountsDistinctSitesOnly(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-300 * 24 * time.Hour)
	for i := 0; i < 6; i++ {
		// One agent, six different paths — six findings, one site.
		sight(t, db, "same-agent",
			"wp-content/plugins/acme/f"+string(rune('a'+i))+".php", "rep", base)
	}
	c := consensusOf(t, db, "rep")
	if c.Sites != 1 {
		t.Errorf("sites = %d, want 1: repeats from one agent are not independent", c.Sites)
	}
	if c.Corroborates() {
		t.Error("one agent corroborated itself")
	}
}

func TestVendorTreeOf(t *testing.T) {
	cases := map[string]string{
		"wp-content/plugins/acme/inc/x.php":     "wp-content/plugins/acme",
		"wp-content/themes/Divi/functions.php":  "wp-content/themes/Divi",
		"wp-content/mu-plugins/kinsta/boot.php": "wp-content/mu-plugins/kinsta",
		"wp-content/uploads/2026/07/x.php":      "",
		"wp-includes/version.php":               "",
		"index.php":                             "",
		"wp-content/plugins/acme":               "",
	}
	for in, want := range cases {
		if got := vendorTreeOf(in); got != want {
			t.Errorf("vendorTreeOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConsensusForHandlesEmptyInput(t *testing.T) {
	db := consensusDB(t)
	m, err := db.ConsensusFor(0, []string{"", "", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected no results for empty digests, got %d", len(m))
	}
}

// sightAs records a sighting with an explicit host identity, so a test can
// model two agent enrollments that are really the same machine.
func sightAs(t *testing.T, db *DB, agentID, hostname, webroot, path, sha string, retired bool, at time.Time) {
	t.Helper()
	r := 0
	if retired {
		r = 1
	}
	_, err := db.sql.Exec(
		`INSERT OR IGNORE INTO agents (id, hostname, webroot, site, label, enrolled_at, last_seen, cred_hash, retired)
		 VALUES (?, ?, ?, '', '', ?, ?, '', ?)`,
		agentID, hostname, webroot, at.Unix(), at.Unix(), r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.sql.Exec(
		`INSERT INTO findings (agent_id, dedupe_key, first_seen, last_seen, rule_id, path, sha256, severity, state)
		 VALUES (?, ?, ?, ?, 'test.rule', ?, ?, 'critical', 'open')`,
		agentID, agentID+"|"+path+"|"+sha, at.Unix(), at.Unix(), path, sha)
	if err != nil {
		t.Fatal(err)
	}
}

// Consensus EXONERATES: enough corroborating sites and a file is treated as
// vendor code the pattern engines should leave alone. The vote must therefore
// be per HOST, never per agent record.
//
// Re-running an installer enrolls a second agent for the same machine, which is
// an ordinary administrative event — the field estate did it on the first
// deployment. Counting those separately does not merely inflate a number on the
// correlation page; it hands an attacker with one foothold a way to
// manufacture the corroboration that suppresses detection of their own implant.
func TestConsensusCountsMachinesNotEnrollments(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-30 * 24 * time.Hour)
	const sha = "dup0000000000000000000000000000000000000000000000000000000000dup"
	const p = "wp-content/plugins/premium/inc/lib.php"

	// One machine, four enrollments.
	for i, id := range []string{"ag_a1", "ag_a2", "ag_a3", "ag_a4"} {
		sightAs(t, db, id, "host-a", "/www/site/public", p, sha, false,
			base.Add(time.Duration(i)*time.Hour))
	}
	// A genuinely different machine.
	sightAs(t, db, "ag_b1", "host-b", "/www/other/public", p, sha, false, base.Add(72*time.Hour))

	c := consensusOf(t, db, sha)
	if c.Sites != 2 {
		t.Errorf("Sites = %d, want 2 (four enrollments on host-a are one witness)", c.Sites)
	}
	if c.Verdict == ConsensusVendor {
		t.Errorf("one duplicated host manufactured a vendor verdict: %s", c.Rationale)
	}
}

// The same machine running two different sites is two installations, and each
// is entitled to a vote — the identity is host AND webroot, not host alone.
func TestConsensusSeparatesSitesOnOneHost(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-30 * 24 * time.Hour)
	const sha = "multi00000000000000000000000000000000000000000000000000000multi"
	const p = "wp-content/plugins/premium/inc/lib.php"

	sightAs(t, db, "ag_s1", "host-a", "/www/one/public", p, sha, false, base)
	sightAs(t, db, "ag_s2", "host-a", "/www/two/public", p, sha, false, base.Add(time.Hour))

	if c := consensusOf(t, db, sha); c.Sites != 2 {
		t.Errorf("Sites = %d, want 2 (two webroots on one host are two installations)", c.Sites)
	}
}

// A decommissioned host is not evidence about what the estate runs now. Stale
// enrollments left behind by testing must not pad any denominator.
func TestConsensusExcludesRetiredAgents(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-30 * 24 * time.Hour)
	const sha = "ret0000000000000000000000000000000000000000000000000000000000ret"
	const p = "wp-content/plugins/premium/inc/lib.php"

	sightAs(t, db, "ag_live", "host-live", "/www/a", p, sha, false, base)
	sightAs(t, db, "ag_dead", "host-dead", "/www/b", p, sha, true, base.Add(time.Hour))

	if c := consensusOf(t, db, sha); c.Sites != 1 {
		t.Errorf("Sites = %d, want 1 (the retired host must not vote)", c.Sites)
	}
}

// The point of the whole feature: turning estate agreement into something an
// agent can act on.
//
// Premium and bespoke code — Divi, Gravity Forms, a customer's own theme —
// publishes no checksum manifest, so provenance has no authority for it and
// every dangerous-looking primitive inside reaches the pattern engines
// unexonerated on every host, forever. The console can see the whole estate;
// one agent cannot. VendorAttestations is that asymmetry made usable.
func TestVendorAttestationsCoverCorroboratedPremiumCode(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-90 * 24 * time.Hour)
	const sha = "gf00000000000000000000000000000000000000000000000000000000000gf"
	const p = "wp-content/plugins/gravityforms/common.php"

	// Four independent sites, accumulating over months as an installed base
	// does rather than landing at once as a deployment does.
	for i, host := range []string{"a", "b", "c", "d"} {
		sightAs(t, db, "ag_"+host, "host-"+host, "/www/"+host, p, sha, false,
			base.Add(time.Duration(i)*14*24*time.Hour))
	}

	at, err := db.VendorAttestations(0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range at {
		if a.SHA256 == sha {
			found = true
			if a.Path != p {
				t.Errorf("attested path %q, want %q", a.Path, p)
			}
			if a.Sites < consensusMinSites {
				t.Errorf("attested on %d sites, below the floor of %d", a.Sites, consensusMinSites)
			}
		}
	}
	if !found {
		t.Errorf("a file corroborated across four sites over months was not attested: %+v", at)
	}
}

// A digest appearing at several paths is a campaign, not a vendor shipping a
// file, and must never be attested — that is the route by which corroboration
// would exonerate an implant.
func TestVendorAttestationsRefuseMovingPaths(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-90 * 24 * time.Hour)
	const sha = "mv00000000000000000000000000000000000000000000000000000000000mv"

	paths := []string{
		"wp-content/plugins/acme/a.php",
		"wp-content/plugins/acme/b.php",
		"wp-content/themes/x/c.php",
	}
	for i, host := range []string{"a", "b", "c", "d"} {
		sightAs(t, db, "ag_"+host, "host-"+host, "/www/"+host, paths[i%len(paths)], sha, false,
			base.Add(time.Duration(i)*14*24*time.Hour))
	}

	at, err := db.VendorAttestations(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range at {
		if a.SHA256 == sha {
			t.Error("a digest appearing at several paths was attested as vendor code")
		}
	}
}

// Arriving everywhere at once is a deployment, not an installed base. The soak
// is deliberate: the estate must have known a file for a while before it will
// vouch for it.
func TestVendorAttestationsRefuseASimultaneousArrival(t *testing.T) {
	db := consensusDB(t)
	now := time.Now()
	const sha = "bz00000000000000000000000000000000000000000000000000000000000bz"
	const p = "wp-content/plugins/acme/lib.php"

	for _, host := range []string{"a", "b", "c", "d"} {
		sightAs(t, db, "ag_"+host, "host-"+host, "/www/"+host, p, sha, false, now)
	}

	at, err := db.VendorAttestations(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range at {
		if a.SHA256 == sha {
			t.Error("a file that appeared on every site at once was attested as vendor code")
		}
	}
}
