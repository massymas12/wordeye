package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The finding query language.
//
// This feature turns operator text into a SQL WHERE clause, which is the most
// dangerous shape a feature can have. The injection tests below are the point
// of this file; the functional ones merely confirm it is worth having.

func queryDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// seedFinding inserts one finding with metadata.
func seedFinding(t *testing.T, db *DB, agent, rule, sev, path, meta string) {
	t.Helper()
	at := time.Now().Unix()
	if _, err := db.sql.Exec(
		`INSERT OR IGNORE INTO agents (id, hostname, site, label, enrolled_at, last_seen, cred_hash)
		 VALUES (?,?,'','',?,?,'')`, agent, agent, at, at); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(
		`INSERT INTO findings (agent_id, dedupe_key, first_seen, last_seen, rule_id, path,
		                       severity, state, class, sha256, meta)
		 VALUES (?,?,?,?,?,?,?,'open','SHELL','abc123',?)`,
		agent, agent+rule+path, at, at, rule, path, sev, meta); err != nil {
		t.Fatal(err)
	}
}

func seedCorpus(t *testing.T, db *DB) {
	t.Helper()
	seedFinding(t, db, "web01", "fs.heuristic_webshell", "critical",
		"wp-content/uploads/2026/08/x.php", `{"score":31,"tainted":true}`)
	seedFinding(t, db, "web01", "yara.php_shell_input_to_exec", "critical",
		"wp-content/plugins/acme/a.php", `{"yara_rule":"php_shell_input_to_exec"}`)
	seedFinding(t, db, "web02", "fs.timestomp_bulk", "low",
		"wp-content/mu-plugins", `{"count":49}`)
	seedFinding(t, db, "web02", "fs.heuristic_webshell", "medium",
		"wp-content/themes/divi/b.php", `{"score":9}`)
	seedFinding(t, db, "web03", "wp.config_world_readable", "medium",
		"wp-config.php", `{}`)
}

func search(t *testing.T, db *DB, q string) []Finding {
	t.Helper()
	f, err := db.ListFindings(FindingFilter{Search: q, Limit: 100})
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return f
}

// ---------------------------------------------------------------------------
// injection
// ---------------------------------------------------------------------------

// Every one of these must be treated as DATA. None may alter the statement,
// and none may error in a way that suggests it reached the parser.
func TestQueryResistsInjection(t *testing.T) {
	db := queryDB(t)
	seedCorpus(t, db)
	before := len(search(t, db, ""))
	if before != 5 {
		t.Fatalf("corpus has %d findings, want 5", before)
	}

	attacks := []string{
		`path:' OR '1'='1`,
		`path:'; DROP TABLE findings; --`,
		`path:") OR 1=1 --`,
		`severity:critical' UNION SELECT * FROM users --`,
		`meta.score:>0 UNION SELECT 1`,
		`path:x'||(SELECT cred_hash FROM agents)||'`,
		`rule:*' AND (SELECT COUNT(*) FROM sqlite_master)>0 AND '*`,
		`path:%' --`,
	}
	for _, a := range attacks {
		// It may match nothing or error, but it must never widen the result set
		// and must never damage the database.
		got, err := db.ListFindings(FindingFilter{Search: a, Limit: 100})
		if err != nil {
			continue // rejected outright, which is fine
		}
		if len(got) > before {
			t.Errorf("query %q returned %d rows, more than the %d in the corpus — it changed the statement",
				a, len(got), before)
		}
	}

	// The tables must still be intact and unchanged.
	if after := len(search(t, db, "")); after != before {
		t.Fatalf("corpus changed from %d to %d findings after injection attempts", before, after)
	}
	var users int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='findings'`).Scan(&users); err != nil || users != 1 {
		t.Fatalf("findings table missing after injection attempts (err=%v)", err)
	}
}

// A field name is resolved through an allowlist, so it cannot carry SQL either.
func TestQueryRejectsUnknownAndHostileFields(t *testing.T) {
	for _, q := range []string{
		`bogus:value`,
		`f.path) OR (1=1:x`,
		`meta.score);DROP TABLE findings;--:1`,
		`meta.:5`,
		`meta.a-b:5`,
		`meta.$.x:5`,
	} {
		if _, _, err := CompileQuery(q); err == nil {
			t.Errorf("accepted hostile field expression %q", q)
		}
	}
}

// Values must never be concatenated: the compiled SQL should contain no
// fragment of the user's input at all.
func TestCompiledSQLContainsNoUserInput(t *testing.T) {
	sql, args, err := CompileQuery(`path:SECRETVALUE AND meta.score:>7`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "SECRETVALUE") {
		t.Errorf("user value was spliced into SQL: %s", sql)
	}
	if strings.Count(sql, "?") < 3 {
		t.Errorf("expected bound placeholders, got: %s", sql)
	}
	var sawValue bool
	for _, a := range args {
		if s, ok := a.(string); ok && strings.Contains(s, "SECRETVALUE") {
			sawValue = true
		}
	}
	if !sawValue {
		t.Error("the value never reached the bound arguments")
	}
}

// ---------------------------------------------------------------------------
// behaviour
// ---------------------------------------------------------------------------

func TestQueryFieldsAndOperators(t *testing.T) {
	db := queryDB(t)
	seedCorpus(t, db)

	cases := []struct {
		q    string
		want int
		why  string
	}{
		{`severity:critical`, 2, "field match"},
		{`severity:critical AND path:uploads`, 1, "implicit substring plus AND"},
		{`severity:critical path:uploads`, 1, "adjacency means AND"},
		{`rule:yara.*`, 1, "glob"},
		{`path:*.php`, 4, "leading glob — wp-config.php ends in .php too"},
		{`agent:web02`, 2, "agent scope"},
		{`severity:critical OR severity:low`, 3, "OR"},
		{`NOT severity:critical`, 3, "negation"},
		{`severity:medium AND NOT path:wp-config`, 1, "AND NOT"},
		{`(severity:critical OR severity:low) AND agent:web02`, 1, "parentheses"},
		{`uploads`, 1, "bare word falls back to free text"},
		{`meta.score:>20`, 1, "numeric meta comparison"},
		{`meta.score:>5`, 2, "numeric meta comparison, wider"},
		{`meta.count:>40`, 1, "different meta key"},
		{`meta.yara_rule:input_to_exec`, 1, "string meta match"},
	}
	for _, c := range cases {
		got := search(t, db, c.q)
		if len(got) != c.want {
			var paths []string
			for _, f := range got {
				paths = append(paths, f.RuleID+" "+f.Path)
			}
			t.Errorf("%-52s got %d want %d (%s): %v", c.q, len(got), c.want, c.why, paths)
		}
	}
}

// The triage query that motivated this: on a 236-host estate, show me the
// heuristic's strongest hits that are not the known-benign bulk timestomp.
func TestQueryRealTriageCase(t *testing.T) {
	db := queryDB(t)
	seedCorpus(t, db)
	got := search(t, db, `meta.score:>20 AND NOT rule:timestomp`)
	if len(got) != 1 {
		t.Fatalf("expected the single high-scoring shell, got %d", len(got))
	}
	if !strings.Contains(got[0].Path, "uploads") {
		t.Errorf("wrong finding returned: %s", got[0].Path)
	}
}

// A malformed query must report itself rather than silently matching all rows.
func TestMalformedQueryIsAnError(t *testing.T) {
	db := queryDB(t)
	seedCorpus(t, db)
	for _, q := range []string{`(severity:critical`, `severity:`, `AND`, `meta.score:>abc`} {
		if _, err := db.ListFindings(FindingFilter{Search: q, Limit: 10}); err == nil {
			t.Errorf("malformed query %q was silently accepted", q)
		}
	}
}

// An empty query matches everything, so clearing the box behaves as expected.
func TestEmptyQueryMatchesAll(t *testing.T) {
	db := queryDB(t)
	seedCorpus(t, db)
	if got := search(t, db, "   "); len(got) != 5 {
		t.Errorf("blank query returned %d, want the whole corpus", len(got))
	}
}

// Complexity is bounded: a query is a triage tool, not a way to make the
// console's single writer do arbitrary work.
func TestQueryComplexityIsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxQueryTerms+5; i++ {
		if i > 0 {
			b.WriteString(" OR ")
		}
		b.WriteString("path:x")
	}
	if _, _, err := CompileQuery(b.String()); err == nil {
		t.Error("an unbounded query was accepted")
	}
	if _, _, err := CompileQuery(strings.Repeat("a", 3000)); err == nil {
		t.Error("an over-long query was accepted")
	}
}

// host: must select a machine. It used to resolve to the installer label when
// one was set, so on an estate enrolled from a single installer every host
// carried the same value and the field could not narrow anything.
func TestQueryHostMatchesTheMachineNotTheLabel(t *testing.T) {
	frag, args, err := CompileQuery("host:web-01")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frag, "a.hostname") {
		t.Errorf("host: compiles to %q, which does not reference the hostname", frag)
	}
	if strings.Contains(frag, "a.label") {
		t.Errorf("host: still matches the installer label: %q", frag)
	}
	if len(args) != 1 {
		t.Errorf("got %d bound args, want 1", len(args))
	}
}

// The label stays searchable under its own name, so "everything from that
// installer batch" is still a question you can ask.
func TestQueryLabelIsSeparatelySearchable(t *testing.T) {
	frag, _, err := CompileQuery("label:fleet-rollout")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frag, "a.label") {
		t.Errorf("label: compiles to %q", frag)
	}
}
