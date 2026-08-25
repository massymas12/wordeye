package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"wordeye/internal/store"
)

// runToken mints an enrollment token from the host, without a console session.
//
// The console UI is the normal path and requires a password plus a second
// factor. This exists for the cases the UI cannot serve:
//
//   - bootstrapping or automating a rollout from a script
//   - recovering a console whose only administrator has lost their authenticator
//   - proving the ingest path works before anyone has signed in
//
// It is NOT a hole in the MFA requirement. It needs write access to the console
// database, which already means the host is owned — at that point an attacker
// can read every credential hash and forge sessions directly. Requiring a
// second factor to do something a file write could do anyway would be theatre.
//
// It cannot grant containment. Destructive authority stays a deliberate act
// through the audited console path, so a script that leaks its output cannot
// hand anyone the ability to destroy an estate.
func runToken(args []string) int {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	var (
		dbPath = fs.String("db", defaultDBPath(), "path to the console database")
		label  = fs.String("label", "cli", "label shown in the console")
		uses   = fs.Int("uses", 1, "how many agents may enroll with it")
		ttl    = fs.Duration("ttl", 24*time.Hour, "how long it remains valid")
		estate = fs.Int64("estate", 0, "estate id to file enrolled agents under (0 = unassigned)")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wordeye token — mint an enrollment token from the host

  Prints the token once. Only its hash is stored, so it cannot be recovered
  later. The token CANNOT grant remote containment; use the console for that.

EXAMPLES
  wordeye token --label "acme rollout" --uses 20 --ttl 72h
  wordeye token --estate 1

FLAGS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *uses < 1 || *uses > 500 {
		fmt.Fprintln(os.Stderr, "--uses must be between 1 and 500")
		return 2
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opening %s: %v\n", *dbPath, err)
		return 1
	}
	defer db.Close()

	// allowContain is hard-wired false: see the note above.
	plain, tok, err := db.CreateEnrollToken(*label, "cli", *ttl, *uses, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating token: %v\n", err)
		return 1
	}
	if *estate != 0 {
		if _, err := db.GetEstate(*estate); err != nil {
			fmt.Fprintf(os.Stderr, "estate %d: %v\n", *estate, err)
			return 1
		}
		if err := db.SetTokenEstate(tok.ID, *estate); err != nil {
			fmt.Fprintf(os.Stderr, "scoping token to estate: %v\n", err)
			return 1
		}
	}
	// Audited like any other token issue: a token minted outside the UI must
	// still be attributable when someone asks where an agent came from.
	_ = db.Audit("cli", "token.create", tok.Prefix,
		fmt.Sprintf("uses=%d ttl=%s estate=%d", *uses, *ttl, *estate), "local", "ok")

	fmt.Println(plain)
	fmt.Fprintf(os.Stderr, "\nlabel   %s\nuses    %d\nexpires %s\n",
		tok.Label, tok.UsesAllowed, tok.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintln(os.Stderr, "shown once; only its hash is stored")
	return 0
}
