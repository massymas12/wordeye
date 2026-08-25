package agent

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"wordeye/internal/model"
)

// Database checks.
//
// A significant share of WordPress persistence never touches the filesystem:
// autoloaded options carrying executable payloads, redirect rows that create
// doorway pages, scheduled events that re-download a dropper, injected posts.
// A file scanner is blind to all of it.
//
// Connecting directly rather than shelling out to wp-cli matters for more than
// speed: wp-cli has to bootstrap WordPress to answer a query, so on an install
// that is broken — or that the attacker has deliberately broken — it returns
// nothing at all, exactly when the answers matter most.

var (
	dbNameRe  = regexp.MustCompile(`define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]*)['"]`)
	dbUserRe  = regexp.MustCompile(`define\s*\(\s*['"]DB_USER['"]\s*,\s*['"]([^'"]*)['"]`)
	dbPassRe  = regexp.MustCompile(`define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"]([^'"]*)['"]`)
	dbHostRe  = regexp.MustCompile(`define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"]([^'"]*)['"]`)
	tblPrefix = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]*)['"]`)
	identSafe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

type dbConfig struct {
	Host, Name, User, Pass, Prefix string
}

// loadDBConfig reads credentials from wp-config.php, allowing CLI flags to
// override for hosts where the config is generated or externalised.
func (a *Agent) loadDBConfig() (dbConfig, error) {
	c := dbConfig{
		Host: a.cfg.DBHost, Name: a.cfg.DBName,
		User: a.cfg.DBUser, Pass: a.cfg.DBPass, Prefix: a.cfg.DBPrefix,
	}
	if c.Name == "" || c.User == "" {
		p, ok := findWPConfig(a.cfg.Webroot)
		if !ok {
			return c, fmt.Errorf("wp-config.php not found")
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return c, err
		}
		grab := func(re *regexp.Regexp, dst *string) {
			if *dst != "" {
				return
			}
			if m := re.FindSubmatch(b); m != nil {
				*dst = string(m[1])
			}
		}
		grab(dbNameRe, &c.Name)
		grab(dbUserRe, &c.User)
		grab(dbPassRe, &c.Pass)
		grab(dbHostRe, &c.Host)
		grab(tblPrefix, &c.Prefix)
	}
	if c.Host == "" {
		c.Host = "localhost"
	}
	if c.Prefix == "" {
		c.Prefix = "wp_"
	}
	if !identSafe.MatchString(c.Prefix) {
		return c, fmt.Errorf("refusing to use unsafe table prefix %q", c.Prefix)
	}
	if c.Name == "" {
		return c, fmt.Errorf("could not determine DB_NAME")
	}
	return c, nil
}

// dsn builds a go-sql-driver connection string, handling the socket, host, and
// host:port forms WordPress accepts.
func (c dbConfig) dsn() string {
	base := c.User + ":" + c.Pass + "@"
	switch {
	case strings.HasPrefix(c.Host, "/"):
		return base + "unix(" + c.Host + ")/" + c.Name + "?timeout=10s&readTimeout=30s"
	case strings.Contains(c.Host, ":") && !strings.Contains(c.Host, "]"):
		parts := strings.SplitN(c.Host, ":", 2)
		if strings.HasPrefix(parts[1], "/") { // host:/path/to/socket
			return base + "unix(" + parts[1] + ")/" + c.Name + "?timeout=10s&readTimeout=30s"
		}
		return base + "tcp(" + c.Host + ")/" + c.Name + "?timeout=10s&readTimeout=30s"
	default:
		return base + "tcp(" + c.Host + ":3306)/" + c.Name + "?timeout=10s&readTimeout=30s"
	}
}

func (a *Agent) checkDatabase(ctx context.Context) {
	cfg, err := a.loadDBConfig()
	if err != nil {
		a.rep.AddCheck(model.CheckStatus{ID: "db", State: model.CheckUnavailable, Reason: err.Error()})
		return
	}
	db, err := sql.Open("mysql", cfg.dsn())
	if err != nil {
		a.rep.AddCheck(model.CheckStatus{ID: "db", State: model.CheckError, Reason: err.Error()})
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(2)

	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		a.rep.AddCheck(model.CheckStatus{ID: "db", State: model.CheckError, Reason: "connect: " + err.Error()})
		return
	}

	p := cfg.Prefix
	a.timed("db.options", func() (model.CheckState, string) { return a.dbAutoloadedCode(ctx, db, p) })
	a.timed("db.cron", func() (model.CheckState, string) { return a.dbCron(ctx, db, p) })
	a.timed("db.redirects", func() (model.CheckState, string) { return a.dbRedirects(ctx, db, p) })
	a.timed("db.content", func() (model.CheckState, string) { return a.dbSpamContent(ctx, db, p) })
	a.timed("db.deserialization", func() (model.CheckState, string) { return a.dbDeserialization(ctx, db, p) })
	a.timed("db.users", func() (model.CheckState, string) { return a.dbUsers(ctx, db, p) })
	a.timed("db.apppasswords", func() (model.CheckState, string) { return a.dbAppPasswords(ctx, db, p) })
	a.timed("db.searchconsole", func() (model.CheckState, string) { return a.dbSearchConsoleTokens(ctx, db, p) })
}

// dbAutoloadedCode finds options loaded on every request that contain PHP
// execution primitives — the classic fileless backdoor.
func (a *Agent) dbAutoloadedCode(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	q := fmt.Sprintf(`SELECT option_name, LEFT(option_value, 200) FROM %soptions
	                  WHERE autoload IN ('yes','on','auto','auto-on')
	                    AND (option_value LIKE '%%eval(%%' OR option_value LIKE '%%base64_decode(%%'
	                      OR option_value LIKE '%%gzinflate(%%' OR option_value LIKE '%%create_function(%%'
	                      OR option_value LIKE '%%shell_exec(%%' OR option_value LIKE '%%assert(%%')
	                  LIMIT 25`, p)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return model.CheckError, err.Error()
	}
	defer rows.Close()
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			continue
		}
		a.emit(model.Finding{
			RuleID:      "db.autoloaded_code",
			Class:       "DB",
			Severity:    model.SevCritical,
			Confidence:  model.ConfLikely,
			Title:       "Autoloaded option contains code-execution markers: " + name,
			Detail:      "Autoloaded options are read on every page load. A payload stored here needs no file on disk and survives a complete filesystem cleanup.",
			Evidence:    truncate(val, 200),
			Remediation: fmt.Sprintf("Inspect and remove: SELECT option_value FROM %soptions WHERE option_name='%s'", p, name),
			Meta:        map[string]any{"option": name},
		})
	}
	return model.CheckOK, ""
}

// dbSearchConsoleTokens finds search-engine ownership verification tokens.
//
// This is persistence that survives everything else. An operator who adds their
// own google-site-verification token gains ownership of the property in Search
// Console, and from there can submit sitemaps, request indexing of spam URLs,
// read the site's search traffic, and — most usefully to them — keep all of it
// after the shells are gone, the passwords are rotated and the site is declared
// clean. No file, no code execution, nothing for a scanner to match.
//
// Tokens are legitimate: most sites have one. So this reports the INVENTORY and
// asks the operator to confirm ownership, rather than pretending to know which
// token is theirs. An unrecognised verification token is the finding.
func (a *Agent) dbSearchConsoleTokens(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	// Every major SEO plugin stores these under its own option name, and
	// hand-added ones land in the theme's header injection settings.
	// option_name LIKE '%verif%' was far too broad. It matched
	// filemanager_email_verified_19 — a plugin's own bookkeeping, nothing to do
	// with search-engine ownership — and reported it as an ownership token at
	// medium severity. A rule that cries wolf on unrelated options is a rule
	// analysts learn to scroll past, which costs more than it catches.
	//
	// Ownership tokens are recognisable by their VALUE: each search engine
	// publishes a fixed marker string. Name matching is kept only for the
	// narrow, unambiguous cases, and '%verif%' is replaced by '%site_verif%',
	// which no ordinary option name carries by accident.
	q := searchConsoleQuery(p)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return model.CheckError, err.Error()
	}
	defer rows.Close()

	var found int
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			continue
		}
		found++
		a.emit(model.Finding{
			RuleID:     "db.search_console_token",
			Class:      "DB",
			Severity:   model.SevMedium,
			Confidence: model.ConfReview,
			Title:      "Search-engine ownership token present: " + name,
			Detail: "A verification token grants ownership of this site in the search engine's console — sitemap " +
				"submission, indexing requests and traffic data. It is stored in the database, so it survives file " +
				"cleanup, password rotation and reinstallation entirely. Most sites legitimately have one; the " +
				"question is whether THIS one is yours.",
			Evidence:    truncate(val, 200),
			Remediation: "Confirm every token against your own Search Console/Bing property list. Remove any you do not recognise, then check the property's user list for unfamiliar owners.",
			Meta:        map[string]any{"option": name},
		})
	}
	if err := rows.Err(); err != nil {
		return model.CheckError, err.Error()
	}
	if found == 0 {
		return model.CheckOK, "no ownership tokens stored"
	}
	return model.CheckOK, fmt.Sprintf("%d ownership token(s) require owner confirmation", found)
}

// dbCron inspects the serialized cron array for hooks that look like payload
// re-downloaders. Scheduled events are how an implant reinstalls itself hours
// after a "successful" cleanup.
func (a *Agent) dbCron(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	var val string
	err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT option_value FROM %soptions WHERE option_name='cron' LIMIT 1", p)).Scan(&val)
	if err == sql.ErrNoRows {
		return model.CheckOK, "no cron option"
	}
	if err != nil {
		return model.CheckError, err.Error()
	}

	hookRe := regexp.MustCompile(`s:\d+:"([^"]{3,80})";a:\d+:\{s:32:`)
	suspicious := regexp.MustCompile(`(?i)(eval|base64|assert|shell_exec|gzinflate|create_function|^[0-9a-f]{16,}$)`)
	seen := map[string]bool{}
	for _, m := range hookRe.FindAllStringSubmatch(val, -1) {
		hook := m[1]
		if seen[hook] || !suspicious.MatchString(hook) {
			continue
		}
		seen[hook] = true
		a.emit(model.Finding{
			RuleID:      "db.suspicious_cron",
			Class:       "DB",
			Severity:    model.SevHigh,
			Confidence:  model.ConfLikely,
			Title:       "Suspicious scheduled event: " + hook,
			Detail:      "WP-Cron hooks with encoded or random-looking names are a common re-infection mechanism.",
			Remediation: "Confirm which plugin registers this hook. If none does, delete the event.",
			Meta:        map[string]any{"hook": hook},
		})
	}
	return model.CheckOK, ""
}

// dbRedirects finds doorway rows in redirect-plugin tables. These create spam
// landing pages with no file and no signature anywhere on disk.
func (a *Agent) dbRedirects(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	kw := a.set.IOCs.SpamKeywords
	if len(kw) == 0 {
		return model.CheckNotApplicable, "no spam keywords in the loaded packs"
	}
	tables := []struct{ table, col string }{
		{p + "redirects", "url"},
		{p + "redirection_items", "url"},
		{p + "yoast_indexable", "permalink"},
	}
	checked := 0
	for _, t := range tables {
		if !identSafe.MatchString(t.table) {
			continue
		}
		if !tableExists(ctx, db, t.table) {
			continue
		}
		checked++
		var where []string
		var args []any
		for _, k := range kw {
			where = append(where, t.col+" LIKE ?")
			args = append(args, "%"+k+"%")
		}
		q := fmt.Sprintf("SELECT %s FROM %s WHERE %s LIMIT 25", t.col, t.table, strings.Join(where, " OR "))
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			continue
		}
		var hits []string
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				hits = append(hits, u)
			}
		}
		rows.Close()
		if len(hits) == 0 {
			continue
		}
		a.emit(model.Finding{
			RuleID:      "db.redirect_doorway",
			Class:       "DB",
			Severity:    model.SevHigh,
			Confidence:  model.ConfLikely,
			Title:       fmt.Sprintf("%d spam doorway row(s) in %s", len(hits), t.table),
			Detail:      "Matched: " + truncate(strings.Join(hits, ", "), 400),
			Remediation: "Delete the attacker rows individually; legitimate migration redirects often live in the same table.",
			Meta:        map[string]any{"table": t.table, "rows": hits},
		})
	}
	if checked == 0 {
		return model.CheckNotApplicable, "no redirect plugin tables present"
	}
	return model.CheckOK, ""
}

func (a *Agent) dbSpamContent(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	kw := a.set.IOCs.SpamKeywords
	if len(kw) == 0 {
		return model.CheckNotApplicable, "no spam keywords in the loaded packs"
	}
	var where []string
	var args []any
	for _, k := range kw {
		where = append(where, "post_title LIKE ? OR post_content LIKE ?")
		args = append(args, "%"+k+"%", "%"+k+"%")
	}
	q := fmt.Sprintf(`SELECT COUNT(*) FROM %sposts WHERE post_status='publish' AND (%s)`,
		p, strings.Join(where, " OR "))
	var n int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return model.CheckError, err.Error()
	}
	if n > 0 {
		a.emit(model.Finding{
			RuleID:      "db.spam_content",
			Class:       "DB",
			Severity:    model.SevHigh,
			Confidence:  model.ConfLikely,
			Title:       fmt.Sprintf("%d published post(s) match campaign spam keywords", n),
			Detail:      "Injected content published under the site's own authority, which is what damages search reputation.",
			Remediation: "Review and remove; then request re-indexing once the cloak is gone.",
			Meta:        map[string]any{"count": n},
		})
	}
	return model.CheckOK, ""
}

// dbDeserialization looks for object-injection payloads and phar:// triggers.
func (a *Agent) dbDeserialization(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	gadget := `O:[0-9]+:"(Monolog|GuzzleHttp|Symfony|PHPUnit|SplFileObject|SplFileInfo|Faker|PharData|SoapClient|SimplePie_File|TCPDF|Imagick)`
	q := fmt.Sprintf(`SELECT option_name FROM %soptions WHERE option_value REGEXP ? LIMIT 15`, p)
	rows, err := db.QueryContext(ctx, q, gadget)
	if err != nil {
		return model.CheckError, err.Error()
	}
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	rows.Close()
	if len(names) > 0 {
		a.emit(model.Finding{
			RuleID:      "db.deserialization_gadget",
			Class:       "DB",
			Severity:    model.SevHigh,
			Confidence:  model.ConfReview,
			Title:       "Option(s) hold a serialized deserialization-gadget class",
			Detail:      "These classes are not normally serialized into wp_options: " + strings.Join(names, ", "),
			Remediation: "Inspect the serialized value for a POP chain before deleting.",
			Meta:        map[string]any{"options": names},
		})
	}

	// phar:// anywhere in options or meta is a deserialization trigger.
	for _, t := range []struct{ table, key, val string }{
		{p + "options", "option_name", "option_value"},
		{p + "postmeta", "meta_key", "meta_value"},
		{p + "usermeta", "meta_key", "meta_value"},
	} {
		if !tableExists(ctx, db, t.table) {
			continue
		}
		q := fmt.Sprintf("SELECT %s FROM %s WHERE %s LIKE '%%phar://%%' LIMIT 10", t.key, t.table, t.val)
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			continue
		}
		var keys []string
		for rows.Next() {
			var k string
			if rows.Scan(&k) == nil {
				keys = append(keys, k)
			}
		}
		rows.Close()
		if len(keys) > 0 {
			a.emit(model.Finding{
				RuleID:      "db.phar_reference",
				Class:       "DB",
				Severity:    model.SevHigh,
				Confidence:  model.ConfReview,
				Title:       "phar:// reference stored in " + t.table,
				Detail:      "Keys: " + strings.Join(keys, ", ") + ". phar:// stream access triggers deserialization of embedded metadata.",
				Remediation: "Inspect the stored value.",
				Meta:        map[string]any{"table": t.table, "keys": keys},
			})
		}
	}
	return model.CheckOK, ""
}

// dbUsers audits administrator accounts — the persistence layer that survives
// every file cleanup and every password reset of *other* accounts.
func (a *Agent) dbUsers(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	q := fmt.Sprintf(`SELECT u.ID, u.user_login, u.user_email, u.user_registered
	                  FROM %susers u
	                  JOIN %susermeta m ON m.user_id = u.ID AND m.meta_key = '%scapabilities'
	                  WHERE m.meta_value LIKE '%%administrator%%'
	                  ORDER BY u.user_registered DESC LIMIT 200`, p, p, p)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return model.CheckError, err.Error()
	}
	defer rows.Close()

	var incidentStart time.Time
	if s := a.set.IOCs.IncidentStart; s != "" {
		incidentStart, _ = time.Parse("2006-01-02", s)
	}
	oddName := regexp.MustCompile(`(?i)^wp[0-9a-f]{5,}$|^user[0-9]{4,}$|[0-9a-f]{10,}`)

	total := 0
	for rows.Next() {
		var id int
		var login, email, registered string
		if err := rows.Scan(&id, &login, &email, &registered); err != nil {
			continue
		}
		total++

		var flags []string
		if !incidentStart.IsZero() {
			if reg, err := time.Parse("2006-01-02 15:04:05", registered); err == nil &&
				!reg.Before(incidentStart) {
				flags = append(flags, "registered on/after incident onset")
			}
		}
		if oddName.MatchString(login) {
			flags = append(flags, "machine-generated username")
		}
		for _, d := range a.set.IOCs.SuspectEmailDomains {
			if strings.Contains(strings.ToLower(email), "@"+d+".") {
				flags = append(flags, "free/throwaway email domain")
				break
			}
		}
		for _, d := range a.set.IOCs.VendorDomains {
			if strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(d)) {
				flags = append(flags, "former-vendor domain still holding administrator")
				break
			}
		}
		if len(flags) == 0 {
			continue
		}
		a.emit(model.Finding{
			RuleID:      "db.suspicious_admin",
			Class:       "DB",
			Severity:    model.SevHigh,
			Confidence:  model.ConfReview,
			Title:       fmt.Sprintf("Administrator %q warrants review", login),
			Detail:      fmt.Sprintf("%s <%s>, registered %s — %s", login, email, registered, strings.Join(flags, "; ")),
			Remediation: "Verify against your staff/vendor inventory. Remove or demote if unrecognised, and rotate sessions afterwards.",
			Meta:        map[string]any{"user_id": id, "login": login, "email": email, "registered": registered, "flags": flags},
		})
	}
	a.emit(model.Finding{
		RuleID:     "db.admin_inventory",
		Class:      "DB",
		Severity:   model.SevInfo,
		Confidence: model.ConfConfirmed,
		Title:      fmt.Sprintf("%d administrator account(s)", total),
		Detail:     "Baseline figure for comparison across the estate.",
		Meta:       map[string]any{"count": total},
	})
	return model.CheckOK, ""
}

// dbAppPasswords enumerates application passwords, which authenticate to the
// REST API and are unaffected by a password reset — a persistence mechanism
// that routinely outlives an otherwise complete remediation.
func (a *Agent) dbAppPasswords(ctx context.Context, db *sql.DB, p string) (model.CheckState, string) {
	q := fmt.Sprintf(`SELECT u.user_login, m.meta_value FROM %susermeta m
	                  JOIN %susers u ON u.ID = m.user_id
	                  WHERE m.meta_key = '_application_passwords' AND m.meta_value != '' LIMIT 100`, p, p)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return model.CheckError, err.Error()
	}
	defer rows.Close()

	nameRe := regexp.MustCompile(`"name";s:\d+:"([^"]*)"`)
	for rows.Next() {
		var login, blob string
		if err := rows.Scan(&login, &blob); err != nil {
			continue
		}
		var names []string
		for _, m := range nameRe.FindAllStringSubmatch(blob, -1) {
			names = append(names, m[1])
		}
		if len(names) == 0 {
			continue
		}
		a.emit(model.Finding{
			RuleID:      "db.application_password",
			Class:       "DB",
			Severity:    model.SevHigh,
			Confidence:  model.ConfReview,
			Title:       fmt.Sprintf("%s has %d application password(s)", login, len(names)),
			Detail:      "Named: " + strings.Join(names, ", ") + ". These keep working after a password reset and grant REST API access.",
			Remediation: "Confirm each corresponds to a known integration; revoke the rest.",
			Meta:        map[string]any{"user": login, "names": names},
		})
	}
	return model.CheckOK, ""
}

func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n string
	err := db.QueryRowContext(ctx, "SHOW TABLES LIKE ?", name).Scan(&n)
	return err == nil
}

// checkIntegrity delegates to wp-cli for core and plugin checksum verification,
// which needs wordpress.org egress and WordPress's own manifest handling. It is
// the one place the agent still shells out, and it degrades to "skipped" rather
// than failing when wp-cli is unavailable.
func (a *Agent) checkIntegrity(ctx context.Context) {
	a.timed("wp.integrity", func() (model.CheckState, string) {
		wp, err := lookWPCLI()
		if err != nil {
			return model.CheckUnavailable, "wp-cli not available"
		}
		run := func(args ...string) string {
			all := append([]string{"--path=" + a.cfg.Webroot, "--skip-plugins", "--skip-themes"}, args...)
			out, _ := runCmdCombined(ctx, 180*time.Second, wp, all...)
			return out
		}
		core := run("core", "verify-checksums")
		for _, line := range strings.Split(core, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || !strings.Contains(strings.ToLower(l), "does not verify") &&
				!strings.Contains(strings.ToLower(l), "should not exist") &&
				!strings.Contains(strings.ToLower(l), "doesn't verify") {
				continue
			}
			// Managed hosts legitimately add platform files to the core tree.
			if strings.Contains(l, "wp-salt.php") || strings.Contains(l, "wp-config.php") {
				continue
			}
			a.emit(model.Finding{
				RuleID:      "wp.core_integrity",
				Class:       "WP",
				Severity:    model.SevHigh,
				Confidence:  model.ConfLikely,
				Title:       "WordPress core file fails checksum verification",
				Detail:      truncate(l, 300),
				Remediation: "Reinstall core: wp core download --force --version=<installed version>",
			})
		}
		plug := run("plugin", "verify-checksums", "--all")
		for _, line := range strings.Split(plug, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.Contains(strings.ToLower(l), "verified") ||
				strings.HasPrefix(strings.ToLower(l), "success") || strings.HasPrefix(l, "Warning:") {
				continue
			}
			if !strings.Contains(strings.ToLower(l), "checksum") && !strings.Contains(l, "File ") {
				continue
			}
			a.emit(model.Finding{
				RuleID:      "wp.plugin_integrity",
				Class:       "WP",
				Severity:    model.SevHigh,
				Confidence:  model.ConfLikely,
				Title:       "Plugin file fails checksum verification",
				Detail:      truncate(l, 300),
				Remediation: "Reinstall the plugin from the official package.",
			})
		}
		return model.CheckOK, ""
	})
}

// searchConsoleQuery builds the ownership-token query.
//
// Extracted so its shape can be asserted in a test: the previous version
// matched any option whose name contained "verif", which is a much larger
// set than it looks.
func searchConsoleQuery(prefix string) string {
	return fmt.Sprintf(`SELECT option_name, LEFT(option_value, 300) FROM %soptions
	                  WHERE (option_name LIKE '%%site_verif%%' OR option_name LIKE '%%webmaster%%'
	                      OR option_name LIKE '%%_gsc_%%'
	                      OR option_name LIKE '%%search_console%%'
	                      OR option_value LIKE '%%google-site-verification%%'
	                      OR option_value LIKE '%%msvalidate.01%%'
	                      OR option_value LIKE '%%yandex-verification%%'
	                      OR option_value LIKE '%%p:domain_verify%%'
	                      OR option_value LIKE '%%facebook-domain-verification%%')
	                    AND option_value != '' AND option_value != 'a:0:{}'
	                  LIMIT 40`, prefix)
}
