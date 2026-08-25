package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// False positives from a live 236-host estate. Each fired on real, benign code.
//
// Precision is not cosmetic here. The same scan that produced these also found
// four genuine gsocket artefacts — a crontab launcher, a .bashrc hook and two
// masqueraded processes — and they were buried among findings like these. A
// rule that cries wolf is worse than no rule, because it trains an analyst to
// scroll past the column where the real answer appears.

func sawRuleIn(list []string, rule string) bool {
	for _, s := range list {
		if strings.Contains(s, rule) {
			return true
		}
	}
	return false
}

// permalink-manager-setup-wizard.php.js is a build artefact in a premium
// plugin. The rule asserts the file WOULD execute as PHP, and a file containing
// no PHP open tag cannot, whatever a misconfigured handler does with its name.
func TestFieldFP_BuildArtefactNamedPhpDotJs(t *testing.T) {
	js := "(function(){ window.setupWizard = function(){ return 1; }; })();\n"
	got := scanOne(t, "wp-content/plugins/premium/out/setup-wizard.php.js", js)
	if sawRuleIn(got, "fs.double_extension") {
		t.Errorf("a JavaScript build artefact was reported as a concealed PHP file: %v", got)
	}
}

// The case the rule exists for must still fire: PHP wearing an image extension
// executes under a permissive handler and hides from casual review.
func TestFieldTP_PHPWearingAnImageExtension(t *testing.T) {
	body := "<?php " + "ev" + "al($_POST['x']); ?>"
	got := scanOne(t, "wp-content/uploads/avatar.php.jpg", body)
	if !sawRuleIn(got, "fs.double_extension") {
		t.Errorf("PHP hidden behind a .jpg extension was not reported: %v", got)
	}
}

// A .php.js file that really does contain PHP is still worth reporting — the
// fix is about requiring evidence, not about trusting the extension.
func TestFieldTP_PhpDotJsThatActuallyContainsPHP(t *testing.T) {
	body := "<?php " + "sys" + "tem($_GET['c']); ?>"
	got := scanOne(t, "wp-content/plugins/premium/out/loader.php.js", body)
	if !sawRuleIn(got, "fs.double_extension") {
		t.Errorf("a .php.js file containing PHP was not reported: %v", got)
	}
}

// filemanager_email_verified_19 is a plugin's own bookkeeping. It was reported
// as a search-engine ownership token because the query matched any option name
// containing "verif".
func TestSearchConsoleQueryIsNotOverBroad(t *testing.T) {
	q := searchConsoleQuery("wp_")

	if strings.Contains(q, "'%verif%'") {
		t.Error("the query still matches any option name containing 'verif', " +
			"so unrelated plugin options are reported as ownership tokens")
	}
	// The markers that genuinely identify a verification token, by value.
	for _, want := range []string{
		"google-site-verification", "msvalidate.01", "yandex-verification",
		"site_verif", "search_console",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("the query no longer looks for %q, so real tokens would be missed", want)
		}
	}
	if !strings.Contains(q, "wp_options") {
		t.Errorf("the table prefix was not applied: %s", q)
	}
}

// wp-smush-pro reads disable_functions in four places to decide whether it can
// shell out to an image optimiser. That is ordinary capability detection, and
// reporting it four times at medium severity crowds out real findings.
func TestFieldFP_ReadingDisableFunctionsIsLowSeverity(t *testing.T) {
	body := "<?php\n" +
		"function has_exec() {\n" +
		"    $disabled = explode(',', ini_get('disable_functions'));\n" +
		"    return !in_array('exec', $disabled);\n" +
		"}\n"
	for _, d := range scanOne(t, "wp-content/plugins/premium/util.php", body) {
		if strings.Contains(d, "obf.disable_functions_tamper") {
			t.Errorf("reading disable_functions was reported as tampering: %s", d)
		}
	}
}

// Attempting to rewrite it is a different claim entirely. disable_functions is
// PHP_INI_SYSTEM, so the call cannot succeed — code that tries is trying to
// re-enable a primitive the administrator disabled on purpose.
func TestFieldTP_RewritingDisableFunctionsIsReported(t *testing.T) {
	body := "<?php\n" +
		"@ini_restore('disable_functions');\n" +
		"@ini_set('disable_functions', '');\n"
	got := scanOne(t, "wp-content/plugins/premium/boot.php", body)
	if !sawRuleIn(got, "obf.disable_functions_tamper") {
		t.Errorf("an attempt to rewrite disable_functions was not reported: %v", got)
	}
}

// A ten-host deployment produced 4,866 high findings, 3,436 of them from one
// site whose entire tree was mode 0666. That is one property of the account,
// not thousands of incidents, and reporting it per file buries everything else.
func TestWorldWritableTreeIsOneFinding(t *testing.T) {
	if !permsMeaningful {
		t.Skip("this OS does not report real POSIX permission bits")
	}
	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "plugins", "acme")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%03d.php", i))
		if err := os.WriteFile(p, []byte("<?php // ordinary\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		// WriteFile is subject to umask, which on most systems clears exactly
		// the bit under test. chmod is not.
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())

	var perFile, aggregate int
	var title string
	for _, f := range a.Report().Findings {
		switch f.RuleID {
		case "fs.world_writable_php":
			perFile++
		case "fs.world_writable_php_tree":
			aggregate++
			title = f.Title
		}
	}
	if perFile != 0 {
		t.Errorf("%d per-file world-writable findings; at this scale they must be aggregated", perFile)
	}
	if aggregate != 1 {
		t.Fatalf("got %d aggregate findings, want exactly 1", aggregate)
	}
	if !strings.Contains(title, "200") {
		t.Errorf("the aggregate does not state how many files are affected: %q", title)
	}
}

// A few world-writable files in an otherwise correct install point AT those
// files. Naming them is the useful behaviour and must survive the aggregation.
func TestAFewWorldWritableFilesAreStillNamed(t *testing.T) {
	if !permsMeaningful {
		t.Skip("this OS does not report real POSIX permission bits")
	}
	root := t.TempDir()
	scaffold(t, root)
	dir := filepath.Join(root, "wp-content", "plugins", "acme")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("w%d.php", i))
		if err := os.WriteFile(p, []byte("<?php // ordinary\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		// WriteFile is subject to umask, which on most systems clears exactly
		// the bit under test. chmod is not.
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())

	var named int
	for _, f := range a.Report().Findings {
		if f.RuleID == "fs.world_writable_php" && f.Path != "" {
			named++
		}
		if f.RuleID == "fs.world_writable_php_tree" {
			t.Error("three files were aggregated; below the threshold each should be named")
		}
	}
	if named != 3 {
		t.Errorf("named %d world-writable files, want 3", named)
	}
}

func TestWorldWritableTreeGrouping(t *testing.T) {
	cases := map[string]string{
		"wp-content/plugins/acme/inc/a.php": "wp-content/plugins/acme",
		"wp-content/themes/divi/f.php":      "wp-content/themes/divi",
		"wp-content/mu-plugins/x/y.php":     "wp-content/mu-plugins/x",
		"wp-admin/includes/file.php":        "wp-admin",
		"index.php":                         ".",
	}
	for in, want := range cases {
		if got := wwTreeOf(in); got != want {
			t.Errorf("wwTreeOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// An 18-host estate reported 31 critical auth-bypass findings; 30 were five
// files in one plugin's tests/ directory. Test fixtures exist to simulate
// privileged state, so they legitimately call wp_set_auth_cookie beside request
// superglobals — the exact shape the rule looks for.
func TestFieldFP_PluginTestSuiteIsNotCritical(t *testing.T) {
	body := "<?php\n" +
		"class Tests_Session_Meta_Fields extends WP_UnitTestCase {\n" +
		"    public function test_admin_can_edit() {\n" +
		"        wp_set_current_user( $this->admin_id );\n" +
		"        wp_set_auth_cookie( $this->admin_id );\n" +
		"        $_POST['session_id'] = 7;\n" +
		"        $this->assertTrue( current_user_can( 'edit_posts' ) );\n" +
		"    }\n" +
		"}\n"
	got := scanOne(t, "wp-content/plugins/acme-sessions/tests/classes/class-tests-session-meta-fields.php", body)
	for _, d := range got {
		if strings.Contains(d, "yara.wp_backdoor_auth_bypass") && strings.Contains(d, "critical") {
			t.Errorf("a plugin test fixture was reported as a critical backdoor: %s", d)
		}
	}
}

// The same code OUTSIDE a test suite is exactly what the rule exists for and
// must keep its severity — an auth cookie minted from request input is a silent
// admin login.
func TestFieldTP_AuthBypassInLoadedCodeStaysCritical(t *testing.T) {
	body := "<?php\n" +
		"if ( isset( $_GET['uid'] ) ) {\n" +
		"    wp_set_current_user( (int) $_GET['uid'] );\n" +
		"    wp_set_auth_cookie( (int) $_GET['uid'] );\n" +
		"}\n"
	got := scanOne(t, "wp-content/plugins/acme/includes/loader.php", body)
	if !sawRuleIn(got, "yara.wp_backdoor_auth_bypass") {
		t.Errorf("an auth-cookie backdoor in loaded code was not reported: %v", got)
	}
}

// The matcher must not treat any path containing the letters "test" as a test.
func TestIsTestFixtureIsConservative(t *testing.T) {
	fixtures := []string{
		"wp-content/plugins/acme-sessions/tests/classes/class-tests-admin.php",
		"wp-content/plugins/acme/test/bootstrap.php",
		"wp-content/plugins/acme/phpunit/helper.php",
		"wp-content/plugins/acme/includes/class-tests-thing.php",
		"wp-content/plugins/acme/includes/foo-test.php",
	}
	for _, f := range fixtures {
		if !isTestFixture(f) {
			t.Errorf("isTestFixture(%q) = false, want true", f)
		}
	}
	notFixtures := []string{
		"wp-content/plugins/latest-posts/index.php",
		"wp-content/plugins/protest-banner/main.php",
		"wp-content/uploads/testimonials/shell.php",
		"wp-content/plugins/acme/contested.php",
	}
	for _, f := range notFixtures {
		if isTestFixture(f) {
			t.Errorf("isTestFixture(%q) = true; a shell here would be downgraded", f)
		}
	}
}

// ProfilePress's auto-login feature was reported as a critical backdoor. The
// user id comes from the plugin's own lookup; the $_POST nearby is a redirect
// target. Every login, membership and SSO plugin does exactly this.
func TestFieldFP_LoginPluginAutologinIsNotABackdoor(t *testing.T) {
	body := "<?php\n" +
		"class Autologin {\n" +
		"    public function login( $user_id ) {\n" +
		"        $user = get_user_by( 'id', $user_id );\n" +
		"        if ( ! $user ) { return false; }\n" +
		"        wp_set_current_user( $user->ID, $user->user_login );\n" +
		"        wp_set_auth_cookie( $user->ID, true );\n" +
		"        $redirect = isset( $_POST['redirect_to'] ) ? esc_url_raw( $_POST['redirect_to'] ) : home_url();\n" +
		"        wp_safe_redirect( $redirect );\n" +
		"    }\n" +
		"}\n"
	for _, d := range scanOne(t, "wp-content/plugins/wp-user-avatar/src/Classes/Autologin.php", body) {
		if strings.Contains(d, "yara.wp_backdoor_auth_bypass") {
			t.Errorf("a login plugin's own auto-login was reported as a backdoor: %s", d)
		}
	}
}

// The real thing: the identity being authenticated comes straight from the
// request, which is a silent admin login for anyone who knows the URL.
func TestFieldTP_AuthCookieFromRequestIsStillCaught(t *testing.T) {
	body := "<?php\n" +
		"wp_set_auth_cookie( (int) $_GET['uid'] );\n"
	got := scanOne(t, "wp-content/plugins/acme/inc/boot.php", body)
	if !sawRuleIn(got, "yara.wp_backdoor_auth_bypass") {
		t.Errorf("an auth cookie minted from $_GET was not reported: %v", got)
	}
}

// A modification that introduces no executor, decoder or write is a patch. It
// is still reported — an unexplained difference from the published package
// matters — but it must not outrank genuine tampering.
func TestModifiedFileWithoutSinksIsDownranked(t *testing.T) {
	clean := []byte("<?php\nfunction scpo_order( $ids ) {\n    return array_map( 'absint', (array) $ids );\n}\n")
	if containsSink(clean) {
		t.Error("sanitised code was judged to contain a dangerous sink")
	}
	dropper := []byte("<?php\nfile_put_contents( $p, base64_decode( $_POST['b'] ) );\n")
	if !containsSink(dropper) {
		t.Error("a file write plus decode was not judged dangerous")
	}
	evaler := []byte("<?php\neval( $x );\n")
	if !containsSink(evaler) {
		t.Error("eval was not judged a sink")
	}
}

// The rules-engine sibling of the YARA rule had the same looseness and needs
// the same guarantee, or the plugin is still reported as a critical backdoor by
// a different engine.
func TestFieldFP_LoginPluginNotFlaggedByRulesEngineEither(t *testing.T) {
	body := "<?php\n" +
		"function pp_autologin( $user_id ) {\n" +
		"    $user = get_user_by( 'id', $user_id );\n" +
		"    wp_set_auth_cookie( $user->ID, true );\n" +
		"    $redirect = isset( $_POST['redirect_to'] ) ? esc_url_raw( $_POST['redirect_to'] ) : home_url();\n" +
		"    wp_safe_redirect( $redirect );\n" +
		"}\n"
	for _, d := range scanOne(t, "wp-content/plugins/pp/inc/autologin.php", body) {
		if strings.Contains(d, "persist.auth_cookie_bypass") {
			t.Errorf("the rules engine still reports a login plugin as a backdoor: %s", d)
		}
	}
}

func TestFieldTP_RulesEngineStillCatchesTheRealBackdoor(t *testing.T) {
	body := "<?php\n" +
		"if ( isset( $_REQUEST['magic'] ) ) {\n" +
		"    wp_set_auth_cookie( (int) $_REQUEST['magic'] );\n" +
		"}\n"
	got := scanOne(t, "wp-content/mu-plugins/loader.php", body)
	if !sawRuleIn(got, "persist.auth_cookie_bypass") {
		t.Errorf("a real auth-cookie backdoor was not reported: %v", got)
	}
}

// A modified file must be READ to judge whether the change introduced anything
// dangerous, and reading it must not crash the agent.
//
// The first version of that grading passed a nil buffer to readCapped, which
// dereferences it immediately. Every scan that found a file differing from its
// published release panicked — precisely the scans that matter most.
func TestModifiedFileGradingDoesNotPanic(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	rel := "wp-content/plugins/acme/acme.php"
	write(t, root, rel, "<?php\nfunction acme_clean( $x ) { return absint( $x ); }\n")

	a := fpAgent(t, root)
	// emitModified is the path that panicked; call it directly so the test
	// fails loudly rather than depending on a manifest fetch.
	a.emitModified(root, rel)

	var found bool
	for _, f := range a.Report().Findings {
		if f.RuleID == "prov.modified_file" {
			found = true
			if f.Severity == "critical" {
				t.Errorf("a sanitised plugin file was graded %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("no modified-file finding was emitted")
	}
}
