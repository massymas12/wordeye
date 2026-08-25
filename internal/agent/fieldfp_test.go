package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"wordeye/internal/govern"
)

// Regression corpus built from a real engagement.
//
// A scan of a live 66,975-file WordPress estate returned 173 findings, and
// every one that was inspected was a false positive: ACF Pro, Gravity Forms,
// Divi, wp-crontrol, simple-history, wordpress-importer — and, repeatedly,
// Wordfence's own source. Three defects produced them:
//
//  1. Rules matched raw bytes, so they fired inside comments and translation
//     strings ("Disable reading of php://input").
//  2. preg_replace was treated as an execution sink. Its /e modifier was
//     removed in PHP 7, so a bare preg_replace is ordinary string handling
//     present in nearly every large plugin.
//  3. Conditions required only co-occurrence, never proximity. In a 400KB file
//     any two tokens appear "together".
//
// Each case below reproduces one FP's shape from benign code, and is paired
// with the malicious shape it must still catch. A fix that silences the FP by
// blinding the detector fails the paired case.
//
// Payloads are assembled from fragments at runtime and never written
// contiguously, so endpoint protection does not quarantine the corpus.

func fpAgent(t *testing.T, root string) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "scan", Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 8 << 20,
		SkipDB: true, SkipOS: true, SkipNet: true, SkipProbe: true,
		SkipProvenance: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	// Tests create their fixtures now, so inside a container every one of them
	// post-dates the namespace start and trips the deploy-time heuristics. Those
	// are exercised by their own tests; clearing the environment here keeps this
	// helper focused on what it is actually asserting.
	a.env = nil
	return a
}

// scanOne writes a single file and returns a description of each finding
// reported against it. The description carries the rule id AND its stated
// reasons, because "which rule fired" is rarely enough to tell whether a
// finding is justified.
func scanOne(t *testing.T, rel, body string) []string {
	t.Helper()
	root := t.TempDir()
	scaffold(t, root)
	write(t, root, rel, body)

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())

	base := rel[strings.LastIndex(rel, "/")+1:]
	var out []string
	for _, f := range a.Report().Findings {
		if !strings.HasSuffix(filepath.ToSlash(f.Path), base) {
			continue
		}
		if f.Class == "PROV" || f.Severity == "info" {
			continue
		}
		d := f.RuleID
		if f.Detail != "" {
			d += " — " + strings.TrimSpace(f.Detail)
		}
		out = append(out, d)
	}
	return out
}

// filler pads a file so that terms which are "co-occurring" are genuinely far
// apart, reproducing the large-plugin condition that defeated the old rules.
func filler(n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString("// routine plugin logic, nothing of interest here.\n")
		b.WriteString("$out = array(); foreach ( $items as $k => $v ) { $out[$k] = $v; }\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Defect 1: matching inside comments and string literals
// ---------------------------------------------------------------------------

// Wordfence ships this exact translation string. It is a UI label.
func TestFieldFP_TranslationStringMentioningPHPInput(t *testing.T) {
	body := open + "\n" +
		"$fields = array(\n" +
		"  'avoid_input' => __( 'Disable reading of php://input', 'wordfence' ),\n" +
		");\n" +
		"function wf_render( $f ) { return esc_html( $f ); }\n"
	if got := scanOne(t, "wp-content/plugins/wordfence/lib/wfJavascriptBridge.php", body); len(got) > 0 {
		t.Errorf("translation string flagged: %v", got)
	}
}

// A docblock describing the technique, as in the Wordfence WAF's json.php.
func TestFieldFP_DocblockMentioningPHPInput(t *testing.T) {
	body := open + "\n" +
		"/**\n" +
		" * Decode a request body.\n" +
		" * $input = file_get_contents('php://input', 1000000);\n" +
		" * The value is then passed to " + kEval + "() by NOTHING; it is parsed.\n" +
		" */\n" +
		"function wf_json_decode( $s ) { return json_decode( $s, true ); }\n"
	if got := scanOne(t, "wp-content/plugins/wordfence/vendor/wf-waf/src/lib/json.php", body); len(got) > 0 {
		t.Errorf("docblock flagged: %v", got)
	}
}

// A line comment, as in wfUtils.php.
func TestFieldFP_LineCommentMentioningPHPInput(t *testing.T) {
	body := open + "\n" +
		"if ( $avoidPHPInput ) { //Some custom PHP builds break reading from php://input\n" +
		"    return $_SERVER['QUERY_STRING'];\n" +
		"}\n"
	if got := scanOne(t, "wp-content/plugins/wordfence/lib/wfUtils.php", body); len(got) > 0 {
		t.Errorf("line comment flagged: %v", got)
	}
}

// The paired true positive: php://input actually reaching an executor.
func TestFieldTP_PHPInputReachesExecutor(t *testing.T) {
	body := open + "\n" +
		"$d = file_get_contents('php://input');\n" +
		kEval + "($d);\n"
	got := scanOne(t, "wp-content/plugins/acme/handler.php", body)
	if len(got) == 0 {
		t.Fatal("real php://input -> executor was missed")
	}
	t.Logf("caught: %v", got)
}

// ---------------------------------------------------------------------------
// Defect 2: preg_replace treated as an execution sink
// ---------------------------------------------------------------------------

// The shape behind most of the field's YARA findings: a decoder and a
// preg_replace both present in a large file, and nothing else.
func TestFieldFP_DecoderAndBarePregReplace(t *testing.T) {
	body := open + "\n" +
		"$logo = " + kB64 + "( $this->get_asset( 'logo' ) );\n" +
		filler(6000) +
		"$slug = preg_replace( '/[^a-z0-9]+/', '-', strtolower( $title ) );\n" +
		filler(6000) +
		"$raw = gzdecode( $this->cache_blob );\n"
	if got := scanOne(t, "wp-content/plugins/wordfence/lib/wfConfig.php", body); len(got) > 0 {
		t.Errorf("decoder + bare preg_replace flagged: %v", got)
	}
}

// The legacy case must still fire: /e actually evaluated its replacement.
func TestFieldTP_PregReplaceEvalModifier(t *testing.T) {
	// The /e pattern is split so no runnable one-liner exists on disk.
	body := open + "\n" +
		"preg_replace( '/(.*)/" + "e', $repl, " + kPost + "['x'] );\n"
	got := scanOne(t, "wp-content/plugins/acme/legacy.php", body)
	if len(got) == 0 {
		t.Fatal("preg_replace /e modifier was missed")
	}
	t.Logf("caught: %v", got)
}

// ---------------------------------------------------------------------------
// Defect 3: co-occurrence without proximity
// ---------------------------------------------------------------------------

// wordpress-importer legitimately creates users from an admin-gated importer.
func TestFieldFP_AdminGatedUserImporter(t *testing.T) {
	body := open + "\n" +
		"function acme_import( $data ) {\n" +
		"    if ( ! current_user_can( 'create_users' ) ) { return; }\n" +
		"    check_admin_referer( 'import-users' );\n" +
		"    foreach ( $data as $i => $row ) {\n" +
		"        $user_id = wp_create_user( " + kPost + "['user_new'][ $i ], wp_generate_password() );\n" +
		"        $u = new WP_User( $user_id );\n" +
		"        $u->set_role( 'subscriber' );\n" +
		"    }\n" +
		"}\n" +
		filler(4000) +
		"// the word administrator appears in this help text far below.\n"
	if got := scanOne(t, "wp-content/plugins/wordpress-importer/class-wp-import.php", body); len(got) > 0 {
		t.Errorf("admin-gated importer flagged: %v", got)
	}
}

// Divi's SupportCenter creates a support account behind a capability check.
func TestFieldFP_CapabilityGatedSupportAccount(t *testing.T) {
	body := open + "\n" +
		"function et_support_user_create() {\n" +
		"    if ( ! current_user_can( 'manage_options' ) ) { return false; }\n" +
		"    $user_id = wp_insert_user( array(\n" +
		"        'user_login' => 'et_support',\n" +
		"        'role'       => 'administrator',\n" +
		"    ) );\n" +
		"    return $user_id;\n" +
		"}\n" +
		filler(3000) +
		"$nonce = isset( " + kPost + "['et_nonce'] ) ? " + kPost + "['et_nonce'] : '';\n"
	if got := scanOne(t, "wp-content/themes/Divi/core/components/SupportCenter.php", body); len(got) > 0 {
		t.Errorf("capability-gated support account flagged: %v", got)
	}
}

// The paired true positive: ungated, request-driven admin creation.
func TestFieldTP_RogueAdminCreator(t *testing.T) {
	body := open + "\n" +
		"if ( isset( " + kGet + "['add'] ) ) {\n" +
		"    $uid = wp_create_user( " + kGet + "['u'], " + kGet + "['p'] );\n" +
		"    $user = new WP_User( $uid );\n" +
		"    $user->set_role( 'administrator' );\n" +
		"}\n"
	got := scanOne(t, "wp-content/plugins/acme/inc/util.php", body)
	if len(got) == 0 {
		t.Fatal("rogue administrator creator was missed")
	}
	t.Logf("caught: %v", got)
}

// A large plugin with a superglobal and an executor thousands of bytes apart.
// This is the php_shell_input_to_exec shape that flagged Gravity Forms.
func TestFieldFP_DistantSuperglobalAndExecutor(t *testing.T) {
	// Faithful to the reported Gravity Forms finding: request superglobals,
	// urldecode/rawurldecode, base64_decode, a $GLOBALS access and input
	// sanitised through preg_replace — every one a normal thing for a large
	// forms plugin to do, and none of them near each other.
	body := open + "\n" +
		"$page = isset( " + kGet + "['page'] ) ? sanitize_key( " + kGet + "['page'] ) : '';\n" +
		"$value = preg_replace( '/[^a-zA-Z0-9_-]/', '', " + kPost + "['field'] );\n" +
		filler(5000) +
		"$decoded = urldecode( rawurldecode( $query ) );\n" +
		filler(5000) +
		"$asset = " + kB64 + "( $GLOBALS['gf_inline_assets'] );\n" +
		filler(5000) +
		"$ua = substr( $_SERVER['HTTP_USER_AGENT'], 0, 255 );\n"
	if got := scanOne(t, "wp-content/plugins/gravityforms/common.php", body); len(got) > 0 {
		t.Errorf("distant superglobal/executor flagged: %v", got)
	}
}

// A base64 helper class is not a loader. nextend's Base64/Decoder.php.
func TestFieldFP_Base64HelperClass(t *testing.T) {
	body := open + "\n" +
		"class Decoder {\n" +
		"    public static function decode( $s ) {\n" +
		"        return " + kB64 + "( strtr( $s, '-_', '+/' ) );\n" +
		"    }\n" +
		"    public static function inflate( $s ) { return gzinflate( $s ); }\n" +
		"}\n"
	if got := scanOne(t, "wp-content/plugins/nextend/Base64/Decoder.php", body); len(got) > 0 {
		t.Errorf("base64 helper class flagged: %v", got)
	}
}

// The paired true positive: decoder chained straight into the sink.
func TestFieldTP_DecoderChainedIntoSink(t *testing.T) {
	body := open + "\n" +
		kEval + "(gzinflate(" + kB64 + "($" + "payload)));\n"
	got := scanOne(t, "wp-content/plugins/acme/loader.php", body)
	if len(got) == 0 {
		t.Fatal("decoder chained into sink was missed")
	}
	t.Logf("caught: %v", got)
}

// ---------------------------------------------------------------------------
// Defect 5: a substring match that swallowed the platform's own API
// ---------------------------------------------------------------------------

// wp_mail() is the WordPress mail wrapper every well-behaved plugin uses. The
// substring "mail(" matches inside it, which flagged Gravity Forms, Divi's
// contact form, Wordfence and simple-history as spam relays.
func TestFieldFP_WpMailIsNotASpamRelay(t *testing.T) {
	body := open + "\n" +
		"function gf_send_notifications( $entry, $form ) {\n" +
		"    foreach ( $form['notifications'] as $n ) {\n" +
		"        $to = rgar( $n, 'to' );\n" +
		"        wp_mail( $to, $n['subject'], $n['message'] );\n" +
		"    }\n" +
		"}\n" +
		"$id = absint( " + kPost + "['form_id'] );\n"
	if got := scanOne(t, "wp-content/plugins/gravityforms/notification.php", body); len(got) > 0 {
		t.Errorf("wp_mail() in a loop flagged as a spam relay: %v", got)
	}
}

// The paired true positive: raw mail() looping over recipients from the request.
func TestFieldTP_SpamRelay(t *testing.T) {
	body := open + "\n" +
		"$list = explode( ',', " + kPost + "['to'] );\n" +
		"foreach ( $list as $addr ) {\n" +
		"    " + "mail" + "( $addr, " + kPost + "['subj'], " + kPost + "['body'] );\n" +
		"}\n"
	got := scanOne(t, "wp-content/uploads/m.php", body)
	if len(got) == 0 {
		t.Fatal("a raw mail() relay over request-supplied recipients was missed")
	}
	t.Logf("caught: %v", got)
}

// ---------------------------------------------------------------------------
// Defect 6: "double extension" firing on ordinary PHP naming
// ---------------------------------------------------------------------------

// name.inc.php is a routine PHP convention. It was flagged because "inc" is
// itself a PHP extension and appeared mid-filename — but the FINAL extension is
// .php, so the file is served as PHP because it IS PHP. Nothing is disguised.
func TestFieldFP_IncDotPhpIsNotADoubleExtension(t *testing.T) {
	body := open + "\nreturn array( 'prefix' => 'WPMUDEV' );\n"
	got := scanOne(t, "wp-content/plugins/wp-smush-pro/core/scoper.inc.php", body)
	for _, g := range got {
		if strings.Contains(g, "double_extension") {
			t.Errorf("scoper.inc.php flagged as a double extension: %v", got)
		}
	}
}

// The paired true positive: PHP followed by a non-PHP extension, which only
// executes under a misconfigured handler and is meant to look inert.
func TestFieldTP_PhpFollowedByImageExtension(t *testing.T) {
	got := scanOne(t, "wp-content/uploads/2026/07/avatar.php.jpg", open+"\n$x=1;\n")
	var found bool
	for _, g := range got {
		if strings.Contains(g, "double_extension") {
			found = true
		}
	}
	if !found {
		t.Fatalf("avatar.php.jpg was not flagged as a double extension: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Defect 4: a server-configuration rule firing on PHP source
// ---------------------------------------------------------------------------

// Wordfence's WAF bootstrap configures auto_prepend_file as its whole purpose.
func TestFieldFP_AutoPrependMentionedInPHP(t *testing.T) {
	body := open + "\n" +
		"$ini = 'auto_prepend_file';\n" +
		"if ( ini_get( $ini ) ) { wfWAF::bootstrap(); }\n" +
		"echo 'Set auto_prepend_file in your php.ini to enable the firewall.';\n"
	if got := scanOne(t, "wp-content/plugins/wordfence/waf/bootstrap.php", body); len(got) > 0 {
		t.Errorf("auto_prepend_file in PHP source flagged: %v", got)
	}
}

// The paired true positive: the directive in an actual handler config.
func TestFieldTP_AutoPrependInHtaccess(t *testing.T) {
	got := scanOne(t, "wp-content/uploads/.htaccess",
		"php_value auto_prepend_file /var/www/html/wp-content/uploads/.x.php\n")
	if len(got) == 0 {
		t.Fatal("auto_prepend_file in .htaccess was missed")
	}
	t.Logf("caught: %v", got)
}

// ---------------------------------------------------------------------------
// Whole-corpus guard
// ---------------------------------------------------------------------------

// Every benign fixture together must produce a clean report. Individual tests
// localise a regression; this one states the property the field run violated.
func TestFieldFP_CorpusIsClean(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)

	write(t, root, "wp-content/plugins/wordfence/lib/wfUtils.php", open+"\n"+
		"if ( $avoidPHPInput ) { //Some custom PHP builds break reading from php://input\n"+
		"    return '';\n}\n")
	write(t, root, "wp-content/plugins/wordfence/lib/wfConfig.php", open+"\n"+
		"$a = "+kB64+"( $x );\n"+filler(5000)+
		"$s = preg_replace( '/[^a-z]+/', '-', $t );\n")
	write(t, root, "wp-content/plugins/nextend/Base64/Decoder.php", open+"\n"+
		"class Decoder { static function d($s){ return "+kB64+"($s); } }\n")
	write(t, root, "wp-content/plugins/wordpress-importer/class-wp-import.php", open+"\n"+
		"if ( ! current_user_can( 'create_users' ) ) { return; }\n"+
		"$user_id = wp_create_user( "+kPost+"['user_new'][0], wp_generate_password() );\n")
	write(t, root, "wp-content/plugins/wordfence/waf/bootstrap.php", open+"\n"+
		"echo 'configure auto_prepend_file in php.ini';\n")
	write(t, root, "wp-content/plugins/gravityforms/common.php", open+"\n"+
		"$p = sanitize_key( "+kGet+"['page'] );\n"+filler(8000)+"return $p;\n")

	a := fpAgent(t, root)
	a.scanFilesystem(context.Background())

	var noisy []string
	for _, f := range a.Report().Findings {
		if f.Class == "PROV" || f.Severity == "info" {
			continue
		}
		noisy = append(noisy, string(f.Severity)+" "+f.RuleID+" "+f.Path)
	}
	if len(noisy) > 0 {
		t.Errorf("benign plugin corpus produced %d finding(s):\n  %s",
			len(noisy), strings.Join(noisy, "\n  "))
	}
}
