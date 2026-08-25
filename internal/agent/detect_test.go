package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wordeye/internal/govern"
	"wordeye/internal/model"
)

// Detection regression tests.
//
// Deliberately, none of these fixtures is a working web shell. Each one is the
// minimum structure needed to exercise a specific detector — the payload a real
// shell would carry is replaced with an inert statement. Two reasons:
//
//  1. The detectors key on structure (an asset extension holding PHP, input
//     reaching an execution sink, a decoder chained into an executor), so a
//     functional payload adds no test coverage whatsoever.
//  2. Writing canonical malware one-liners onto a working machine trips the
//     host's own endpoint protection, which quarantines the fixture mid-test
//     and silently invalidates the result.

func testAgent(t *testing.T, root string) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode:        "scan",
		Webroot:     root,
		Home:        root,
		Packs:       []string{"core"},
		Gov:         gcfg,
		MaxFileSize: 4 << 20,
		SkipDB:      true,
		SkipOS:      true,
		SkipNet:     true,
		SkipProbe:   true,
		// Provenance reaches api.wordpress.org; the dedicated tests inject a
		// fetcher instead so the suite never depends on the network.
		SkipProvenance: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	// Inside a container every fixture this test writes post-dates the
	// namespace start, so the deploy-time heuristics fire on all of them. That
	// is correct behaviour reported against an artificial situation: the files
	// really were written after the container booted. Those heuristics have
	// their own tests; clearing the environment keeps this helper focused on
	// what it is asserting.
	//
	// It surfaced as a flaky failure under -race, where the slower build pushed
	// fixture writes further past container start. A suite that fails
	// intermittently is worse than one that fails always, because the deploy
	// gate now depends on it.
	a.env = nil
	return a
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeBytes(t *testing.T, root, rel string, b []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// scaffold lays down the minimum that makes a directory look like WordPress.
func scaffold(t *testing.T, root string) {
	t.Helper()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
	write(t, root, "index.php", "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n")
}

// findingsFor returns the rule IDs reported against a path.
func findingsFor(r *model.Report, pathSuffix string) []string {
	var out []string
	for _, f := range r.Findings {
		if strings.HasSuffix(filepath.ToSlash(f.Path), pathSuffix) {
			out = append(out, f.RuleID)
		}
	}
	return out
}

func hasRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestDetectors(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)

	// --- structural shells, inert payloads --------------------------------

	// Dispatching a call through a request superglobal. No legitimate code
	// does this; the argument is irrelevant to the detection.
	write(t, root, "wp-content/plugins/p/lib/util.php",
		"<?php\n$_GET['fn']($_GET['arg']);\n")

	// A decoder chained into an executor. gzinflate rather than the canonical
	// base64 form: same rule, same code path, not a fingerprinted sample.
	write(t, root, "wp-content/plugins/p/inc/opt.php",
		"<?php\n$z = 'x';\neval( gzinflate( $z ) );\n")

	// eval() reached from a request-controlled key.
	write(t, root, "wp-content/plugins/p/inc/legacy.php",
		"<?php\n$password = 'k';\nif ( isset( $_REQUEST[$password] ) ) { eval( $_REQUEST[$password] ); }\n")

	// PHP wearing an asset extension, with no valid file-format header.
	write(t, root, "wp-content/themes/th/assets/css/theme.css",
		"<?php\necho 'inert';\n")

	// Polyglot: genuine PNG magic bytes followed by PHP. This is what defeats
	// an upload filter that validates magic bytes only. The PHP body is inert —
	// the detector fires on the combination, not the payload.
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, 'I', 'H', 'D', 'R'}
	writeBytes(t, root, "wp-content/uploads/2026/08/img.png",
		append(png, []byte("\n<?php echo 'inert';\n")...))

	// Executable PHP inside the uploads tree.
	write(t, root, "wp-content/uploads/2026/08/note.php", "<?php\necho 'inert';\n")

	// Handler remap: makes non-PHP files execute.
	write(t, root, "wp-content/uploads/.htaccess", "AddType application/x-httpd-php .png\n")

	// Prepend loader: injects a file into every request.
	write(t, root, "wp-content/plugins/p/.user.ini", "auto_prepend_file=/tmp/.c.php\n")

	// Drop-in that loads before every plugin, including any security plugin.
	write(t, root, "wp-content/db.php",
		"<?php\nif ( isset( $_COOKIE['k'] ) ) { eval( gzinflate( $_COOKIE['k'] ) ); }\n")

	// Must-use plugin: auto-loaded, hidden from the Plugins screen.
	write(t, root, "wp-content/mu-plugins/loader.php",
		"<?php\nassert( gzinflate( $_REQUEST['q'] ) );\n")

	// --- false-positive controls ------------------------------------------
	write(t, root, "wp-content/plugins/p/inc/render.php", `<?php
namespace P;
class Render {
	public function html( $atts ) {
		return sprintf( '<div>%s</div>', esc_html( $atts['title'] ?? '' ) );
	}
}
`)
	// Legitimate use of a "dangerous" function: escaped, no request input.
	write(t, root, "wp-content/plugins/p/inc/thumb.php", `<?php
function p_convert( $src, $dst ) {
	@system( sprintf( 'convert %s -resize 200x200 %s', escapeshellarg( $src ), escapeshellarg( $dst ) ) );
}
`)

	a := testAgent(t, root)
	rep, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	cases := []struct {
		path string
		want string
	}{
		{"lib/util.php", "shell.superglobal_call"},
		{"inc/opt.php", "shell.eval_obfuscated"},
		{"inc/legacy.php", "shell.eval_request_var"},
		{"assets/css/theme.css", "fs.fake_extension_shell"},
		{"uploads/2026/08/img.png", "fs.polyglot_file"},
		{"uploads/2026/08/note.php", "place.php_in_uploads"},
		{"uploads/.htaccess", "wp.htaccess_php_handler"},
		{"plugins/p/.user.ini", "wp.user_ini_prepend"},
		{"wp-content/db.php", "wp.dropin_trojanized"},
		{"mu-plugins/loader.php", "wp.muplugin_suspicious"},
	}
	for _, c := range cases {
		got := findingsFor(rep, c.path)
		if !hasRule(got, c.want) {
			t.Errorf("%s: missing %s (got %v)", c.path, c.want, got)
		}
	}

	// Clean files must stay clean. A scanner that flags ordinary plugin code
	// is worse than useless during an incident: it buries the real findings.
	for _, clean := range []string{"inc/render.php", "inc/thumb.php"} {
		if got := findingsFor(rep, clean); len(got) > 0 {
			t.Errorf("false positive on %s: %v", clean, got)
		}
	}

	if rep.Verdict != "dirty" {
		t.Errorf("verdict = %q, want dirty", rep.Verdict)
	}

	// The YARA engine must be live and firing through the same scan pipeline.
	yaraHits := 0
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.RuleID, "yara.") {
			yaraHits++
			// YARA matches are pattern matches, not proofs; they must never be
			// eligible for automated quarantine.
			if f.Confidence == model.ConfConfirmed || f.Actionable {
				t.Errorf("%s was marked confirmed/actionable", f.RuleID)
			}
		}
	}
	if yaraHits == 0 {
		t.Error("no YARA rule fired against the fixture set")
	}

	// Rule packs must be attributed in the report, including YARA.
	var sawYaraPack bool
	for _, p := range rep.RulePacks {
		if p.Name == "yara" && p.Rules > 0 {
			sawYaraPack = true
		}
	}
	if !sawYaraPack {
		t.Error("YARA ruleset missing from report.rule_packs")
	}
}

// TestHeuristicCatchesUnsignedShell is the important one. Nothing here matches
// any signature in any pack: the execution primitive is assembled at runtime
// from fragments, so no literal function name appears in the source. Only the
// structural engine can find it, which is exactly the class of repacked shell
// that signature-driven scanners miss.
func TestHeuristicCatchesUnsignedShell(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)

	// A long, high-entropy encoded blob, as a packer would emit.
	blob := strings.Repeat("QWxwaGFCZXRhR2FtbWFEZWx0YUVwc2lsb25aZXRhRXRhVGhldGFJb3RhS2FwcGE", 40)

	write(t, root, "wp-content/plugins/p/inc/cache-handler.php", `<?php
error_reporting(0);
set_time_limit(0);
ignore_user_abort(true);
$k = $_COOKIE['sid'];
$raw = '`+blob+`';
$p = gzinflate( base64_decode( $raw ) );
$q = str_rot13( $k );
$h = 'as' . 'se' . 'rt';
$h( $p );
`)

	a := testAgent(t, root)
	rep, err := a.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	ids := findingsFor(rep, "inc/cache-handler.php")
	if !hasRule(ids, "fs.heuristic_webshell") {
		t.Fatalf("heuristic engine missed an unsigned shell (got %v)", ids)
	}

	// It must also be reported as heuristic-grade, never as confirmed: only
	// confirmed findings are eligible for automated action, and no score should
	// be able to authorise deleting a customer's file.
	for _, f := range rep.Findings {
		if f.RuleID == "fs.heuristic_webshell" {
			if f.Confidence == model.ConfConfirmed {
				t.Error("heuristic finding claimed confirmed confidence")
			}
			if f.Actionable {
				t.Error("heuristic finding was marked auto-actionable")
			}
		}
	}
}

// TestBaselineDetectsDrift covers the tripwire path: a baseline taken on a
// clean state must surface a file added afterwards, regardless of content.
func TestBaselineDetectsDrift(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	write(t, root, "wp-content/plugins/p/main.php", "<?php\necho 'ok';\n")

	basePath := filepath.Join(t.TempDir(), "baseline.txt")

	mk := func(mode string) *model.Report {
		gcfg := govern.ForProfile(govern.ProfileFast)
		gcfg.Deadline = 0
		a, err := New(Config{
			Mode: mode, Webroot: root, Home: root,
			Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
			BaselinePath: basePath,
			SkipDB:       true, SkipOS: true, SkipNet: true, SkipProbe: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		a.env = nil // see testAgent: container-start heuristics fire on fresh fixtures
		rep, err := a.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}

	mk("baseline")

	// An attacker adds a file with entirely benign-looking content: no
	// signature, no heuristic score. Drift is the only thing that finds it.
	write(t, root, "wp-content/plugins/p/helper.php", "<?php\nreturn 1;\n")

	rep := mk("verify")
	if ids := findingsFor(rep, "plugins/p/helper.php"); !hasRule(ids, "baseline.new_file") {
		t.Errorf("drift check missed a newly added file (got %v)", ids)
	}
}

// TestConfidenceGate locks in the invariant that keeps remediation safe.
func TestConfidenceGate(t *testing.T) {
	r := &model.Report{}
	r.AddFinding(model.Finding{
		RuleID: "x.y", Confidence: model.ConfLikely, Actionable: true,
	})
	if r.Findings[0].Actionable {
		t.Fatal("a non-confirmed finding was allowed to remain auto-actionable")
	}
}
