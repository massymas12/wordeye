package agent

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// The evasion corpus.
//
// Every entry is the SAME web shell — request input reaching an execution
// primitive — written a different way. A signature scanner fails here because
// the bytes differ each time; a structural engine should not care.
//
// IMPORTANT, and learned the hard way: every payload below is assembled from
// FRAGMENTS at runtime, so this source file never contains a contiguous web
// shell on disk. Endpoint protection scans test fixtures too, and a quarantined
// test file fails in thoroughly confusing ways — the compiler reports a missing
// package rather than a missing file. The bytes are identical once assembled in
// memory, so detection coverage is unaffected.

var (
	kEval    = "ev" + "al"
	kAssert  = "ass" + "ert"
	kSystem  = "sys" + "tem"
	kPost    = "$_" + "POST"
	kGet     = "$_" + "GET"
	kReq     = "$_" + "REQUEST"
	kCookie  = "$_" + "COOKIE"
	kB64     = "base64_" + "decode"
	kInflate = "gz" + "inflate"
	open     = "<?" + "php"
)

func scoreFile(t *testing.T, rel, content string) *heurResult {
	t.Helper()
	root := t.TempDir()
	scaffold(t, root)
	write(t, root, rel, content)

	a := testAgent(t, root)
	hit := make([]bool, a.set.NumPatterns())
	sc := &heurScratch{}
	src := []byte(content)
	a.set.AC.MatchSet(src, hit)
	return a.analyzeHeuristic(src, hit, int64(len(src)), rel, sc)
}

// innerShell is the payload that gets packed: input reaching a sink.
func innerShell() string {
	return open + " if (isset(" + kPost + `["c"])) { ` + kEval + "(" + kPost + `["c"]); }`
}

func packB64(inner string) string {
	return fmt.Sprintf("%s\n$x = '%s';\n%s(%s($x));\n",
		open, base64.StdEncoding.EncodeToString([]byte(inner)), kEval, kB64)
}

// packDeflateB64 builds the gzinflate(base64_decode(...)) form, which is the
// most common packer seen in real WordPress compromises.
func packDeflateB64(t *testing.T, inner string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(inner)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return fmt.Sprintf("%s\n$p = '%s';\n%s(%s(%s($p)));\n",
		open, base64.StdEncoding.EncodeToString(buf.Bytes()), kEval, kInflate, kB64)
}

func TestEvasionCorpusIsDetected(t *testing.T) {
	// A tainted variable used far from its assignment: byte-proximity scoring
	// misses this entirely.
	distant := open + "\n$a = " + kPost + "['x'];\n" +
		strings.Repeat("$noise = strlen('padding padding padding');\n", 60) +
		kEval + "($a);\n"

	cases := []struct {
		name    string
		rel     string
		content string
	}{
		{
			"plain execution of request input",
			"wp-content/plugins/p/a.php",
			open + "\n" + kEval + "(" + kPost + "['c']);\n",
		},
		{
			"split literal defeats the signature",
			"wp-content/plugins/p/b.php",
			open + "\n$f = 'ev' . 'al';\n$f(" + kPost + "['c']);\n",
		},
		{
			"taint reaches the sink from far away",
			"wp-content/plugins/p/c.php",
			distant,
		},
		{
			"assignment chain launders the taint",
			"wp-content/plugins/p/d.php",
			open + "\n$a = " + kReq + "['q'];\n$b = $a;\n$c = $b;\n" + kAssert + "($c);\n",
		},
		{
			"dispatch straight through a superglobal",
			"wp-content/plugins/p/e.php",
			open + "\n" + kGet + "['fn'](" + kGet + "['arg']);\n",
		},
		{
			"variable-variable dispatch",
			"wp-content/plugins/p/f.php",
			open + "\n$v = 'zz';\n$$v = '" + kSystem + "';\n$zz(" + kPost + "['c']);\n",
		},
		{
			"base64-packed payload",
			"wp-content/plugins/p/g.php",
			packB64(innerShell()),
		},
		{
			"gzinflate+base64-packed payload",
			"wp-content/plugins/p/h.php",
			packDeflateB64(t, innerShell()),
		},
		{
			"anti-analysis preamble with an assembled primitive",
			"wp-content/plugins/p/i.php",
			open + "\nerror_reporting(0);\nset_time_limit(0);\nignore_user_abort(true);\n" +
				"$k = " + kCookie + "['s'];\n$h = 'as' . 'se' . 'rt';\n$h($k);\n",
		},
		{
			"fake plugin header does not buy absolution",
			"wp-content/plugins/p/j.php",
			open + "\n/**\n * Plugin Name: Totally Legitimate SEO\n * @package Legit\n * @since 1.0\n */\n" +
				"namespace Legit;\nadd_action('init', 'x');\nclass Helper { public function run() {} }\n" +
				"$a = " + kPost + "['c'];\n" + kEval + "($a);\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := scoreFile(t, tc.rel, tc.content)
			if h == nil {
				t.Fatalf("NOT DETECTED\n---\n%s\n---", tc.content)
			}
			t.Logf("score=%d severity=%s\n  %s", h.Score, h.Severity, strings.Join(h.Reasons, "\n  "))
			if h.Severity == "medium" {
				t.Errorf("only scored medium (%d) — a shell should reach high or critical", h.Score)
			}
		})
	}
}

// The other half of the job. A scanner that flags ordinary plugin code during an
// incident is worse than useless: it buries the real findings.
func TestBenignCorpusIsQuiet(t *testing.T) {
	// A maintainer's warning comment naming dangerous functions. Before the
	// lexer, this scored as though the calls were real.
	docComment := open + `
namespace Good;

/**
 * Security notes for maintainers.
 *
 * Never use ` + kEval + "(" + kPost + `['x']) or ` + kAssert + "(" + kGet + `['y']) here.
 * Calls such as shell_exec() and ` + kSystem + `() are forbidden by policy.
 *
 * @package Good
 * @since 2.1
 */
class Docs {
	public function render() { return __CLASS__; }
}
`

	escapedShell := open + `
namespace Good;
/** @package Good */
class Thumbs {
	public function convert($src, $dst) {
		@` + kSystem + `(sprintf('convert %s -resize 200x200 %s', escapeshellarg($src), escapeshellarg($dst)));
	}
}
`

	settingsPage := open + `
namespace Good;
/** @package Good */
add_action('admin_post_save', function () {
	check_admin_referer('good_save');
	$title = sanitize_text_field(` + kPost + `['title'] ?? '');
	$count = absint(` + kPost + `['count'] ?? 0);
	update_option('good_title', $title);
	update_option('good_count', $count);
	wp_safe_redirect(admin_url('options-general.php'));
});
`

	dataURI := open + "\n/** @package Theme */\nnamespace T;\nfunction logo() {\n  return '<img src=\"data:image/png;base64," +
		strings.Repeat("iVBORw0KGgoAAAANSUhEUg", 40) + "\">';\n}\n"

	cases := []struct{ name, rel, content string }{
		{"dangerous functions named only in a comment", "wp-content/plugins/p/doc.php", docComment},
		{"escaped shell call with no request input", "wp-content/plugins/p/thumb.php", escapedShell},
		{"settings page handling request input safely", "wp-content/plugins/p/settings.php", settingsPage},
		{"template embedding a long legitimate base64 data URI", "wp-content/themes/t/logo.php", dataURI},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := scoreFile(t, tc.rel, tc.content)
			if h != nil && h.Severity != "medium" {
				t.Errorf("FALSE POSITIVE at %s (score %d):\n  %s",
					h.Severity, h.Score, strings.Join(h.Reasons, "\n  "))
			}
			if h != nil {
				t.Logf("scored %d (%s) — acceptable only as review-grade", h.Score, h.Severity)
			}
		})
	}
}

// Decoding is the point: the operator should receive the payload, not the
// wrapper it arrived in.
func TestPackedPayloadIsDecodedAndSurfaced(t *testing.T) {
	h := scoreFile(t, "wp-content/plugins/p/packed.php", packDeflateB64(t, innerShell()))
	if h == nil {
		t.Fatal("packed shell not detected")
	}
	if len(h.Layers) == 0 {
		t.Fatal("payload was not decoded")
	}
	chain := summarizeLayers(h.Layers)
	if !strings.Contains(chain, "base64") || !strings.Contains(chain, kInflate) {
		t.Errorf("decode chain = %q, want base64 then gzinflate", chain)
	}
	found := false
	for _, l := range h.Layers {
		if bytes.Contains(l.Data, []byte(kPost)) && bytes.Contains(l.Data, []byte(kEval)) {
			found = true
		}
	}
	if !found {
		t.Error("decoded payload does not contain the inner shell")
	}
}

// A compression bomb must not be able to exhaust the agent on a live site.
func TestDecoderResistsCompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(bytes.Repeat([]byte("A"), 64<<20)) // 64MB compresses to almost nothing
	w.Close()
	src := []byte(fmt.Sprintf("%s\n$p='%s';\n%s(%s(%s($p)));\n",
		open, base64.StdEncoding.EncodeToString(buf.Bytes()), kEval, kInflate, kB64))

	view := lexPHP(src, nil)
	for _, l := range deobfuscate(src, view) {
		if len(l.Data) > maxDecodedSize {
			t.Errorf("decoded %d bytes, above the %d cap", len(l.Data), maxDecodedSize)
		}
	}
}

// The lexer is the foundation everything else stands on.
func TestLexerSeparatesCodeFromCommentsAndStrings(t *testing.T) {
	src := []byte(open + "\n// " + kEval + "(" + kPost + "['a']);\n/* " + kSystem +
		"('x'); */\n$s = 'shell_exec';\n$real = 1;\n")
	v := lexPHP(src, nil)
	code := string(v.code)

	for _, blanked := range []string{kEval, kSystem, "shell_exec"} {
		if strings.Contains(code, blanked) {
			t.Errorf("%q survived into the code view; comments/strings were not blanked", blanked)
		}
	}
	if !strings.Contains(code, "$real") {
		t.Error("real code was blanked out")
	}
	if len(v.code) != len(src) {
		t.Errorf("code view length %d != source %d — offsets would shift", len(v.code), len(src))
	}
	if strings.Count(code, "\n") != strings.Count(string(src), "\n") {
		t.Error("newlines were not preserved; line numbers would be wrong")
	}
}
