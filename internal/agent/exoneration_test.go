package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

// The field lesson, encoded.
//
// The first real run against a live site flagged a dozen stock WordPress core
// files as CRITICAL web shells — ajax-actions.php, user.php, file.php,
// class-pclzip.php — because core legitimately calls system(), mail() inside a
// loop, wp_insert_user() from request data, gzinflate and pack. The location
// weighting made it worse, since core directories were weighted UP.
//
// Threshold tuning cannot fix that: the primitives genuinely are there. Only
// authority can. A file identical to its published release cannot be a shell,
// so it must produce NOTHING regardless of how alarming it looks in isolation.

func TestVerifiedCoreFileIsExoneratedDespiteLookingMalicious(t *testing.T) {
	root := t.TempDir()
	version := open + "\n$wp_version = '6.5.2';\n"
	write(t, root, "wp-includes/version.php", version)

	// Built to light up every engine: request input reaching preg_replace, an
	// exec sink, a decoder, a file write, and mail() in a loop. A fair
	// caricature of what wp-admin/includes/file.php actually contains.
	scary := open + "\n" +
		"$p = " + kPost + "['x'];\n" +
		"preg_replace('/a/', $p, 'subject');\n" +
		"@" + kSystem + "(escapeshellarg($p));\n" +
		"$d = " + kB64 + "($p);\n" +
		"file_put_contents('/tmp/x.php', $d);\n" +
		"foreach ($rows as $r) { mail($r, 'subject', 'body'); }\n"
	write(t, root, "wp-admin/includes/file.php", scary)

	fetch := fakeManifests(map[string]string{
		"wp-includes/version.php":    md5hex([]byte(version)),
		"wp-admin/includes/file.php": md5hex([]byte(scary)),
	}, nil)

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	var noisy []string
	for _, f := range a.Report().Findings {
		if strings.HasSuffix(filepath.ToSlash(f.Path), "wp-admin/includes/file.php") {
			noisy = append(noisy, f.RuleID+"("+string(f.Severity)+")")
		}
	}
	if len(noisy) > 0 {
		t.Errorf("a file identical to its published release still produced findings: %v", noisy)
	}
	if a.provVerified.Load() == 0 {
		t.Error("expected the file to be counted as verified")
	}
}

// Exoneration must not become a blind spot. The SAME alarming content, when it
// does NOT match the manifest, has to be caught by every engine as before —
// otherwise an attacker need only modify a core file to gain immunity.
func TestTamperedCoreFileIsStillAnalysed(t *testing.T) {
	root := t.TempDir()
	version := open + "\n$wp_version = '6.5.2';\n"
	write(t, root, "wp-includes/version.php", version)

	scary := open + "\n$p = " + kPost + "['x'];\n" + kEval + "($p);\n"
	write(t, root, "wp-admin/includes/file.php", scary)

	fetch := fakeManifests(map[string]string{
		"wp-includes/version.php": md5hex([]byte(version)),
		// The manifest says this file should be something else entirely.
		"wp-admin/includes/file.php": md5hex([]byte(open + "\n// the real core file\n")),
	}, nil)

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	ids := findingIDs(a, "wp-admin/includes/file.php")
	if !hasRule(ids, "prov.modified_file") {
		t.Errorf("tampering not reported (got %v)", ids)
	}
	sawContent := false
	for _, id := range ids {
		if strings.HasPrefix(id, "fs.") || strings.HasPrefix(id, "shell.") || strings.HasPrefix(id, "yara.") {
			sawContent = true
		}
	}
	if !sawContent {
		t.Errorf("a tampered file skipped content analysis (got %v)", ids)
	}
}

// An undeployed file gets the full treatment too: provenance reports it, and
// the content engines still characterise what it actually is.
func TestUnexpectedFileIsAlsoAnalysed(t *testing.T) {
	root := t.TempDir()
	version := open + "\n$wp_version = '6.5.2';\n"
	write(t, root, "wp-includes/version.php", version)

	shell := open + "\n" + kEval + "(" + kPost + "['c']);\n"
	write(t, root, "wp-includes/wp-cache-helper.php", shell)

	fetch := fakeManifests(map[string]string{
		"wp-includes/version.php": md5hex([]byte(version)),
	}, nil)

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	ids := findingIDs(a, "wp-includes/wp-cache-helper.php")
	if !hasRule(ids, "prov.unexpected_file") {
		t.Errorf("undeployed file not reported by provenance (got %v)", ids)
	}
	sawContent := false
	for _, id := range ids {
		if strings.HasPrefix(id, "shell.") || strings.HasPrefix(id, "fs.") || strings.HasPrefix(id, "yara.") {
			sawContent = true
		}
	}
	if !sawContent {
		t.Errorf("an undeployed file skipped content analysis (got %v)", ids)
	}
}
