package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wordeye/internal/govern"
)

// Quick-mode scoping.
//
// Two field runs failed to converge because the sweep walked far past the PHP
// corpus. These tests pin down exactly what --quick does and does not touch, so
// the answer stops being a matter of opinion.

func scopeAgent(t *testing.T, root string, quick bool) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "scan", Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		Quick:  quick,
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

// buildBulkyTree makes a webroot shaped like a real site: a modest amount of
// code, and a great deal of everything else.
func buildBulkyTree(t *testing.T, root string) {
	t.Helper()
	scaffold(t, root)

	// Code, which must be analysed.
	for i := 0; i < 20; i++ {
		write(t, root, filepath.ToSlash(filepath.Join("wp-content/plugins/p/inc",
			"mod"+string(rune('a'+i%26))+".php")), open+"\nreturn 1;\n")
	}
	// Media under uploads, which must not be walked at all in quick mode.
	big := strings.Repeat("x", 64<<10)
	for i := 0; i < 40; i++ {
		write(t, root, filepath.ToSlash(filepath.Join("wp-content/uploads/2026/08",
			"img"+string(rune('a'+i%26))+string(rune('a'+i/26))+".jpg")), big)
	}
	// Bulky non-executable files INSIDE a walked tree — minified JS, CSS, maps,
	// language files. This is the category the directory-level skip never
	// caught, and it is where the file count and the bytes actually came from.
	for i := 0; i < 40; i++ {
		suffix := string(rune('a'+i%26)) + string(rune('a'+i/26))
		write(t, root, "wp-content/plugins/p/assets/bundle"+suffix+".js", big)
		write(t, root, "wp-content/plugins/p/assets/style"+suffix+".css", big)
		write(t, root, "wp-content/plugins/p/assets/map"+suffix+".map", big)
	}
	write(t, root, "wp-content/languages/plugin-en_GB.po", big)
}

func TestQuickModeExcludesUploads(t *testing.T) {
	root := t.TempDir()
	buildBulkyTree(t, root)

	// Count what is actually on disk, and what lives in the excluded trees, so
	// the assertion measures the difference rather than guessing at a number.
	var total, excluded int
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		total++
		rel := filepath.ToSlash(strings.TrimPrefix(p, root))
		if strings.Contains(rel, "/uploads/") || strings.Contains(rel, "/languages/") {
			excluded++
		}
		return nil
	})

	quick := scopeAgent(t, root, true)
	quick.scanFilesystem(context.Background())
	qSeen, _, _ := quick.Progress()

	full := scopeAgent(t, root, false)
	full.scanFilesystem(context.Background())
	fSeen, _, _ := full.Progress()

	t.Logf("on disk %d (%d in excluded trees); quick saw %d, full saw %d",
		total, excluded, qSeen, fSeen)

	if quick.rep.Stats.DirsSkipped == 0 {
		t.Error("quick mode skipped no directories at all")
	}
	if int(fSeen) != total {
		t.Errorf("a full scan saw %d of %d files", fSeen, total)
	}
	// The whole excluded set, and nothing else, must be missing from the quick run.
	if int(qSeen) != total-excluded {
		t.Errorf("quick saw %d files, expected %d (%d on disk minus %d excluded)",
			qSeen, total-excluded, total, excluded)
	}
}

// The regression that actually mattered: bulky non-executable files sitting
// INSIDE trees that are legitimately walked. The directory skip never touched
// these, so every minified bundle was read in full and analysed.
func TestQuickModeHeaderProbesNonExecutableFiles(t *testing.T) {
	root := t.TempDir()
	buildBulkyTree(t, root)

	quick := scopeAgent(t, root, true)
	quick.scanFilesystem(context.Background())
	qBytes := quick.rep.Stats.BytesRead
	qSkipped := quick.rep.Stats.FilesSkippedByType

	full := scopeAgent(t, root, false)
	full.scanFilesystem(context.Background())
	fBytes := full.rep.Stats.BytesRead

	t.Logf("quick read %d bytes (%d files header-probed); full read %d bytes",
		qBytes, qSkipped, fBytes)

	if qSkipped == 0 {
		t.Fatal("quick mode header-probed nothing — the type filter is not running")
	}
	// The whole point: quick must read dramatically less.
	if qBytes >= fBytes/4 {
		t.Errorf("quick read %d bytes vs full %d — the type filter is not saving work",
			qBytes, fBytes)
	}
}

// Scoping must not create a blind spot: a script wearing an asset extension is
// still caught, because that detection only ever needed the file's first bytes.
func TestQuickModeStillCatchesDisguisedScript(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	write(t, root, "wp-content/themes/t/assets/css/theme.css", open+"\necho 'inert';\n")

	a := scopeAgent(t, root, true)
	a.scanFilesystem(context.Background())

	var found bool
	for _, f := range a.Report().Findings {
		if strings.HasSuffix(filepath.ToSlash(f.Path), "assets/css/theme.css") {
			found = true
		}
	}
	if !found {
		t.Error("quick mode missed a PHP script wearing a .css extension")
	}
}

// And PHP anywhere in a walked tree is still fully analysed.
func TestQuickModeStillAnalysesPHP(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	write(t, root, "wp-content/plugins/p/shell.php",
		open+"\n"+kEval+"("+kPost+"['c']);\n")

	a := scopeAgent(t, root, true)
	a.scanFilesystem(context.Background())

	var found bool
	for _, f := range a.Report().Findings {
		if strings.HasSuffix(filepath.ToSlash(f.Path), "p/shell.php") {
			found = true
		}
	}
	if !found {
		t.Error("quick mode missed a shell in a plugin directory")
	}
}

// Guards the flag plumbing itself: Quick must actually reach the sweep.
func TestQuickFlagReachesTheSweep(t *testing.T) {
	root := t.TempDir()
	buildBulkyTree(t, root)

	if !scopeAgent(t, root, true).cfg.Quick {
		t.Fatal("Quick did not survive into the agent config")
	}
	a := scopeAgent(t, root, true)
	if !a.skipDir("wp-content/uploads", "uploads") {
		t.Error("skipDir does not exclude uploads in quick mode")
	}
	if !a.skipDir("wp-content/languages", "languages") {
		t.Error("skipDir does not exclude languages in quick mode")
	}
	full := scopeAgent(t, root, false)
	if full.skipDir("wp-content/uploads", "uploads") {
		t.Error("uploads was skipped even without --quick")
	}
	_ = os.Getenv
}
