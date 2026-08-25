package agent

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wordeye/internal/govern"
	"wordeye/internal/model"
)

// Provenance tests.
//
// The manifests are injected rather than fetched, so the suite never depends on
// api.wordpress.org being reachable — and so the comparison logic can be tested
// against exactly the cases that matter.

func md5hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// fakeManifests serves core and plugin checksum documents from memory.
func fakeManifests(core map[string]string, plugins map[string]map[string]string) provFetcher {
	return func(_ context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "api.wordpress.org/core/checksums") {
			return json.Marshal(map[string]any{"checksums": core})
		}
		for key, files := range plugins {
			if strings.Contains(url, "/plugin-checksums/"+key+"/") {
				out := map[string]any{}
				for rel, sum := range files {
					out[rel] = map[string]any{"md5": []string{sum}}
				}
				return json.Marshal(map[string]any{"files": out})
			}
		}
		return nil, fmt.Errorf("no manifest for %s", url)
	}
}

func provAgent(t *testing.T, root string, fetch provFetcher) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "scan", Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		SkipDB: true, SkipOS: true, SkipNet: true, SkipProbe: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	a.SetProvenanceFetcher(fetch)
	// Tests create their fixtures now, so inside a container every one of them
	// post-dates the namespace start and trips the deploy-time heuristics. Those
	// are exercised by their own tests; clearing the environment here keeps this
	// helper focused on what it is actually asserting.
	a.env = nil
	return a
}

func findingIDs(a *Agent, suffix string) []string {
	var out []string
	for _, f := range a.Report().Findings {
		if strings.HasSuffix(filepath.ToSlash(f.Path), suffix) {
			out = append(out, f.RuleID)
		}
	}
	return out
}

// The headline case: a file present in a directory whose contents are fully
// published, but absent from the manifest. It was never deployed.
func TestUnexpectedFileInCoreIsDetected(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")

	genuine := "<?php\n// genuine core file\n"
	write(t, root, "wp-includes/pluggable.php", genuine)

	// A dropper with no malicious content at all — nothing for a signature or a
	// heuristic to find. Only provenance catches this.
	write(t, root, "wp-includes/wp-cache-helper.php", "<?php\nreturn 1;\n")

	fetch := fakeManifests(map[string]string{
		"wp-includes/version.php":   md5hex([]byte("<?php\n$wp_version = '6.5.2';\n")),
		"wp-includes/pluggable.php": md5hex([]byte(genuine)),
	}, nil)

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	ids := findingIDs(a, "wp-includes/wp-cache-helper.php")
	if !hasRule(ids, "prov.unexpected_file") {
		t.Fatalf("undeployed file in core not detected (got %v)", ids)
	}
	// Nothing legitimate adds files to core, so this must be unambiguous.
	for _, f := range a.Report().Findings {
		if f.RuleID == "prov.unexpected_file" && strings.Contains(f.Path, "wp-cache-helper") {
			if f.Severity != model.SevCritical {
				t.Errorf("severity = %s, want critical for an extra file in core", f.Severity)
			}
			if f.Confidence != model.ConfConfirmed {
				t.Errorf("confidence = %s, want confirmed", f.Confidence)
			}
		}
	}
	// The genuine file must not be flagged.
	if ids := findingIDs(a, "wp-includes/pluggable.php"); len(ids) > 0 {
		t.Errorf("false positive on a genuine core file: %v", ids)
	}
}

func TestModifiedCoreFileIsDetected(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
	write(t, root, "wp-includes/load.php", "<?php\n// TAMPERED\n")

	fetch := fakeManifests(map[string]string{
		"wp-includes/version.php": md5hex([]byte("<?php\n$wp_version = '6.5.2';\n")),
		"wp-includes/load.php":    md5hex([]byte("<?php\n// original\n")),
	}, nil)

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	if ids := findingIDs(a, "wp-includes/load.php"); !hasRule(ids, "prov.modified_file") {
		t.Fatalf("modified core file not detected (got %v)", ids)
	}
}

// A premium plugin has no published manifest. Flagging every file in it would
// be far worse than not checking it.
func TestPluginWithoutManifestIsNotFlagged(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
	write(t, root, "wp-content/plugins/premium-thing/premium-thing.php",
		"<?php\n/*\nPlugin Name: Premium Thing\nVersion: 3.1.0\n*/\n")
	write(t, root, "wp-content/plugins/premium-thing/lib/helper.php", "<?php\nreturn 2;\n")

	fetch := fakeManifests(map[string]string{
		"wp-includes/version.php": md5hex([]byte("<?php\n$wp_version = '6.5.2';\n")),
	}, nil) // no plugin manifests at all

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	for _, f := range a.Report().Findings {
		if strings.Contains(f.Path, "premium-thing") && f.RuleID != "prov.coverage" {
			t.Errorf("flagged a file in an unverifiable plugin: %s on %s", f.RuleID, f.Path)
		}
	}
}

// A repository plugin WITH a manifest: an extra file inside it is caught.
func TestUnexpectedFileInRepoPluginIsDetected(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")

	main := "<?php\n/*\nPlugin Name: Contact Form\nVersion: 5.9.8\n*/\n"
	write(t, root, "wp-content/plugins/contact-form/contact-form.php", main)
	write(t, root, "wp-content/plugins/contact-form/inc/x.php", "<?php\nreturn 3;\n")

	fetch := fakeManifests(
		map[string]string{"wp-includes/version.php": md5hex([]byte("<?php\n$wp_version = '6.5.2';\n"))},
		map[string]map[string]string{
			"contact-form": {"contact-form.php": md5hex([]byte(main))},
		})

	a := provAgent(t, root, fetch)
	runProvenanceScan(t, a)

	if ids := findingIDs(a, "contact-form/inc/x.php"); !hasRule(ids, "prov.unexpected_file") {
		t.Fatalf("extra file in a repository plugin not detected (got %v)", ids)
	}
}

// The integrity property again: a provenance check that verified nothing must
// report itself as unavailable, never as a pass.
func TestOfflineProvenanceReportsUnavailable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")

	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "scan", Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		SkipDB: true, SkipOS: true, SkipNet: true, SkipProbe: true,
		Offline: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	runProvenanceScan(t, a)
	a.Report().Finalize()

	var found bool
	for _, c := range a.Report().Checks {
		if c.ID == "prov.expected_set" {
			found = true
			if c.State != model.CheckUnavailable {
				t.Errorf("offline provenance state = %q, want unavailable", c.State)
			}
		}
	}
	if !found {
		t.Fatal("provenance check missing from the report")
	}
	if a.Report().Verdict == "clean" {
		t.Error("a scan that verified no provenance reported CLEAN")
	}
}

// Fetch failure must be treated the same as offline: unavailable, not pass.
func TestUnreachableManifestsReportUnavailable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")

	failing := func(context.Context, string) ([]byte, error) {
		return nil, fmt.Errorf("dial tcp: network unreachable")
	}
	a := provAgent(t, root, failing)
	runProvenanceScan(t, a)

	for _, c := range a.Report().Checks {
		if c.ID == "prov.expected_set" && c.State != model.CheckUnavailable {
			t.Errorf("state = %q with all manifests unreachable, want unavailable", c.State)
		}
	}
}

// Plugin version discovery drives which manifest gets requested, so a wrong
// version silently means no coverage.
func TestPluginVersionDiscovery(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "akismet")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "<?php\n/**\n * Plugin Name: Akismet Anti-spam\n * Version: 5.3.2\n */\n"
	if err := os.WriteFile(filepath.Join(pluginDir, "akismet.php"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := pluginVersion(pluginDir); got != "5.3.2" {
		t.Errorf("pluginVersion = %q, want 5.3.2", got)
	}
}

// runProvenanceScan drives the split API: fetch the manifests, run the sweep
// (which is where exoneration and classification now happen), then report.
func runProvenanceScan(t *testing.T, a *Agent) {
	t.Helper()
	ctx := context.Background()
	a.loadProvenance(ctx)
	a.scanFilesystem(ctx)
	a.reportProvenance()
}
