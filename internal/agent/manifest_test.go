package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Parsing the wordpress.org plugin-checksums manifest.
//
// This is the highest-consequence parser in the agent. Provenance EXONERATES:
// a file matching its published manifest skips every pattern engine. So a
// manifest that fails to parse does not degrade gracefully — the entire plugin
// goes to the heuristics unverified, and a field run showed what that costs.
//
// The original struct declared md5/sha256 as []string. The endpoint actually
// emits a bare string, so EVERY plugin manifest failed to parse and plugin
// provenance never once worked. Worse, the failure surfaced as "16 manifest(s)
// could not be obtained", which sent the investigation to the network layer.
//
// These fixtures are the real response shapes, captured from the live endpoint.

// realManifestBareString is the actual response for
// add-featured-image-to-rss-feed 1.1.5 — the plugin named in the field report.
const realManifestBareString = `{
  "plugin": "add-featured-image-to-rss-feed",
  "version": "1.1.5",
  "files": {
    "add-featured-image-to-rss-feed.php": {
      "md5": "9e24f01e6ef6132fa22f53a879686ffb",
      "sha256": "7d44660937fc1680c103833418463b9fcb8fa7d1fddbdab22366ea97142bba5a"
    },
    "readme.txt": {
      "md5": "275a947c6a255247eff2eb44d6447e42",
      "sha256": "0f0830d87b1fce281890ba7c653dff9e0bc6ecb89edd6457030512e92b1f46eb"
    }
  }
}`

// The array form, which the endpoint has also been documented to produce.
const manifestArrayForm = `{
  "plugin": "acme", "version": "1.0.0",
  "files": {
    "acme.php": {"md5": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                 "sha256": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}
  }
}`

func fetcherFor(body string) provFetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		return []byte(body), nil
	}
}

// The regression: a bare-string md5 must parse.
func TestPluginManifestParsesBareStringHashes(t *testing.T) {
	sums, err := pluginChecksums(context.Background(),
		fetcherFor(realManifestBareString), "add-featured-image-to-rss-feed", "1.1.5")
	if err != nil {
		t.Fatalf("the real endpoint response failed to parse: %v", err)
	}
	const key = "wp-content/plugins/add-featured-image-to-rss-feed/add-featured-image-to-rss-feed.php"
	h, ok := sums[key]
	if !ok {
		t.Fatalf("missing %s; got keys %v", key, keysOf(sums))
	}
	if h.MD5 != "9e24f01e6ef6132fa22f53a879686ffb" {
		t.Errorf("md5 = %q", h.MD5)
	}
	if h.SHA256 != "7d44660937fc1680c103833418463b9fcb8fa7d1fddbdab22366ea97142bba5a" {
		t.Errorf("sha256 = %q", h.SHA256)
	}
}

func TestPluginManifestParsesArrayHashes(t *testing.T) {
	sums, err := pluginChecksums(context.Background(),
		fetcherFor(manifestArrayForm), "acme", "1.0.0")
	if err != nil {
		t.Fatalf("array-form manifest failed to parse: %v", err)
	}
	h := sums["wp-content/plugins/acme/acme.php"]
	if h.MD5 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("md5 = %q", h.MD5)
	}
}

// A manifest mixing both shapes must parse completely. This is the property
// that actually failed: Go aborts the whole document on the first type
// mismatch, so one odd field discarded every other file in the plugin.
func TestPluginManifestParsesMixedShapes(t *testing.T) {
	mixed := `{"plugin":"acme","version":"1.0","files":{
		"a.php": {"md5": "11111111111111111111111111111111"},
		"b.php": {"md5": ["22222222222222222222222222222222"]},
		"c.php": {"md5": null},
		"d.php": {"md5": 12345}
	}}`
	sums, err := pluginChecksums(context.Background(), fetcherFor(mixed), "acme", "1.0")
	if err != nil {
		t.Fatalf("mixed-shape manifest failed to parse: %v", err)
	}
	if len(sums) != 4 {
		t.Fatalf("parsed %d of 4 files — one bad field discarded the rest: %v",
			len(sums), keysOf(sums))
	}
	if got := sums["wp-content/plugins/acme/a.php"].MD5; got != "11111111111111111111111111111111" {
		t.Errorf("string form: md5 = %q", got)
	}
	if got := sums["wp-content/plugins/acme/b.php"].MD5; got != "22222222222222222222222222222222" {
		t.Errorf("array form: md5 = %q", got)
	}
	// Unusable values yield an empty hash rather than killing the manifest.
	if got := sums["wp-content/plugins/acme/d.php"].MD5; got != "" {
		t.Errorf("numeric md5 should be ignored, got %q", got)
	}
}

// Paths must be rooted at the webroot, or nothing ever matches during the sweep.
func TestPluginManifestKeysAreWebrootRelative(t *testing.T) {
	sums, err := pluginChecksums(context.Background(),
		fetcherFor(realManifestBareString), "add-featured-image-to-rss-feed", "1.1.5")
	if err != nil {
		t.Fatal(err)
	}
	for k := range sums {
		if !strings.HasPrefix(k, "wp-content/plugins/add-featured-image-to-rss-feed/") {
			t.Errorf("key %q is not webroot-relative", k)
		}
	}
}

// A genuinely empty manifest is still an error: it would otherwise register as
// a covered tree containing nothing, making every real file "unexpected".
func TestPluginManifestRejectsEmptyFileList(t *testing.T) {
	if _, err := pluginChecksums(context.Background(),
		fetcherFor(`{"plugin":"acme","version":"1.0","files":{}}`), "acme", "1.0"); err == nil {
		t.Error("an empty file list was accepted")
	}
}

func TestFlexStringsUnmarshal(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"abc"`, "abc"},
		{`["abc"]`, "abc"},
		{`["abc","def"]`, "abc"},
		{`[]`, ""},
		{`null`, ""},
		{`123`, ""},
		{`{"x":1}`, ""},
	}
	for _, c := range cases {
		var f flexStrings
		if err := json.Unmarshal([]byte(c.in), &f); err != nil {
			t.Errorf("Unmarshal(%s) errored: %v", c.in, err)
			continue
		}
		if got := f.first(); got != c.want {
			t.Errorf("Unmarshal(%s).first() = %q, want %q", c.in, got, c.want)
		}
	}
}

// A parse failure must be reported as a fault, never mistaken for "this plugin
// publishes no manifest" — that distinction is what tells an operator whether
// the tree is genuinely unverifiable or the agent is broken.
func TestManifestParseFailureIsAFaultNotUnpublished(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	plugin(t, root, "acme", "1.0.0")

	fetch := func(ctx context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "plugin-checksums") {
			return []byte(`{"files": not json at all`), nil
		}
		return []byte(`{"checksums":{"wp-includes/version.php":"0bad"}}`), nil
	}
	a := provAgent(t, root, fetch)
	a.loadProvenance(context.Background())

	if len(a.prov.unpublished) != 0 {
		t.Errorf("a malformed manifest was recorded as unpublished: %v", a.prov.unpublished)
	}
	if len(a.prov.failures) != 1 {
		t.Fatalf("expected 1 recorded fault, got %v", a.prov.failures)
	}
	a.reportProvenance()
	var reason string
	for _, c := range a.Report().Checks {
		if c.ID == "prov.expected_set" {
			reason = c.Reason
		}
	}
	if !strings.Contains(reason, "could not be obtained") {
		t.Errorf("reason does not surface the fault: %q", reason)
	}
	t.Logf("reason: %s", reason)
}

func keysOf(m map[string]fileHashes) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = fmt.Sprint
