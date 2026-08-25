package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"strings"
	"sync"
	"testing"
	"time"

	"wordeye/internal/model"
)

// Provenance must report its own coverage honestly.
//
// A field run reported prov.expected_set as:
//
//	state: ok    reason: "1303 verified, 0 modified, 0 unexpected"
//
// Every one of those 1,303 was WordPress core. Not a single plugin manifest had
// loaded, so the entire plugin tree went to the pattern engines unexonerated —
// and produced every false positive in the report. The check said "ok" because
// plugin fetch failures were counted into a prose summary and never into the
// failure list the state was derived from.
//
// Coverage is part of the result. These tests hold that line.

// fakeManifest builds a plugin-checksums response for the given files.
func fakeManifest(files map[string]string) []byte {
	type fh struct {
		MD5    []string `json:"md5"`
		SHA256 []string `json:"sha256"`
	}
	out := struct {
		Files map[string]fh `json:"files"`
	}{Files: map[string]fh{}}
	for p, sha := range files {
		out.Files[p] = fh{SHA256: []string{sha}}
	}
	b, _ := json.Marshal(out)
	return b
}

// plugin writes a plugin with a parseable version header.
func plugin(t *testing.T, root, slug, version string) {
	t.Helper()
	write(t, root, "wp-content/plugins/"+slug+"/"+slug+".php",
		"<?php\n/*\nPlugin Name: "+slug+"\nVersion: "+version+"\n*/\n")
}

func provCheck(r *model.Report) model.CheckStatus {
	for _, c := range r.Checks {
		if c.ID == "prov.expected_set" {
			return c
		}
	}
	return model.CheckStatus{}
}

// A transport failure means the check did not run for that plugin. That must
// degrade the state — it is the difference between "verified" and "unknown".
func TestProvenanceTransportFailureIsUnavailable(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	plugin(t, root, "acme", "1.0.0")

	// Core resolves; only the plugin fetch fails. This is the shape that
	// matters: a run that verified core and must not therefore claim success.
	fetch := func(ctx context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "plugin-checksums") {
			return nil, fmt.Errorf("dial tcp: connection refused")
		}
		return []byte(`{"checksums":{"wp-includes/version.php":"0bad"}}`), nil
	}
	a := provAgent(t, root, fetch)
	a.loadProvenance(context.Background())
	a.reportProvenance()

	c := provCheck(a.Report())
	if c.State != model.CheckUnavailable {
		t.Errorf("state = %q, want unavailable when a manifest could not be obtained (reason: %s)",
			c.State, c.Reason)
	}
	if !strings.Contains(c.Reason, "could not be obtained") {
		t.Errorf("reason does not name the fetch failure: %q", c.Reason)
	}
}

// A 404 is the authority answering. Premium plugins are simply not published;
// that bounds coverage but is not a fault, and must be stated rather than hidden.
func TestProvenanceUnpublishedIsReportedNotHidden(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	plugin(t, root, "premium-one", "2.0.0")
	plugin(t, root, "premium-two", "3.1.4")

	fetch := func(ctx context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "plugin-checksums") {
			return nil, fmt.Errorf("%w", errNoManifest)
		}
		return []byte(`{"checksums":{"wp-includes/version.php":"0bad"}}`), nil
	}
	a := provAgent(t, root, fetch)
	a.loadProvenance(context.Background())

	if got := len(a.prov.unpublished); got != 2 {
		t.Errorf("unpublished = %d, want 2", got)
	}
	if len(a.prov.failures) != 0 {
		t.Errorf("a 404 was recorded as a fault: %v", a.prov.failures)
	}
	a.reportProvenance()

	c := provCheck(a.Report())
	// Nothing verified at all, so the check cannot claim success.
	if c.State == model.CheckOK && !strings.Contains(c.Reason, "unpublished") {
		t.Errorf("check reported ok without disclosing unverifiable plugins: %q", c.Reason)
	}
}

// The core regression: coverage must appear in the reason, so a core-only run
// is never mistaken for a whole-site verification.
func TestProvenanceReasonStatesPluginCoverage(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	plugin(t, root, "covered", "1.0.0")
	plugin(t, root, "premium", "9.9.9")

	fetch := func(ctx context.Context, url string) ([]byte, error) {
		switch {
		case strings.Contains(url, "core/checksums"):
			return []byte(`{"checksums":{"wp-includes/version.php":"0bad"}}`), nil
		case strings.Contains(url, "/covered/"):
			return fakeManifest(map[string]string{"covered.php": "abc"}), nil
		default:
			return nil, fmt.Errorf("%w", errNoManifest)
		}
	}
	a := provAgent(t, root, fetch)
	a.loadProvenance(context.Background())
	a.reportProvenance()

	c := provCheck(a.Report())
	if !strings.Contains(c.Reason, "plugin manifest(s) covered") {
		t.Errorf("reason omits plugin coverage: %q", c.Reason)
	}
	if !strings.Contains(c.Reason, "unpublished") {
		t.Errorf("reason omits unverifiable plugins: %q", c.Reason)
	}
	if a.prov.pluginsCovered != 1 {
		t.Errorf("pluginsCovered = %d, want 1", a.prov.pluginsCovered)
	}
	t.Logf("reason: %s", c.Reason)
}

// Manifests are fetched concurrently; sequentially, sixty at a 20s timeout
// could outlast the scan and leave coverage silently truncated.
func TestProvenanceFetchesPluginsConcurrently(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	const n = 24
	for i := 0; i < n; i++ {
		plugin(t, root, fmt.Sprintf("p%02d", i), "1.0.0")
	}

	// Overlap is made DETERMINISTIC with a barrier rather than inferred from
	// timing. A fake fetcher that returns instantly lets each goroutine finish
	// before the next starts, so a sampled "peak concurrency" measures the
	// scheduler, not the code — and reports 1 on a single-CPU container even
	// though the fetches are genuinely concurrent.
	var mu sync.Mutex
	inFlight, peak := 0, 0
	gate := make(chan struct{})
	var once sync.Once

	fetch := func(ctx context.Context, url string) ([]byte, error) {
		if !strings.Contains(url, "plugin-checksums") {
			return nil, fmt.Errorf("%w", errNoManifest)
		}
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		reached := inFlight >= provFetchWorkers
		mu.Unlock()

		if reached {
			// The worker pool is saturated; release everyone.
			once.Do(func() { close(gate) })
		}
		select {
		case <-gate:
		case <-time.After(5 * time.Second):
			// Never hang the suite if the pool is smaller than expected.
		}

		mu.Lock()
		inFlight--
		mu.Unlock()
		return fakeManifest(map[string]string{"x.php": "abc"}), nil
	}

	a := provAgent(t, root, fetch)
	a.loadProvenance(context.Background())

	if a.prov.pluginsCovered != n {
		t.Errorf("covered %d of %d plugins", a.prov.pluginsCovered, n)
	}
	if peak < provFetchWorkers {
		t.Errorf("peak concurrency %d, expected the full pool of %d", peak, provFetchWorkers)
	}
	if peak > provFetchWorkers {
		t.Errorf("peak concurrency %d exceeds the %d-worker bound", peak, provFetchWorkers)
	}
	t.Logf("peak concurrent fetches: %d (bound %d)", peak, provFetchWorkers)
}
