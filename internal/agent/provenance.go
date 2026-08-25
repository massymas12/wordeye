package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"wordeye/internal/model"
)

// Provenance: which files are supposed to be here?
//
// Every other detector asks "does this file look malicious?" and can therefore
// be defeated by a file that does not. This one asks a different and much
// harder question to evade: "was this file ever deployed?"
//
// WordPress makes that answerable in a way most applications do not. Core and
// every plugin on wordpress.org publish per-file checksums, so an EXPECTED SET
// can be constructed from authority rather than inferred. Anything present in a
// covered directory but absent from that set was written after deployment —
// which is exactly the re-dropped web shell case, caught with no signature, no
// heuristic and no privileges at all.
//
// Two rules keep this honest:
//
//  1. "Unexpected" is only claimed inside directories we actually have a
//     manifest for. A premium plugin has no public checksums, and flagging
//     every file in it would be worse than useless.
//  2. If the manifests cannot be fetched, the check reports UNAVAILABLE and
//     degrades the verdict. A provenance check that silently covers nothing
//     would be the most dangerous kind of false confidence.

const (
	// provTimeout covers the WHOLE request, body included — that is what
	// http.Client.Timeout means. Plugin manifests are large (Wordfence's is
	// ~120KB, some exceed 500KB), and a field run lost 16 of 23 manifests to a
	// 20s budget while the tiny 404 responses all came back fine: the failures
	// correlated with response SIZE, not with reachability. wp-cli fetched the
	// same files successfully because it fetches them one at a time.
	provTimeout   = 60 * time.Second
	provCacheTTL  = 30 * 24 * time.Hour
	provMaxPlugin = 60
	// provFetchWorkers bounds concurrent manifest fetches. Deliberately modest:
	// this runs on a live web server whose network budget belongs to visitors,
	// and wordpress.org is a free service being asked for a hundred megabytes.
	// Three is enough to stay well inside the scan's runtime.
	provFetchWorkers = 3
	// provFetchAttempts is the total number of tries per manifest. A manifest
	// lost to a transient error is not a neutral outcome: every file that
	// plugin ships then goes to the pattern engines unexonerated, which is
	// precisely what produced a field run's worth of false positives.
	provFetchAttempts = 3
	provRetryBackoff  = 750 * time.Millisecond
)

// errNoManifest means the authority answered and has no manifest for this
// artefact — the normal case for premium and bespoke plugins. It is
// deliberately distinct from a transport failure: one bounds what provenance
// can prove, the other means the check did not run.
var errNoManifest = errors.New("no published manifest")

type fileHashes struct {
	MD5    string
	SHA256 string
}

// flexStrings decodes a JSON field that is sometimes a string and sometimes an
// array of strings.
//
// This field was originally declared []string, which turned out to match no
// real response at all: every manifest sampled from downloads.wordpress.org
// emits a BARE STRING ("md5":"9e24f0…"). Go's decoder aborts the entire
// document on the first type mismatch, so every plugin manifest failed and
// plugin provenance never once worked — a field run reported 0 of 23 covered.
//
// It is accepted in both shapes anyway. The endpoint is a third-party feed with
// no compatibility contract, and the cost of being wrong is not a parse error
// in a log: provenance EXONERATES, so a manifest that fails to parse silently
// sends an entire plugin to the pattern engines and manufactures false
// positives. Liberal parsing here buys real detection quality.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = nil
		return nil
	}
	switch b[0] {
	case '[':
		var xs []string
		if err := json.Unmarshal(b, &xs); err != nil {
			return err
		}
		*f = xs
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexStrings{s}
	default:
		// A number or object here is not something we can use, but it must not
		// cost us the rest of the manifest.
		*f = nil
	}
	return nil
}

func (f flexStrings) first() string {
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// provenanceSet is the expected state of the installation.
type provenanceSet struct {
	// expected maps a webroot-relative path to its authoritative hashes.
	expected map[string]fileHashes
	// covered lists path prefixes for which a manifest was obtained. Only files
	// under these are eligible to be called "unexpected".
	covered []string
	// sources records where the authority came from, for the report.
	sources []string
	// failures records manifests that could not be obtained for a reason that
	// represents a FAULT — a network error, a timeout, a malformed response.
	// A plugin simply having no public manifest is not a fault and belongs in
	// unpublished instead.
	failures []string
	// unpublished lists plugins with no manifest on wordpress.org: premium and
	// bespoke code. Expected, but it bounds what provenance can exonerate, so
	// it must be reported rather than silently absorbed.
	unpublished []string
	// pluginsCovered counts plugins whose manifest was obtained.
	pluginsCovered int
	// fetchMS is how long obtaining the manifests took, cache included.
	fetchMS int64
}

func (p *provenanceSet) isCovered(rel string) bool {
	for _, c := range p.covered {
		if strings.HasPrefix(rel, c) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// fetching
// ---------------------------------------------------------------------------

// provFetcher is injected so the comparison logic can be tested without
// touching the network.
type provFetcher func(ctx context.Context, url string) ([]byte, error)

func httpFetcher(cacheDir string) provFetcher {
	client := &http.Client{Timeout: provTimeout}
	return func(ctx context.Context, url string) ([]byte, error) {
		// Cache aggressively. Checksums for a released version never change, and
		// an agent that works offline on a repeat scan is worth a great deal
		// during an incident on a locked-down host.
		key := sha256.Sum256([]byte(url))
		cachePath := filepath.Join(cacheDir, hex.EncodeToString(key[:])[:32]+".json")
		if fi, err := os.Stat(cachePath); err == nil && time.Since(fi.ModTime()) < provCacheTTL {
			if b, err := os.ReadFile(cachePath); err == nil && len(b) > 0 {
				if looksLikeJSON(b) {
					return b, nil
				}
				// Written by a broken build. Drop it and fetch again.
				_ = os.Remove(cachePath)
			}
		}

		var lastErr error
		for attempt := 1; attempt <= provFetchAttempts; attempt++ {
			if attempt > 1 {
				// Linear backoff. Wait interruptibly: a scan being cancelled
				// must not be held up by a retry sleep.
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(attempt-1) * provRetryBackoff):
				}
			}
			b, err := fetchOnce(ctx, client, url)
			switch {
			case err == nil:
				// Never cache what we would refuse to read back.
				if looksLikeJSON(b) {
					if err := os.MkdirAll(cacheDir, 0o700); err == nil {
						_ = os.WriteFile(cachePath, b, 0o600)
					}
				}
				return b, nil
			case errors.Is(err, errNoManifest):
				// A definitive answer. Retrying cannot change it.
				return nil, err
			case ctx.Err() != nil:
				return nil, ctx.Err()
			}
			lastErr = err
		}
		return nil, fmt.Errorf("after %d attempts: %w", provFetchAttempts, lastErr)
	}
}

// fetchOnce performs a single GET. Split out so the retry loop above stays
// legible and so the body is always closed on every path.
func fetchOnce(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wordeye/"+Version)
	// Accept-Encoding is deliberately NOT set here.
	//
	// Go's transport adds it and transparently decompresses the response, but
	// ONLY while it owns the header. Setting it by hand keeps the compression
	// and silently opts out of the decoding, so every manifest arrived as raw
	// gzip and every json.Unmarshal failed with "invalid character '\x1f'".
	// Provenance then covered nothing, which put stock core and .org plugins in
	// front of the pattern engines: a field run produced 75 findings, six of
	// them critical on untouched WordPress, and took 84s because 51s of YARA
	// ran over files that should have been exonerated before being read.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// The authority answered and has nothing for this artefact. That is a
		// fact about the artefact, not a failure of the check, and the two must
		// never be conflated in the report.
		return nil, errNoManifest
	}
	if resp.StatusCode != http.StatusOK {
		// Drain a little so the connection can be reused rather than torn down;
		// on a rate-limited host that reuse is what lets the next call succeed.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("%s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	// Belt and braces. A forward proxy is entitled to hand back gzip we did not
	// ask for, and the failure mode is silent and estate-wide: an unmarshal
	// error becomes "no authority for this file", which becomes a critical
	// finding on stock core.
	return decompressIfGzip(b)
}

// decompressIfGzip gunzips a body that arrived compressed, and passes anything
// else through untouched.
func decompressIfGzip(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gzip body: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("gzip body: %w", err)
	}
	return out, nil
}

// looksLikeJSON guards the on-disk manifest cache.
//
// The gzip bug wrote compressed bytes into that cache under a 30-day TTL, so a
// host that scanned once while broken would stay broken for a month after
// upgrading — across an estate, with no visible symptom beyond false criticals.
// Validating on read means every already-poisoned agent repairs itself on its
// next scan instead of needing someone to clear a directory on 236 machines.
func looksLikeJSON(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// coreChecksums fetches the per-file manifest for a WordPress version.
func coreChecksums(ctx context.Context, fetch provFetcher, version, locale string) (map[string]fileHashes, error) {
	if locale == "" {
		locale = "en_US"
	}
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s", version, locale)
	b, err := fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Checksums map[string]string `json:"checksums"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	if len(resp.Checksums) == 0 {
		// The API nests by version for some responses.
		var alt struct {
			Checksums map[string]map[string]string `json:"checksums"`
		}
		if err := json.Unmarshal(b, &alt); err == nil {
			for _, m := range alt.Checksums {
				resp.Checksums = m
				break
			}
		}
	}
	if len(resp.Checksums) == 0 {
		return nil, fmt.Errorf("no checksums returned for core %s", version)
	}
	out := make(map[string]fileHashes, len(resp.Checksums))
	for p, sum := range resp.Checksums {
		out[path.Clean(p)] = fileHashes{MD5: strings.ToLower(sum)}
	}
	return out, nil
}

// pluginChecksums fetches the manifest for one plugin release.
func pluginChecksums(ctx context.Context, fetch provFetcher, slug, version string) (map[string]fileHashes, error) {
	url := fmt.Sprintf("https://downloads.wordpress.org/plugin-checksums/%s/%s.json", slug, version)
	b, err := fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Files map[string]struct {
			MD5    flexStrings `json:"md5"`
			SHA256 flexStrings `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	if len(resp.Files) == 0 {
		return nil, fmt.Errorf("no files listed for %s %s", slug, version)
	}
	out := make(map[string]fileHashes, len(resp.Files))
	for rel, h := range resp.Files {
		var fh fileHashes
		fh.MD5 = strings.ToLower(h.MD5.first())
		fh.SHA256 = strings.ToLower(h.SHA256.first())
		out["wp-content/plugins/"+slug+"/"+path.Clean(rel)] = fh
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// installed plugin discovery
// ---------------------------------------------------------------------------

var pluginVersionRe = regexp.MustCompile(`(?im)^\s*\*?\s*Version:\s*(.+)$`)
var pluginNameRe = regexp.MustCompile(`(?im)^\s*\*?\s*Plugin Name:\s*(.+)$`)

type installedPlugin struct {
	Slug    string
	Version string
}

// discoverPlugins reads each plugin's header to learn its version, which is
// what the checksum endpoint is keyed on.
func discoverPlugins(webroot string) []installedPlugin {
	dir := filepath.Join(webroot, "wp-content", "plugins")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []installedPlugin
	for _, e := range entries {
		if !e.IsDir() || len(out) >= provMaxPlugin {
			continue
		}
		slug := e.Name()
		ver := pluginVersion(filepath.Join(dir, slug))
		if ver == "" {
			continue
		}
		out = append(out, installedPlugin{Slug: slug, Version: ver})
	}
	return out
}

// pluginVersion finds the plugin header. It is conventionally in the file named
// after the plugin, but not reliably, so a bounded scan of the directory's
// top-level PHP files is more robust.
func pluginVersion(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var candidates []string
	base := filepath.Base(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".php") {
			continue
		}
		if strings.TrimSuffix(e.Name(), ".php") == base {
			candidates = append([]string{e.Name()}, candidates...)
			continue
		}
		candidates = append(candidates, e.Name())
	}
	for i, name := range candidates {
		if i >= 12 {
			break
		}
		head, err := readHead(filepath.Join(dir, name), 8<<10)
		if err != nil {
			continue
		}
		if !pluginNameRe.Match(head) {
			continue
		}
		if m := pluginVersionRe.FindSubmatch(head); m != nil {
			v := strings.TrimSpace(string(m[1]))
			// Strip a trailing comment terminator.
			v = strings.TrimSpace(strings.TrimSuffix(v, "*/"))
			if v != "" {
				return v
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// the check
// ---------------------------------------------------------------------------

// loadProvenance fetches the manifests BEFORE the filesystem sweep, so the
// sweep itself can consult them.
//
// Ordering matters enormously here. Provenance used to run last and merely add
// findings alongside everything else; the first field run showed why that is
// wrong. WordPress core is the densest concentration of dangerous-looking
// primitives on the system — core legitimately calls system(), mail() in a
// loop, wp_insert_user() from request data, gzinflate, pack, chr — so the
// heuristic and YARA engines lit up on a dozen stock core files at critical
// severity, and the location weighting made it worse.
//
// The fix is not to tune thresholds. It is that a file byte-identical to
// published WordPress core CANNOT be a web shell, whatever primitives it
// contains. Provenance therefore EXONERATES: verified files skip content
// analysis entirely. That makes authority the primary filter and the pattern
// engines the fallback, rather than the other way round.
func (a *Agent) loadProvenance(ctx context.Context) {
	if a.cfg.Webroot == "" || a.cfg.Offline {
		return
	}
	fetch := a.provFetch
	if fetch == nil {
		fetch = httpFetcher(filepath.Join(a.cfg.Home, ".wordeye", "provenance"))
	}
	t0 := time.Now()
	built := a.buildProvenance(ctx, a.cfg.Webroot, fetch)
	if built != nil {
		// Timed separately from the per-file hash comparisons. Conflating the
		// two hid a fetch stage that was not running: the sweep-time lookups
		// took 36ms, which looked entirely healthy.
		// Stamp before publishing: once the pointer is visible, other
		// goroutines may be reading the struct.
		built.fetchMS = time.Since(t0).Milliseconds()
	}
	a.setProvenance(built)
}

// provKind is the provenance verdict for one file.
type provKind int

const (
	provUncovered  provKind = iota // no authority exists for this path
	provVerified                   // matches the published manifest
	provModified                   // path is published, contents differ
	provUnexpected                 // inside a fully published tree, but not in it
	// provAttested: no publisher manifest exists, but a vendor pack vouches for
	// these exact bytes at this exact path. Weaker than provVerified and kept
	// distinct from it everywhere, because "many machines agree" is not the
	// same claim as "the publisher shipped this".
	provAttested
)

// provenanceVerdict classifies a file during the sweep.
func (a *Agent) provenanceVerdict(rel string, content []byte, truncated bool, abs string) provKind {
	p := a.provenance()
	if p == nil || len(p.expected) == 0 || !p.isCovered(rel) {
		// No publisher manifest covers this path. A vendor pack may still
		// attest to it — that is the entire point of packs, since the
		// uncovered trees are exactly the premium and bespoke ones.
		//
		// Only whole files are eligible: a truncated read cannot be hashed
		// honestly, and attesting to bytes we did not see would be a lie.
		if !truncated && a.vendor.Len() > 0 {
			sum := sha256.Sum256(content)
			if _, ok := a.vendor.Attests(rel, hex.EncodeToString(sum[:])); ok {
				return provAttested
			}
		}
		return provUncovered
	}
	want, known := p.expected[rel]
	if !known {
		if provIgnorable(rel) {
			return provUncovered
		}
		return provUnexpected
	}
	if provContentMatches(content, truncated, abs, want) {
		return provVerified
	}
	return provModified
}

// reportProvenance emits the check status and the coverage summary once the
// sweep has finished.
func (a *Agent) reportProvenance() {
	if a.cfg.SkipProvenance {
		return
	}
	start := time.Now()
	state, reason := a.provenanceState()
	a.rep.AddCheck(model.CheckStatus{
		ID: "prov.expected_set", State: state, Reason: reason,
		Duration: time.Since(start).Round(time.Millisecond).String(),
	})

	prov := a.provenance()
	if prov == nil || len(prov.expected) == 0 {
		return
	}
	v := a.provVerified.Load()
	m := a.provModified.Load()
	u := a.provUnexpected.Load()
	n := a.provUncovered.Load()

	a.emit(model.Finding{
		RuleID:     "prov.coverage",
		Class:      "PROV",
		Severity:   model.SevInfo,
		Confidence: model.ConfConfirmed,
		Title: fmt.Sprintf("Provenance verified for %d files; %d have no authority to compare against",
			v, n),
		Detail: fmt.Sprintf(
			"Manifests: %s. Verified files were exonerated and skipped by the pattern engines — a file identical to "+
				"its published release cannot be a shell regardless of what functions it calls. "+
				"%d modified, %d unexpected.",
			strings.Join(prov.sources, ", "), m, u),
		Remediation: "For unverifiable directories, use the estate-wide hash correlation in the console: a premium " +
			"plugin file identical across many sites is almost certainly genuine; one appearing on a single site is not.",
		Meta: map[string]any{
			"verified": v, "modified": m, "unexpected": u, "unverifiable": n,
			"sources": prov.sources, "failures": prov.failures,
			"plugins_covered":     prov.pluginsCovered,
			"plugins_unpublished": prov.unpublished,
			"fetch_ms":            prov.fetchMS,
		},
	})
}

func (a *Agent) provenanceState() (model.CheckState, string) {
	if a.cfg.Webroot == "" {
		return model.CheckUnavailable, "no webroot"
	}
	if a.cfg.Offline {
		return model.CheckUnavailable,
			"running offline: no manifests fetched, so nothing in this webroot has verified provenance"
	}
	prov := a.provenance()
	if prov == nil || len(prov.expected) == 0 {
		reason := "no manifests obtained"
		if prov != nil && len(prov.failures) > 0 {
			reason += " (" + strings.Join(prov.failures, "; ") + ")"
		}
		return model.CheckUnavailable, reason
	}
	reason := fmt.Sprintf("%d verified, %d modified, %d unexpected",
		a.provVerified.Load(), a.provModified.Load(), a.provUnexpected.Load())

	// Coverage is part of the result, not a footnote. A run that verified core
	// and nothing else is a materially weaker statement than one that verified
	// core and every plugin, and the difference decides how much the pattern
	// engines' output should be trusted. Reporting only "N verified" hid a run
	// in which no plugin manifest loaded at all — and the unexonerated plugin
	// tree then produced every false positive in the report.
	if prov.pluginsCovered > 0 || len(prov.unpublished) > 0 {
		reason += fmt.Sprintf("; %d plugin manifest(s) covered", prov.pluginsCovered)
		if n := len(prov.unpublished); n > 0 {
			reason += fmt.Sprintf(", %d unpublished (premium/bespoke, cannot be verified)", n)
		}
	}
	// Attestations are reported separately and never folded into "verified".
	// A publisher checksum and a fleet vote are different claims, and an
	// operator deciding whether to act on a finding needs to know which one
	// spoke for a file.
	if n := a.provAttested.Load(); n > 0 {
		reason += fmt.Sprintf("; %d attested by estate consensus (not publisher checksums)", n)
	}
	if n := len(prov.failures); n > 0 {
		// Name the actual error, not just the count. A bare "16 could not be
		// fetched" sent an operator digging through finding metadata to learn
		// whether it was DNS, a 429 or a timeout — which is the one thing
		// needed to act on it.
		return model.CheckUnavailable, fmt.Sprintf("%s; %d manifest(s) could not be obtained (%s)",
			reason, n, prov.failures[0])
	}
	return model.CheckOK, reason
}

// buildProvenance assembles the expected set from every available authority.
func (a *Agent) buildProvenance(ctx context.Context, root string, fetch provFetcher) *provenanceSet {
	set := &provenanceSet{expected: map[string]fileHashes{}}

	// --- WordPress core ----------------------------------------------------
	if ver := WordPressVersion(root); ver != "" {
		if sums, err := coreChecksums(ctx, fetch, ver, ""); err == nil {
			for p, h := range sums {
				set.expected[p] = h
			}
			// Core publishes a manifest for these trees, so an extra file in
			// them is unambiguous — and wp-includes is a favourite drop site
			// precisely because nobody reads it.
			set.covered = append(set.covered, "wp-admin/", "wp-includes/")
			set.sources = append(set.sources, "wordpress core "+ver)
		} else {
			set.failures = append(set.failures, "core "+ver+": "+err.Error())
		}
	} else {
		set.failures = append(set.failures, "core version could not be determined")
	}

	// --- plugins from the .org repository ----------------------------------
	//
	// Fetched concurrently. Sequentially, sixty manifests at a 20s timeout each
	// could outlast the whole scan, and the loop would simply stop at the first
	// context expiry having covered a fraction of the tree — while still
	// reporting success. Bounded concurrency keeps this within a few seconds.
	plugins := discoverPlugins(root)
	type presult struct {
		slug string
		sums map[string]fileHashes
		err  error
	}
	results := make([]presult, len(plugins))
	sem := make(chan struct{}, provFetchWorkers)
	var wg sync.WaitGroup
	for i, p := range plugins {
		wg.Add(1)
		go func(i int, p installedPlugin) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				results[i] = presult{slug: p.Slug, err: ctx.Err()}
				return
			}
			sums, err := pluginChecksums(ctx, fetch, p.Slug, p.Version)
			results[i] = presult{slug: p.Slug, sums: sums, err: err}
		}(i, p)
	}
	wg.Wait()

	var okPlugins int
	for _, r := range results {
		switch {
		case r.err == nil:
			for path, h := range r.sums {
				set.expected[path] = h
			}
			set.covered = append(set.covered, "wp-content/plugins/"+r.slug+"/")
			okPlugins++
		case errors.Is(r.err, errNoManifest):
			// Premium or bespoke: expected, but it bounds coverage.
			set.unpublished = append(set.unpublished, r.slug)
		default:
			// A transport error, a timeout, a malformed manifest. This means
			// the check did not run for this plugin, which is a different and
			// more serious statement than "this plugin is not published".
			set.failures = append(set.failures,
				fmt.Sprintf("plugin %s: %v", r.slug, r.err))
		}
	}
	set.pluginsCovered = okPlugins
	if okPlugins > 0 {
		set.sources = append(set.sources,
			fmt.Sprintf("%d of %d plugin manifest(s)", okPlugins, len(plugins)))
	}
	if n := len(set.unpublished); n > 0 {
		set.sources = append(set.sources,
			fmt.Sprintf("%d plugin(s) with no public manifest", n))
	}
	return set
}

// provIgnorable skips files that legitimately appear in covered trees without
// being part of a release.
func provIgnorable(rel string) bool {
	base := path.Base(rel)
	switch base {
	case ".htaccess", "index.php", "web.config", ".DS_Store", "error_log", "php_errorlog":
		return true
	}
	// Language packs and per-site uploads live inside covered trees.
	return strings.Contains(rel, "/languages/") ||
		strings.HasSuffix(base, ".mo") || strings.HasSuffix(base, ".po")
}

// provContentMatches compares against the manifest, reusing the bytes the sweep
// already read rather than opening the file a second time.
func provContentMatches(content []byte, truncated bool, abs string, want fileHashes) bool {
	if content == nil || truncated {
		return provHashMatchesFile(abs, want)
	}
	if want.SHA256 != "" {
		sum := sha256.Sum256(content)
		return hex.EncodeToString(sum[:]) == want.SHA256
	}
	// Core publishes MD5 only. Unsuitable for security decisions in general, but
	// here it is detecting DIFFERENCE, and any modification a defender cares
	// about changes it.
	sum := md5.Sum(content)
	return hex.EncodeToString(sum[:]) == want.MD5
}

func provHashMatchesFile(abs string, want fileHashes) bool {
	f, err := os.Open(abs)
	if err != nil {
		return false
	}
	defer f.Close()

	m := md5.New()
	s := sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s), f); err != nil {
		return false
	}
	if want.SHA256 != "" {
		return hex.EncodeToString(s.Sum(nil)) == want.SHA256
	}
	return hex.EncodeToString(m.Sum(nil)) == want.MD5
}

func (a *Agent) emitUnexpected(root, rel string) {
	abs := filepath.Join(root, filepath.FromSlash(rel))
	fi, err := os.Stat(abs)
	if err != nil {
		return
	}
	sev := model.SevHigh
	conf := model.ConfLikely
	where := "a plugin"
	if strings.HasPrefix(rel, "wp-admin/") || strings.HasPrefix(rel, "wp-includes/") {
		// Nothing legitimate adds files to the core trees.
		sev = model.SevCritical
		conf = model.ConfConfirmed
		where = "WordPress core"
	}
	f := a.fileFinding(fileJob{abs: abs, rel: rel, info: fi}, nil, false)
	f.RuleID = "prov.unexpected_file"
	f.Class = "PROV"
	f.Severity = sev
	f.Confidence = conf
	f.Title = "File is not part of the published release"
	f.Detail = fmt.Sprintf(
		"%s publishes a complete file manifest for this version, and this path is not in it. "+
			"The file was therefore not deployed — it was written afterwards. This holds regardless of what the "+
			"file contains, so it catches droppers and loaders that carry no detectable payload.", where)
	f.Remediation = "Compare against the official package. A file in a core directory that is not in core has no legitimate explanation."
	a.emit(f)
}

func (a *Agent) emitModified(root, rel string) {
	abs := filepath.Join(root, filepath.FromSlash(rel))
	fi, err := os.Stat(abs)
	if err != nil {
		return
	}
	sev := model.SevHigh
	conf := model.ConfLikely
	if strings.HasPrefix(rel, "wp-admin/") || strings.HasPrefix(rel, "wp-includes/") {
		sev = model.SevCritical
		conf = model.ConfConfirmed
	}

	// Rank on WHAT the file now contains, not merely on the fact that it
	// changed.
	//
	// "Differs from the published release" is a true statement about a great
	// many files: a whitespace fix, a vendor patch, a hand-applied backport.
	// Reporting all of them at the same severity as an injection makes the
	// check expensive to read. A field estate confirmed it — a modified
	// a modified plugin file was fully sanitised code with no dangerous
	// sink anywhere in it, reported at HIGH alongside genuine tampering.
	//
	// The question that separates the two is whether the file can now DO
	// anything: an edit that introduces no executor, no decoder and no
	// filesystem write is a patch, whatever else it is. It is still reported,
	// because an unexplained edit to published code is worth knowing about, but
	// it does not lead the queue.
	dangerous := false
	// readCapped writes through its buffer pointer, so it needs a real one.
	var scratch []byte
	if b, err := readCapped(abs, minInt64(fi.Size(), a.cfg.MaxFileSize), &scratch); err == nil {
		dangerous = hasMalwareMarker(b) || containsSink(b)
	}

	f := a.fileFinding(fileJob{abs: abs, rel: rel, info: fi}, nil, false)
	f.RuleID = "prov.modified_file"
	f.Class = "PROV"
	f.Severity = sev
	f.Confidence = conf
	f.Title = "File differs from the published release"
	f.Detail = "This path exists in the official manifest but its contents do not match. " +
		"Either it was edited in place, or it was replaced."
	f.Remediation = "Diff against the official package for this exact version before deciding whether it is an injection or a local patch."

	if !dangerous {
		f.Severity = downgrade(f.Severity)
		f.Confidence = model.ConfReview
		f.Title = "File differs from the published release (no dangerous code introduced)"
		f.Detail += " The current contents contain no executor, decoder or filesystem write, " +
			"so this looks like a patch rather than an injection — but it is still an unexplained " +
			"difference from what the publisher shipped."
	}
	f.Meta = map[string]any{"introduces_sink": dangerous}
	a.emit(f)
}

// containsSink reports whether a file contains anything that could execute,
// decode or write. Used to separate a patch from an injection when a file no
// longer matches its published release.
//
// Deliberately broad on the write side: a modified plugin file that gains a
// file_put_contents is how a dropper is planted, even when nothing in it
// evaluates a string.
func containsSink(b []byte) bool {
	if sinkCallRe.Match(b) {
		return true
	}
	lower := bytes.ToLower(b)
	for _, w := range [][]byte{
		[]byte("file_put_contents"), []byte("fwrite"), []byte("fputs"),
		[]byte("move_uploaded_file"), []byte("copy("), []byte("rename("),
		[]byte("curl_exec"), []byte("fsockopen"),
	} {
		if bytes.Contains(lower, w) {
			return true
		}
	}
	return false
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
