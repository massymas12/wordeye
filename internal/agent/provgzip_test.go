package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Provenance is the primary filter: a file that matches its published release
// is exonerated and never reaches the pattern engines. When manifest fetching
// fails, every engine runs on stock WordPress instead, and the product reports
// criticals on untouched core.
//
// It failed in the field for a one-line reason. fetchOnce set
// Accept-Encoding: gzip by hand; Go's transport only decompresses transparently
// while it owns that header, so bodies came back as raw gzip and every
// json.Unmarshal died on "invalid character '\x1f'". Nothing was exonerated,
// 69,903 files were analysed, and the console showed 75 findings — six critical
// on core files nobody had touched.
//
// These tests pin the decode path end to end, because the failure produced no
// error anywhere an operator would look.

const manifestJSON = `{"checksums":{"wp-admin/index.php":"abc123"}}`

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cachePathFor(dir, url string) string {
	key := sha256.Sum256([]byte(url))
	return filepath.Join(dir, hex.EncodeToString(key[:])[:32]+".json")
}

// The exact field failure: a server that compresses the body. Whether Go
// decodes it or our fallback does, the fetcher must return JSON.
func TestFetchDecodesCompressedManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(gzipBytes(t, manifestJSON))
	}))
	defer srv.Close()

	fetch := httpFetcher(t.TempDir())
	b, err := fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !looksLikeJSON(b) {
		t.Fatalf("body is not JSON: %q", firstBytes(b))
	}
	if string(b) != manifestJSON {
		t.Errorf("got %q, want %q", b, manifestJSON)
	}
}

// A proxy may hand back gzip without declaring it, in which case Go cannot
// help and the fallback is the only thing standing between the estate and a
// wave of false criticals.
func TestFetchDecodesUndeclaredGzip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Encoding header, deliberately.
		_, _ = w.Write(gzipBytes(t, manifestJSON))
	}))
	defer srv.Close()

	b, err := httpFetcher(t.TempDir())(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(b) != manifestJSON {
		t.Errorf("got %q, want %q", firstBytes(b), manifestJSON)
	}
}

// coreChecksums is where the field error surfaced. Prove the whole path works,
// not just the transport.
func TestCoreChecksumsThroughCompressedTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzipBytes(t, manifestJSON))
	}))
	defer srv.Close()

	fetch := func(ctx context.Context, url string) ([]byte, error) {
		return httpFetcher(t.TempDir())(ctx, srv.URL)
	}
	sums, err := coreChecksums(context.Background(), fetch, "6.5.2", "")
	if err != nil {
		t.Fatalf("coreChecksums: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("got %d entries, want 1", len(sums))
	}
	if _, ok := sums["wp-admin/index.php"]; !ok {
		t.Errorf("expected path missing from manifest: %v", sums)
	}
}

// The cache carried the bug forward. Compressed bytes were written under a
// 30-day TTL, so upgrading the binary would not have fixed an already-scanned
// host. A poisoned entry must be discarded, not served.
func TestPoisonedCacheSelfHeals(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(manifestJSON))
	}))
	defer srv.Close()

	dir := t.TempDir()
	poisoned := cachePathFor(dir, srv.URL)
	if err := os.WriteFile(poisoned, gzipBytes(t, manifestJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := httpFetcher(dir)(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(b) != manifestJSON {
		t.Errorf("served the poisoned cache entry: %q", firstBytes(b))
	}
	if hits != 1 {
		t.Errorf("expected exactly one refetch, got %d", hits)
	}
	// And the repaired entry must be usable next time.
	if got, err := os.ReadFile(poisoned); err != nil || !looksLikeJSON(got) {
		t.Errorf("cache was not repaired: err=%v content=%q", err, firstBytes(got))
	}
}

// Nothing unreadable may enter the cache in the first place.
func TestCacheRejectsNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>rate limited</html>"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	if _, err := httpFetcher(dir)(context.Background(), srv.URL); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if _, err := os.Stat(cachePathFor(dir, srv.URL)); !os.IsNotExist(err) {
		t.Error("an HTML error page was cached as a manifest")
	}
}

func TestLooksLikeJSON(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`{"a":1}`, true},
		{"  \n\t[1,2]", true},
		{"", false},
		{"<html>", false},
		{"\x1f\x8b\x08", false},
		{"   ", false},
	}
	for _, c := range cases {
		if got := looksLikeJSON([]byte(c.in)); got != c.want {
			t.Errorf("looksLikeJSON(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func firstBytes(b []byte) string {
	s := string(b)
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return strings.ToValidUTF8(s, ".")
}
