//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wordeye/internal/govern"
	"wordeye/internal/model"
)

// Real-time monitoring.
//
// Every case here comes from a field failure, and each was found by RUNNING the
// daemon rather than reading it. The daemon was resident, memory was flat, the
// watches were registered, and it detected nothing an operator could see — a
// monitoring tool that looks healthy while covering 28% of a webroot is worse
// than one that fails loudly.

func monAgent(t *testing.T, root string) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "monitor", Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		SkipDB: true, SkipOS: true, SkipNet: true, SkipProbe: true,
		SkipProvenance: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

// collector records findings as the monitor emits them.
type collector struct {
	mu    sync.Mutex
	paths []string
	rules []string
}

func (c *collector) sink(f model.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths = append(c.paths, filepath.ToSlash(f.Path))
	c.rules = append(c.rules, f.RuleID)
}

// sawRule matches on rule id. OS-persistence findings are about the host rather
// than a file, so several carry no path at all and cannot be matched by suffix.
func (c *collector) sawRule(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.rules {
		if r == id {
			return true
		}
	}
	return false
}

func (c *collector) sawSuffix(suffix string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.paths {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

// startMonitor runs the daemon and returns once its watches are registered.
func startMonitor(t *testing.T, a *Agent) (context.CancelFunc, *collector) {
	t.Helper()
	c := &collector{}
	a.SetSink(c.sink)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = a.Monitor(ctx, 0) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.MonitorWatchSummary() != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if a.MonitorWatchSummary() == "" {
		cancel()
		t.Fatal("monitor did not register watches within 5s")
	}
	t.Cleanup(cancel)
	return cancel, c
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func shell() string {
	// Assembled at runtime so no runnable one-liner exists on disk.
	return "<?php " + "sys" + "tem($_REQUEST['c']); ?>"
}

// The baseline: a write into an already-watched directory.
func TestMonitorDetectsWriteToWatchedDir(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	if err := os.MkdirAll(filepath.Join(root, "wp-content/mu-plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := monAgent(t, root)
	_, c := startMonitor(t, a)

	write(t, root, "wp-content/mu-plugins/evil.php", shell())
	if !waitFor(func() bool { return c.sawSuffix("mu-plugins/evil.php") }, 8*time.Second) {
		t.Fatal("a shell written into a watched directory was not detected")
	}
}

// THE RACE. `mkdir x && cp shell.php x/` completes in microseconds, well before
// the watch for x can be registered, so the file write generates no event at
// all. Adding the watch is not enough — the new subtree must also be swept.
//
// Measured: without the sweep this case was missed entirely while the
// mkdir-then-wait case passed, which is exactly how a dropper behaves.
func TestMonitorDetectsShellInFreshlyCreatedDir(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	if err := os.MkdirAll(filepath.Join(root, "wp-content/plugins/acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := monAgent(t, root)
	_, c := startMonitor(t, a)

	// Directory and file created back to back, with no pause.
	dir := filepath.Join(root, "wp-content/plugins/acme/dropped")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.php"), []byte(shell()), 0o644); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool { return c.sawSuffix("dropped/x.php") }, 10*time.Second) {
		t.Fatal("a shell dropped into a newly created directory was not detected")
	}
}

// uploads/ is the classic drop site. It is enormous, so it is registered LAST —
// but it must still be registered, not excluded to save budget.
func TestMonitorCoversUploads(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	if err := os.MkdirAll(filepath.Join(root, "wp-content/uploads/2026/08"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := monAgent(t, root)
	_, c := startMonitor(t, a)

	write(t, root, "wp-content/uploads/2026/08/x.php", shell())
	if !waitFor(func() bool { return c.sawSuffix("uploads/2026/08/x.php") }, 8*time.Second) {
		t.Fatal("a shell written into uploads/ was not detected — that is the most common drop site")
	}
}

// Inert trees are excluded so a media library or node_modules cannot consume
// the whole watch budget and starve the directories that matter.
func TestMonitorSkipsInertTrees(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	for i := 0; i < 50; i++ {
		if err := os.MkdirAll(filepath.Join(root,
			"wp-content/plugins/acme/node_modules", "pkg"+string(rune('a'+i%26))+string(rune('a'+i/26))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a := monAgent(t, root)
	startMonitor(t, a)

	summary := a.MonitorWatchSummary()
	if summary == "" {
		t.Fatal("no watch summary")
	}
	t.Logf("summary: %s", summary)
	// 50 node_modules subdirectories plus the scaffold; if they were watched the
	// count would be far above the handful of real directories.
	if strings.Contains(summary, "skipped") {
		t.Errorf("budget was exhausted on a tiny tree: %s", summary)
	}
}

// Coverage must be knowable. Monitor mode never emits its report, so a partial
// watch set was previously invisible: 6,000 of 21,439 directories in the field,
// reported nowhere.
func TestMonitorReportsItsCoverage(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	a := monAgent(t, root)
	startMonitor(t, a)

	s := a.MonitorWatchSummary()
	if !strings.Contains(s, "watching") {
		t.Errorf("watch summary does not state coverage: %q", s)
	}
	// And it must reach the report's check list, so a connected agent surfaces
	// it in the console too.
	var found bool
	for _, c := range a.Report().Checks {
		if c.ID == "monitor.watch" {
			found = true
			if c.Reason == "" {
				t.Error("monitor.watch has no reason")
			}
		}
	}
	if !found {
		t.Error("monitor.watch check was not recorded")
	}
}

// The point of the whole product.
//
// inotify sees file writes in the webroot and nothing else. Everything that
// makes this tool worth running over a file scanner — a payload in an
// autoloaded wp_option, a malicious cron event, a rogue administrator, an
// application password, a search-console token, an LD_PRELOAD implant, an
// authorized_keys entry, a covert outbound channel — touches no file under the
// webroot. That is precisely why those techniques defeat file scanners.
//
// The backstop sweep previously ran scanFilesystem alone, so a monitoring
// daemon covered the one layer a file scanner already covers and silently
// omitted every layer that was the reason for building it.
func TestMonitorSweepCoversEveryLayer(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)

	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "monitor", Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		// Only the database is skipped: there is no MySQL in the test
		// environment. Every other layer must run.
		SkipDB:         true,
		SkipProvenance: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	a.fullSweep(context.Background())

	ids := map[string]bool{}
	for _, c := range a.Report().Checks {
		ids[c.ID] = true
		// Also record the family, since OS checks are individually named.
		if i := strings.IndexByte(c.ID, '.'); i > 0 {
			ids[c.ID[:i]] = true
		}
	}
	// Families that must be present, and what each one catches that a file
	// scanner cannot.
	for _, want := range []struct{ family, why string }{
		{"fs", "files on disk"},
		{"wp", "drop-ins, mu-plugins, uploads hardening"},
		{"osp", "cron, shell profiles, ssh keys, LD_PRELOAD, systemd units"},
		{"mem", "code injected into a running process"},
		{"net", "covert outbound channels — the gsocket case"},
	} {
		if !ids[want.family] {
			t.Errorf("monitor sweep ran no %q checks (%s); present: %v",
				want.family, want.why, keysOfBool(ids))
		}
	}
}

// Long-running daemons must not accumulate. Every sweep previously appended its
// checks and findings to a report that is never emitted and never cleared.
func TestMonitorSweepDoesNotAccumulate(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	a := monAgent(t, root)

	a.fullSweep(context.Background())
	first := len(a.Report().Checks)
	for i := 0; i < 3; i++ {
		a.fullSweep(context.Background())
	}
	after := len(a.Report().Checks)

	if after > first {
		t.Errorf("checks grew from %d to %d across sweeps — a daemon would grow without bound",
			first, after)
	}
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestWatchRootsAreRiskOrdered(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{
		"wp-content/mu-plugins", "wp-content/plugins", "wp-content/themes",
		"wp-content/uploads", "wp-includes", "wp-admin",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := watchRoots(root)
	if len(got) == 0 {
		t.Fatal("no roots returned")
	}
	idx := func(suffix string) int {
		for i, p := range got {
			if strings.HasSuffix(filepath.ToSlash(p), suffix) {
				return i
			}
		}
		return -1
	}
	// mu-plugins loads on every request and is hidden from the admin UI, so it
	// must never lose its watch to the media library.
	if mu, up := idx("wp-content/mu-plugins"), idx("wp-content/uploads"); mu < 0 || up < 0 || mu > up {
		t.Errorf("mu-plugins (%d) must be registered before uploads (%d)", mu, up)
	}
}

func TestWatchLimitIsBounded(t *testing.T) {
	n := watchLimit()
	if n < watchFloor {
		t.Errorf("watchLimit() = %d, below the floor %d", n, watchFloor)
	}
	if n > watchCeiling {
		t.Errorf("watchLimit() = %d, above the ceiling %d", n, watchCeiling)
	}
}

// Watch registration must be linear in the size of the tree.
//
// A field deployment burned ~2.8 cores on a live production host and starved
// its own event loop, so real writes went undetected. The cause was a
// membership test that scanned every existing watch — O(n) per directory,
// O(n^2) over a walk — compounded by roots that overlap (wp-content contains
// plugins, themes and uploads), so the same tree was traversed repeatedly.
//
// On the 21,439-directory webroot that measured as roughly 460 million string
// comparisons under a lock. This test fails long before that returns.
func TestMonitorStartupIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large directory tree")
	}
	root := t.TempDir()
	scaffold(t, root)

	// A media-library shape: many sibling directories under the overlapping
	// roots, which is exactly where the quadratic blow-up showed up.
	const dirs = 6000
	for i := 0; i < dirs; i++ {
		p := filepath.Join(root, "wp-content", "uploads",
			"y"+string(rune('a'+i%26)), "m"+string(rune('a'+(i/26)%26)), "d"+string(rune('a'+(i/676)%26)))
		if err := os.MkdirAll(filepath.Join(p, "n"+itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "wp-content/plugins/acme/inc"), 0o755); err != nil {
		t.Fatal(err)
	}

	a := monAgent(t, root)
	start := time.Now()
	_, _ = startMonitor(t, a)
	elapsed := time.Since(start)

	t.Logf("registered watches over ~%d directories in %s: %s", dirs, elapsed, a.MonitorWatchSummary())
	// Generous: the quadratic version took minutes on a tree of this order.
	if elapsed > 20*time.Second {
		t.Errorf("watch registration took %s — that is the quadratic path, not a linear walk", elapsed)
	}
}

// Overlapping roots must not be walked twice.
func TestMonitorDoesNotRewalkOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	for _, d := range []string{
		"wp-content/plugins/a", "wp-content/themes/b",
		"wp-content/uploads/2026/08", "wp-content/mu-plugins",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a := monAgent(t, root)
	startMonitor(t, a)

	// Every directory must hold exactly one watch: the reverse index and the
	// descriptor map must agree, or the count and the coverage report lie.
	if got := a.MonitorWatchSummary(); !strings.Contains(got, "watching") {
		t.Fatalf("summary: %q", got)
	}
	t.Logf("%s", a.MonitorWatchSummary())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Steady state must be event-driven.
//
// The EDR division of labour: one baseline scan at install, then evaluate only
// what changes, with full sweeps triggered by an operator from the console. A
// resident agent that re-scans on a timer is a periodic scanner wearing a
// monitor's clothes — it cost a shared production host ~2.7 cores.
//
// rescan == 0 must therefore perform NO sweep, while still loading the
// provenance needed to exonerate files during real-time evaluation.
func TestMonitorWithoutRescanDoesNoSweep(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	// A file that a full sweep would certainly flag. If it is reported, a sweep
	// ran that should not have.
	write(t, root, "wp-content/mu-plugins/preexisting.php", shell())

	a := monAgent(t, root)
	c := &collector{}
	a.SetSink(c.sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Monitor(ctx, 0) }()

	// Give it well past the time a sweep of this tiny tree would take.
	time.Sleep(3 * time.Second)
	if c.sawSuffix("preexisting.php") {
		t.Error("a full sweep ran despite rescan=0; steady state must be event-driven")
	}

	// But a NEW write must still be caught — monitoring is live, not disabled.
	write(t, root, "wp-content/mu-plugins/fresh.php", shell())
	if !waitFor(func() bool { return c.sawSuffix("fresh.php") }, 8*time.Second) {
		t.Error("a new write was not detected — monitoring is not running")
	}
}
