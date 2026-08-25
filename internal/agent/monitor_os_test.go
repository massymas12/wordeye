//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wordeye/internal/govern"
)

// The Wordfence gap, under monitoring.
//
// A web shell is the visible half of an intrusion; the half that survives
// cleanup is OS-level persistence — an authorized_keys entry, a crontab line, a
// shell rc launcher. None of it lives under the webroot, so inotify on the
// docroot cannot see any of it.
//
// That layer was covered only by the periodic full sweep, and adopting the EDR
// model set the rescan interval to zero. The daemon therefore watched exactly
// the one layer an ordinary file scanner already covers. These tests pin the
// restored coverage: a drop that happens WHILE the monitor runs must be
// reported without waiting for anyone to start a scan.

func osMonAgent(t *testing.T, root, home string) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileSafe)
	a, err := New(Config{
		Mode: "monitor", Webroot: root, Home: home,
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		// SkipOS deliberately false: the OS layer is the subject.
		SkipDB: true, SkipNet: true, SkipProbe: true, SkipProvenance: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	// Suppress the container-start heuristic, which fires on every file a test
	// creates inside a fresh namespace.
	a.env = nil
	return a
}

// An SSH key added after the agent is installed is the classic "I still have
// access after you cleaned the shell" move.
func TestMonitorDetectsAuthorizedKeyDroppedAfterStart(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}

	a := osMonAgent(t, root, home)
	_, c := startMonitor(t, a)

	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI intruder@elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return c.sawRule("osp.ssh_authorized_key") }, 10*time.Second) {
		t.Fatal("an authorized_keys entry written while monitoring was not detected")
	}
}

// The gsocket shape from the field: a launcher line in .bashrc, disguised as a
// PRNG-seed comment, that re-establishes the channel on every login.
func TestMonitorDetectsShellRCLauncher(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	home := t.TempDir()

	a := osMonAgent(t, root, home)
	_, c := startMonitor(t, a)

	rc := filepath.Join(home, ".bashrc")
	body := "# SEED PRNG.\n" +
		"(exec -a '[kcached]' /home/user/.config/dbus/gs-dbus >/dev/null 2>&1 &)\n"
	if err := os.WriteFile(rc, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return c.sawRule("osp.shellrc_persistence") }, 10*time.Second) {
		t.Fatal("a launcher appended to .bashrc while monitoring was not detected")
	}
}

// $HOME must be watched WITHOUT recursion. Walking it would pull in the webroot
// and every other file the account owns, spending the whole watch budget on
// directories the webroot roots already cover.
func TestOSWatchDirsDoesNotRecurseHome(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".ssh", ".config/systemd/user", "public_html/wp-content/uploads/2024/01"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dirs := osWatchDirs(home)

	var sawHome, sawSSH bool
	for _, d := range dirs {
		if d == home {
			sawHome = true
		}
		if d == filepath.Join(home, ".ssh") {
			sawSSH = true
		}
		if d == filepath.Join(home, "public_html", "wp-content", "uploads", "2024", "01") {
			t.Errorf("osWatchDirs descended into the webroot: %s", d)
		}
	}
	if !sawHome {
		t.Error("$HOME is not watched, so .bashrc and .profile changes are invisible")
	}
	if !sawSSH {
		t.Error("~/.ssh is not watched")
	}
}

// Absent paths are skipped rather than reported. In a managed container most of
// /etc is unwritable and several of these simply do not exist.
func TestOSWatchDirsSkipsMissingPaths(t *testing.T) {
	home := filepath.Join(t.TempDir(), "nonexistent")
	for _, d := range osWatchDirs(home) {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("osWatchDirs returned a path that is not a directory: %s", d)
		}
	}
}

// A package upgrade touching $HOME writes many files. The checks are cheap but
// not free, and running them once per written file on a production host is the
// class of mistake that already cost this project a CPU incident.
func TestOSCheckDebounces(t *testing.T) {
	c := &osCheck{name: "t", debounce: 10 * time.Second}
	base := time.Now()

	if !c.due(base) {
		t.Fatal("the first event must run the check immediately")
	}
	if c.due(base.Add(time.Second)) {
		t.Error("a burst of writes re-ran the check within the debounce window")
	}
	if !c.due(base.Add(11 * time.Second)) {
		t.Error("the check never ran again after the debounce window elapsed")
	}
}

func TestOSGuardOnlyCoversListedDirs(t *testing.T) {
	g := newOSGuard(osWatchTargets(t.TempDir()))
	if g.covers("/home/u/public_html/wp-content") {
		t.Error("a webroot directory was treated as OS persistence, so its files would never be scanned")
	}
}

// A write to .bashrc cannot change what is in ~/.cache, and must not pay for a
// walk of it. Only the tree-walking check may carry the long debounce; the
// cheap file reads must stay responsive.
func TestOSDispatchIsTargeted(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{".ssh", ".config/dbus", ".config/systemd/user"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	byDir := map[string]*osCheck{}
	for _, tg := range osWatchTargets(home) {
		byDir[tg.dir] = tg.check
	}

	if got := byDir[home]; got == nil || got.name != "shellrc" {
		t.Errorf("$HOME routes to %v, want the shellrc check", got)
	}
	if got := byDir[filepath.Join(home, ".ssh")]; got == nil || got.name != "ssh" {
		t.Errorf("~/.ssh routes to %v, want the ssh check", got)
	}
	if got := byDir[filepath.Join(home, ".config", "dbus")]; got == nil || got.name != "implants" {
		t.Errorf("~/.config/dbus routes to %v, want the implants check", got)
	}
	// The expensive one, and only the expensive one, is heavily rate-limited.
	for dir, c := range byDir {
		if c.name == "implants" && c.debounce != osWalkDebounce {
			t.Errorf("%s: the tree-walking check has debounce %s, want %s", dir, c.debounce, osWalkDebounce)
		}
		if c.name != "implants" && c.debounce != osFileDebounce {
			t.Errorf("%s: %s has debounce %s, want %s", dir, c.name, c.debounce, osFileDebounce)
		}
	}
}

// Directories triggering the same check must share one rate limit, or ~/bin and
// ~/.local/bin could alternate and defeat it.
func TestOSChecksShareDebounceAcrossDirs(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{"bin", ".local/bin"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	byDir := map[string]*osCheck{}
	for _, tg := range osWatchTargets(home) {
		byDir[tg.dir] = tg.check
	}
	a, b := byDir[filepath.Join(home, "bin")], byDir[filepath.Join(home, ".local", "bin")]
	if a == nil || b == nil {
		t.Fatal("both bin directories should be watched")
	}
	if a != b {
		t.Error("~/bin and ~/.local/bin hold separate rate limits, so they can take turns walking the tree")
	}
}

// The field miss. An implant was dropped into ~/.config/dbus/gs-dbus while the
// monitor was running and produced nothing, because that directory did not
// exist when the watches were registered — the intruder created it. Watching
// only what exists at startup means the interesting directories, the ones an
// attacker makes, are exactly the ones nobody is watching.
func TestMonitorDetectsImplantInDirectoryCreatedAfterStart(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	home := t.TempDir() // deliberately has no .config at all

	a := osMonAgent(t, root, home)
	_, c := startMonitor(t, a)

	dbus := filepath.Join(home, ".config", "dbus")
	if err := os.MkdirAll(dbus, 0o755); err != nil {
		t.Fatal(err)
	}
	// An executable with no extension, which is what gs-dbus is.
	if err := os.WriteFile(filepath.Join(dbus, "gs-dbus"), []byte("\x7fELF payload"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool { return c.sawRule("osp.hidden_executable") }, 90*time.Second) {
		t.Fatal("an implant dropped into a directory created after startup was not detected")
	}
}

// The mkdir race, at the OS layer: `mkdir -p x && cp implant x/` completes long
// before the watch for x can be registered, so the write generates no event.
func TestMonitorSweepsAnOSDirectoryPopulatedBeforeItsWatchLands(t *testing.T) {
	root := t.TempDir()
	scaffold(t, root)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}

	a := osMonAgent(t, root, home)
	_, c := startMonitor(t, a)

	// Create the directory with its payload already inside, as an archive
	// extraction or a cp does.
	staging := filepath.Join(home, ".config", ".staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "gs-dbus"), []byte("\x7fELF payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staging, filepath.Join(home, ".config", "dbus")); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool { return c.sawRule("osp.hidden_executable") }, 90*time.Second) {
		t.Fatal("a directory that arrived already populated was never examined")
	}
}

// A suppressed run must be owed, not lost. `mkdir dbus && cp implant dbus/`
// fires the directory event first; if that consumed the debounce and the write
// were simply dropped, an implant directory — written exactly once — would
// never be examined at all.
func TestSuppressedOSCheckIsDeferredNotDropped(t *testing.T) {
	var runs int
	c := &osCheck{
		name: "t", debounce: 10 * time.Second,
		run: func(*Agent, context.Context) { runs++ },
	}
	base := time.Now()

	if !c.due(base) {
		t.Fatal("the first event must run immediately")
	}
	if c.due(base.Add(time.Second)) {
		t.Fatal("the second event should have been suppressed")
	}
	if c.takePending(base.Add(2 * time.Second)) {
		t.Error("a deferred run fired before its window closed")
	}
	if !c.takePending(base.Add(11 * time.Second)) {
		t.Error("the deferred run was dropped; the write that triggered it is never examined")
	}
	if c.takePending(base.Add(12 * time.Second)) {
		t.Error("the deferred run fired twice")
	}
}

// Cron cannot be watched and must not be listed as if it were. The spool
// directory is mode 1730 root:crontab — writable through crontab(1), not
// listable — so inotify_add_watch fails with EACCES, and the authoritative
// source is `crontab -l` in any case.
func TestCronIsPolledNotWatched(t *testing.T) {
	for _, d := range osWatchDirs(t.TempDir()) {
		if strings.Contains(filepath.ToSlash(d), "/var/spool/cron") {
			t.Errorf("cron spool %s is registered for inotify, which cannot work; it must be polled", d)
		}
	}
}
