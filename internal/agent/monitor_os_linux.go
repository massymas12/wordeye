//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// OS-level persistence under real-time monitoring.
//
// inotify on the webroot sees web shells. It cannot see the layer that actually
// keeps an intruder on a box: an authorized_keys entry, a crontab line, a shell
// rc hook, a systemd user unit, an LD_PRELOAD implant. None of those touch a
// file under the docroot, which is precisely why file scanners miss them and
// why closing that gap was the point of this product.
//
// That layer used to be covered only by the periodic full sweep. Adopting the
// EDR model set the rescan interval to zero — correctly, because a timed full
// sweep is what drove a production host to 2.2x load — and in doing so removed
// the only steady-state coverage of OS persistence. Watching these paths
// directly restores it for a few dozen watches instead of a recurring
// whole-filesystem walk.
//
// A gsocket deployment lands in exactly these places:
//
//	crontab                base64 | bash, then exec -a [kcached]
//	.bashrc                a launcher line disguised as a PRNG-seed comment
//	.config/dbus/gs-dbus   the implant binary and its key file
//	[kcached] process      argv0 lying about /usr/bin/sleep
//
// The first three are file writes and are caught here as they happen. The
// fourth is not a file event at all: a process can start without anything being
// written, so it needs a poll. Both are wired up below.

// osTarget binds a watched directory to the check that could possibly care
// about a write there.
//
// Running all seven persistence checks on every OS event would be wasteful and,
// in one case, genuinely costly: checkHiddenImplants walks ~/.config, ~/.local,
// ~/.cache and ~/.fonts, and a large package cache is not free to traverse. A
// new line in .bashrc cannot change what is in ~/.cache, so it must not pay for
// a walk. Each directory therefore triggers only the check it can affect, and
// the walking check carries a longer debounce than the file reads.
type osTarget struct {
	dir   string
	check *osCheck
}

// osCheck is one persistence check plus its rate limit. Instances are SHARED
// between directories that trigger the same check, so ~/bin and ~/.local/bin
// cannot take turns defeating the debounce.
type osCheck struct {
	name     string
	run      func(*Agent, context.Context)
	debounce time.Duration
	mu       sync.Mutex
	last     time.Time
	pending  bool
}

// due reports whether enough time has passed to run again.
//
// A suppressed run is DEFERRED, not dropped. The original implementation simply
// returned false, which is wrong in the case that matters: `mkdir -p
// ~/.config/dbus && cp implant ~/.config/dbus/gs-dbus` fires the directory
// event first, and if that consumes the window the file write is discarded. If
// nothing ever writes to that directory again — and an implant directory is
// written once — the payload is never examined at all. Marking it pending means
// the check runs as soon as the window closes, so the worst case is a bounded
// delay rather than a permanent miss.
func (c *osCheck) due(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.last.IsZero() && now.Sub(c.last) < c.debounce {
		c.pending = true
		return false
	}
	c.last = now
	c.pending = false
	return true
}

// takePending reports whether a deferred run is now owed, and claims it.
func (c *osCheck) takePending(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.pending || now.Sub(c.last) < c.debounce {
		return false
	}
	c.last = now
	c.pending = false
	return true
}

const (
	// Reading a handful of small config files. Cheap enough to run promptly.
	osFileDebounce = 5 * time.Second
	// Walking four hidden trees to depth+3. The only OS check with a cost that
	// scales with the host rather than with a fixed file list, so it gets a
	// much longer floor.
	osWalkDebounce = 60 * time.Second
	// procPollInterval covers what inotify structurally cannot see. Reading
	// /proc for a few dozen processes is sub-millisecond work — the field host
	// examined 47 — so this stays affordable for a resident agent in a way a
	// filesystem sweep never was.
	procPollInterval = 60 * time.Second
)

// osWatchTargets maps each OS persistence location to its check.
//
// Every directory is watched WITHOUT recursion. $HOME especially must never be
// walked: it contains the webroot and everything else the account owns, so
// adding its tree would spend the whole watch budget re-covering files the
// webroot roots already watch.
//
// Paths that do not exist are skipped rather than created. In a managed
// container most of /etc is not writable by this user and several of these will
// be absent; that is information, not an error.
func osWatchTargets(home string) []osTarget {
	shellrc := &osCheck{name: "shellrc", debounce: osFileDebounce,
		run: func(a *Agent, _ context.Context) { _, _ = a.checkShellRC() }}
	ssh := &osCheck{name: "ssh", debounce: osFileDebounce,
		run: func(a *Agent, _ context.Context) { _, _ = a.checkSSH() }}
	systemd := &osCheck{name: "systemd", debounce: osFileDebounce,
		run: func(a *Agent, _ context.Context) { _, _ = a.checkSystemdUser() }}
	implants := &osCheck{name: "implants", debounce: osWalkDebounce,
		run: func(a *Agent, _ context.Context) { _, _ = a.checkHiddenImplants() }}
	preload := &osCheck{name: "preload", debounce: osFileDebounce,
		run: func(a *Agent, _ context.Context) { _, _ = a.checkPreload() }}
	cron := &osCheck{name: "cron", debounce: osFileDebounce,
		run: func(a *Agent, ctx context.Context) { _, _ = a.checkCron(ctx) }}
	_ = preload

	var out []osTarget
	if home != "" {
		out = append(out,
			osTarget{home, shellrc},                                              // .bashrc, .profile, .zshrc
			osTarget{filepath.Join(home, ".ssh"), ssh},                           // authorized_keys, config
			osTarget{filepath.Join(home, ".config"), implants},                   // parent: sees dbus/ appear
			osTarget{filepath.Join(home, ".config", "systemd", "user"), systemd}, // user units
			osTarget{filepath.Join(home, ".config", "autostart"), implants},
			osTarget{filepath.Join(home, ".config", "dbus"), implants}, // the gsocket implant path
			osTarget{filepath.Join(home, ".local"), implants},          // parent: sees bin/ appear
			osTarget{filepath.Join(home, ".local", "bin"), implants},
			osTarget{filepath.Join(home, "bin"), implants},
		)
	}
	// /etc/cron.d must trigger the CRON check, not the preload one.
	//
	// It was wired to preload, which reads /etc/ld.so.preload and a few shell
	// rc files and never looks at cron at all — so a root cron launcher dropped
	// while the monitor ran fired inotify, re-scanned four unrelated files,
	// emitted nothing, and burned the debounce. The real-time path for the one
	// watchable cron directory was dead, leaving only the 60-second poll.
	out = append(out, osTarget{"/etc/cron.d", cron})
	return out
}

// osExistingWatchTargets is the subset that can be watched right now.
//
// The rest are not discarded: a directory that does not exist yet is the
// interesting case. An intruder runs `mkdir -p ~/.config/dbus` and drops an
// implant into it, and a watcher that only ever registered directories present
// at startup sees none of that. The guard keeps every candidate so the watch
// can be added the moment the directory appears.
func osExistingWatchTargets(home string) []osTarget {
	all := osWatchTargets(home)
	out := make([]osTarget, 0, len(all))
	for _, t := range all {
		if fi, err := os.Stat(t.dir); err == nil && fi.IsDir() {
			out = append(out, t)
		}
	}
	return out
}

// osWatchDirs is the plain directory list, for watch registration.
func osWatchDirs(home string) []string {
	targets := osExistingWatchTargets(home)
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.dir)
	}
	return out
}

// addDir watches exactly one directory and does not descend.
func (w *watcher) addDir(p string) bool {
	if w.watching(p) {
		return false
	}
	w.mu.RLock()
	exhausted := len(w.paths) >= w.budget
	w.mu.RUnlock()
	if exhausted {
		w.dropped++
		return false
	}
	wd, err := syscall.InotifyAddWatch(w.fd, p, inotifyMask)
	if err != nil {
		// Unreadable system directories are the common case in a container.
		w.dropped++
		return false
	}
	w.mu.Lock()
	w.paths[int32(wd)] = p
	w.byPath[p] = int32(wd)
	w.mu.Unlock()
	return true
}

// osGuard routes an event to the one check that could care about it.
type osGuard struct {
	byDir map[string]*osCheck
}

func newOSGuard(targets []osTarget) *osGuard {
	m := make(map[string]*osCheck, len(targets))
	for _, t := range targets {
		m[t.dir] = t.check
	}
	return &osGuard{byDir: m}
}

// covers reports whether a watched directory is an OS persistence location.
func (g *osGuard) covers(dir string) bool {
	if g == nil {
		return false
	}
	_, ok := g.byDir[dir]
	return ok
}

// wants reports whether a directory is a persistence location we would watch if
// it existed. Used to pick up ~/.config/dbus at the moment it is created.
func (g *osGuard) wants(dir string) (*osCheck, bool) {
	if g == nil {
		return nil, false
	}
	c, ok := g.byDir[dir]
	return c, ok
}

// drain runs any check whose deferred work is now owed. Called from the event
// loop, which wakes every 150ms when idle, so a deferred run lands promptly
// after its window closes rather than waiting for the next write.
func (g *osGuard) drain(a *Agent, ctx context.Context, now time.Time) {
	if g == nil || a.cfg.SkipOS {
		return
	}
	seen := make(map[*osCheck]bool, len(g.byDir))
	for _, c := range g.byDir {
		if seen[c] {
			continue
		}
		seen[c] = true
		if c.takePending(now) {
			c.run(a, ctx)
		}
	}
}

// handle runs the check for dir, if one is mapped and its debounce has expired.
func (g *osGuard) handle(a *Agent, ctx context.Context, dir string, now time.Time) bool {
	if g == nil || a.cfg.SkipOS {
		return false
	}
	c, ok := g.byDir[dir]
	if !ok || !c.due(now) {
		return false
	}
	c.run(a, ctx)
	return true
}

// pollVolatileOS covers the persistence that inotify structurally cannot see.
//
// Two things live here, for two different reasons.
//
// Processes: a process start writes no file. argv0 is attacker-controlled —
// exec -a rewrites it freely — while /proc/PID/exe is maintained by the kernel
// and cannot be forged from userspace, so comparing them exposes the
// kernel-thread masquerade ([kcached] over /usr/bin/sleep) with no file event
// to trigger on.
//
// Cron: the authoritative source is `crontab -l`, a COMMAND, and the spool
// directory behind it is typically mode 1730 root:crontab. A normal user may
// write to it through crontab(1) but may not list it, so inotify_add_watch
// fails with EACCES and the watch is silently dropped. A field deployment
// confirmed this: a crontab launcher was installed while the monitor ran and
// produced no event at all, while the .bashrc hook beside it was caught
// immediately. Cron cannot be watched; it has to be asked.
//
// Both are cheap. The field host examined 47 processes, and `crontab -l`
// returns a few lines.
func (a *Agent) pollVolatileOS(ctx context.Context) {
	if a.cfg.SkipOS {
		return
	}
	if procs := readProcs(); len(procs) > 0 {
		a.setProcCache(procs)
		a.checkProcessIdentity(procs)
	}
	_, _ = a.checkCron(ctx)
}

// dirHasEntries reports whether a directory already contains anything. Used to
// distinguish "created empty, a write is coming" from "created and populated
// before the watch landed".
func dirHasEntries(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	names, _ := f.Readdirnames(1)
	return len(names) > 0
}
