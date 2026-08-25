//go:build linux

package agent

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"wordeye/internal/model"
)

// Real-time monitoring.
//
// A periodic scan finds a shell dropped at 03:00 whenever the next sweep runs.
// Watching the filesystem finds it as it is written. Same rule engine, same
// heuristics — the only difference is what triggers evaluation.
//
// The mask is deliberately narrow. IN_CLOSE_WRITE fires when a writer closes
// the file, which means the content is complete; watching IN_MODIFY instead
// would evaluate half-written files and produce noise. IN_MOVED_TO catches the
// common "upload to temp, then rename into place" pattern, which never emits a
// write event for the final path at all.
const inotifyMask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO |
	syscall.IN_CREATE | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

// Watch budget.
//
// Every watch consumes a kernel object from a per-user budget
// (fs.inotify.max_user_watches), and exhausting it breaks OTHER software on the
// box — a monitoring tool must never do that. But a fixed conservative cap is
// its own failure: a field run registered 6,000 watches against a webroot of
// 21,439 directories and silently left 72% of the tree uncovered, including the
// directories the operator was writing test shells into. The daemon was healthy,
// the pipeline worked, and it saw nothing.
//
// So the budget is derived from the kernel's actual limit, and the walk is
// ordered by risk so that the directories malware is actually dropped into are
// registered before any budget runs out.
const (
	// watchBudgetShare is the fraction of the per-user limit we will consume.
	// Half leaves room for whatever else on the host uses inotify.
	watchBudgetShare = 2
	// watchFloor/watchCeiling bound the derived figure. The floor keeps a
	// misreported limit from disabling monitoring; the ceiling keeps a very
	// large limit from letting one site's media library consume everything.
	watchFloor   = 4000
	watchCeiling = 100000
)

// inertDirs are never watched. They hold data and third-party assets, are
// enormous on a real site, and are not where PHP gets executed from.
//
// uploads/ is deliberately ABSENT: it is the single most common place a shell
// is dropped, so excluding it to save budget would remove real-time cover from
// exactly the tree that needs it most. It is instead visited LAST, so it
// competes for leftover budget rather than consuming it first.
var inertDirs = map[string]bool{
	"node_modules": true, "vendor": true, "cache": true, ".cache": true,
	".git": true, ".svn": true, "ai1wm-backups": true, "updraft": true,
	"backups": true, "backup": true, "wpvividbackups": true,
	"et-cache": true, "w3tc-config": true, "wflogs": true,
}

// watchLimit reads the kernel's per-user inotify budget and returns the share
// this process will use. Falls back to the floor when the value is unreadable.
func watchLimit() int {
	b, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err != nil {
		return watchFloor
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return watchFloor
	}
	n /= watchBudgetShare
	if n < watchFloor {
		n = watchFloor
	}
	if n > watchCeiling {
		n = watchCeiling
	}
	return n
}

// watchRoots returns the subtrees to register, highest risk first.
//
// Order is the whole point. If the budget runs out it must run out in the
// media library, never in mu-plugins — a shell in wp-content/mu-plugins loads
// on every request and is invisible in the admin UI, while an unwatched
// uploads directory is still swept every rescan interval.
func watchRoots(webroot string) []string {
	rel := []string{
		".", // the docroot itself: index.php, wp-config.php, drop-ins
		"wp-content/mu-plugins",
		"wp-content",
		"wp-content/plugins",
		"wp-content/themes",
		"wp-includes",
		"wp-admin",
		"wp-content/uploads", // last: biggest, and covered by the backstop sweep
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		p := filepath.Join(webroot, filepath.FromSlash(r))
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

type watcher struct {
	fd     int
	budget int
	mu     sync.RWMutex
	paths  map[int32]string // watch descriptor -> directory
	// byPath is the reverse index.
	//
	// It exists because the obvious implementation — scanning `paths` to ask
	// "is this directory already watched?" — is O(n) per lookup and therefore
	// O(n^2) over a walk. On a 21,439-directory webroot that measured as
	// roughly 460 million string comparisons under a lock, burning ~2.8 cores
	// on a live production host and starving the event loop so that real
	// writes went undetected. A map makes the same question O(1).
	byPath  map[string]int32
	agent   *Agent
	dropped int
}

// Monitor runs the agent as a daemon until ctx is cancelled. Findings stream to
// the configured sink as they occur; a full sweep also runs at rescan intervals
// as a backstop for anything inotify missed (watch exhaustion, remote
// filesystems, events during a restart).
func (a *Agent) Monitor(ctx context.Context, rescan time.Duration) error {
	if a.cfg.Webroot == "" {
		return fmt.Errorf("monitor requires a webroot")
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	defer syscall.Close(fd)

	budget := watchLimit()
	w := &watcher{fd: fd, budget: budget,
		paths: map[int32]string{}, byPath: map[string]int32{}, agent: a}

	// Highest-risk trees first, so an exhausted budget costs coverage in the
	// media library rather than in mu-plugins.
	// Roots overlap by design: wp-content contains plugins, themes and
	// uploads, all of which are listed separately so that risk order is
	// explicit. Walking a root whose tree an earlier root already covered
	// would re-traverse tens of thousands of directories for nothing.
	added := 0
	for _, root := range watchRoots(a.cfg.Webroot) {
		if w.watching(root) {
			continue
		}
		added += w.addTree(root)
	}

	// The OS layer. inotify on the webroot cannot see an authorized_keys entry,
	// a crontab line or a shell rc hook, and those are what keep an intruder on
	// the host after the shell is removed. Watched non-recursively, so this
	// costs a handful of watches rather than a second tree walk.
	osTargets := osExistingWatchTargets(a.cfg.Home)
	osAdded := 0
	for _, t := range osTargets {
		if w.addDir(t.dir) {
			osAdded++
		}
	}
	guard := newOSGuard(osWatchTargets(a.cfg.Home))

	state, reason := model.CheckOK, fmt.Sprintf(
		"watching %d directories (budget %d) plus %d OS persistence paths", added, budget, osAdded)
	if w.dropped > 0 {
		// Partial cover is not success. Say so in the check state, or an
		// operator reads "ok" and believes the whole tree is watched.
		state = model.CheckUnavailable
		reason = fmt.Sprintf(
			"watching %d directories and %d OS persistence paths; %d skipped over the %d-watch budget — those trees are covered only by the %s backstop sweep",
			added, osAdded, w.dropped, budget, rescan)
	}
	a.rep.AddCheck(model.CheckStatus{ID: "monitor.watch", State: state, Reason: reason})

	// The report is never emitted in monitor mode, so this is the only place
	// an operator can learn how much of the tree is actually covered.
	a.setMonitorWatchSummary(reason)

	// Periodic full sweep.
	//
	// inotify sees FILE WRITES IN THE WEBROOT and nothing else. Everything this
	// tool exists to catch beyond that is invisible to it: a payload in an
	// autoloaded wp_option, a malicious cron event, a rogue administrator, an
	// application password, a search-console token, an LD_PRELOAD implant, an
	// authorized_keys entry, a covert outbound channel. None of those touch a
	// file under the webroot, which is exactly why they defeat file scanners.
	//
	// This previously ran only scanFilesystem, so a monitoring daemon covered
	// the one layer a file scanner already covers and silently omitted every
	// layer that made the tool worth running. It now performs the SAME full
	// check set as a scheduled scan, honouring the operator's --skip flags.
	//
	// It also runs once at startup rather than waiting a full interval, so an
	// operator learns the host's current state on day one rather than six hours
	// in — and so provenance is loaded, which the real-time path needs in order
	// to exonerate files that match their published release.
	if rescan > 0 {
		go func() {
			a.fullSweep(ctx)
			t := time.NewTicker(rescan)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					a.fullSweep(ctx)
				}
			}
		}()
	} else {
		// rescan == 0 disables the timer (used by tests), but provenance is
		// still needed or every real-time detection loses its exoneration.
		if !a.cfg.SkipProvenance {
			a.loadProvenance(ctx)
		}
	}

	hit := make([]bool, a.set.NumPatterns())
	buf := make([]byte, 0, 256<<10)
	sc := &heurScratch{}
	evbuf := make([]byte, 64<<10)

	// Coalesce repeated events for the same path: editors and deployment tools
	// touch a file several times in quick succession, and evaluating each one
	// would multiply the work for no extra signal.
	recent := map[string]time.Time{}

	// A process start writes no file, so the masquerade check cannot be driven
	// by events. The read below wakes every 150ms when idle, which makes a
	// deadline check here cheaper and simpler than a second goroutine.
	nextProcPoll := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if now := time.Now(); !now.Before(nextProcPoll) {
			nextProcPoll = now.Add(procPollInterval)
			a.pollVolatileOS(ctx)
		}
		guard.drain(a, ctx, time.Now())

		n, err := syscall.Read(fd, evbuf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(150 * time.Millisecond):
				}
				continue
			}
			return fmt.Errorf("inotify read: %w", err)
		}

		now := time.Now()
		for _, ev := range parseInotify(evbuf[:n]) {
			dir := w.pathFor(ev.wd)
			if dir == "" {
				continue
			}
			full := filepath.Join(dir, ev.name)

			// A newly created directory needs its own watch, or everything
			// written inside it is invisible.
			//
			// Adding the watch is not enough on its own. Between the mkdir and
			// the watch landing there is a window in which files can be created
			// unobserved, and `mkdir x && cp shell.php x/` closes that window
			// in microseconds — which is exactly the shape of a dropper or an
			// archive extraction. Measured, that sequence was missed entirely.
			//
			// So the new subtree is also SWEPT once: anything already inside it
			// is evaluated immediately rather than waiting for the next
			// backstop pass hours later.
			// OS persistence locations first. The webroot handling below
			// walks and content-scans a newly created tree, which is right for
			// wp-content and badly wrong for a new directory under $HOME.
			if guard.covers(dir) {
				// A persistence directory that did not exist at startup has
				// just appeared: `mkdir -p ~/.config/dbus` then drop the
				// implant. Watch it now, and run its check immediately, since
				// the payload may already be inside.
				if ev.mask&syscall.IN_CREATE != 0 {
					if fi, err := os.Stat(full); err == nil && fi.IsDir() {
						if c, ok := guard.wants(full); ok {
							w.addDir(full)
							// Only run now if something is ALREADY inside —
							// that is the mkdir race, where the payload landed
							// before the watch did and no write event will
							// ever arrive. When the directory is still empty,
							// leave the debounce untouched so the write that
							// follows in the next microsecond triggers a run
							// of its own instead of being suppressed by this
							// one.
							if dirHasEntries(full) && c.due(now) {
								c.run(a, ctx)
							}
						}
					}
				}
				guard.handle(a, ctx, dir, now)
				continue
			}

			if ev.mask&syscall.IN_CREATE != 0 {
				if fi, err := os.Stat(full); err == nil && fi.IsDir() {
					w.addTree(full)
					a.sweepNewTree(ctx, full, hit, &buf, sc)
					continue
				}
			}
			if ev.mask&(syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0 {
				w.remove(ev.wd)
				continue
			}
			if ev.name == "" {
				continue
			}
			if last, ok := recent[full]; ok && now.Sub(last) < 2*time.Second {
				continue
			}
			recent[full] = now
			if len(recent) > 4096 {
				for k, t := range recent {
					if now.Sub(t) > time.Minute {
						delete(recent, k)
					}
				}
			}

			a.evaluatePath(ctx, full, hit, &buf, sc)
		}
	}
}

// fullSweep runs the complete check set — filesystem, WordPress, OS
// persistence, memory, network, database, cloak probe — exactly as a scheduled
// scan does, honouring the operator's --skip flags.
//
// Accumulated state is cleared first. Findings have already left through the
// sink, so keeping them serves no purpose and would grow without bound in a
// process expected to run for months. The dedupe set is cleared with them, so
// anything still present is reported again on each sweep: that is what keeps a
// console's "last seen" honest about a shell that is still on disk, rather than
// showing it once and never mentioning it again.
func (a *Agent) fullSweep(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	a.rep.Reset()
	a.ww.reset()
	// Clear in place. Assigning a fresh sync.Map replaced the value while the
	// process poller was calling LoadOrStore on it from another goroutine —
	// caught by the race detector once the two ran concurrently. Clear mutates
	// under the map's own synchronisation, which is what makes it safe.
	a.seen.Clear()
	a.runScan(ctx)

	// Re-assert real-time coverage after the reset. Every report this daemon
	// produces must say how much of the tree inotify actually watches —
	// otherwise a console shows a clean sweep with no indication that 72% of
	// the webroot has no real-time cover at all.
	if s := a.MonitorWatchSummary(); s != "" {
		state := model.CheckOK
		if strings.Contains(s, "skipped") {
			state = model.CheckUnavailable
		}
		a.rep.AddCheck(model.CheckStatus{ID: "monitor.watch", State: state, Reason: s})
	}
}

// sweepNewTreeMax bounds the catch-up sweep of a newly created directory. An
// attacker's drop is a handful of files; a plugin install is thousands. Both
// get looked at, but the second must not stall the event loop — the remainder
// is covered by the backstop sweep.
const sweepNewTreeMax = 512

// sweepNewTree evaluates files already present in a directory that has just
// appeared, closing the race between mkdir and the watch being registered.
func (a *Agent) sweepNewTree(ctx context.Context, root string, hit []bool, buf *[]byte, sc *heurScratch) {
	n := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || ctx.Err() != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (alwaysSkipDir[d.Name()] || inertDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if n >= sweepNewTreeMax {
			return filepath.SkipAll
		}
		n++
		a.evaluatePath(ctx, p, hit, buf, sc)
		return nil
	})
}

// evaluatePath runs the full detection pipeline against a single file. This is
// the same code path the batch scan uses, so a real-time detection and a
// scheduled one are identical in quality.
func (a *Agent) evaluatePath(ctx context.Context, abs string, hit []bool, buf *[]byte, sc *heurScratch) {
	fi, err := os.Lstat(abs)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	rel, err := filepath.Rel(a.cfg.Webroot, abs)
	if err != nil {
		return
	}
	rel = filepath.ToSlash(rel)
	if a.set.Excluded("/" + rel) {
		return
	}
	// Clear the dedupe entry so a file that is rewritten alerts again: the
	// second write may be the malicious one.
	a.seen.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok && strings.HasSuffix(s, "\x00"+rel) {
			a.seen.Delete(k)
		}
		return true
	})
	_, _, _ = a.analyzeFile(ctx, fileJob{abs: abs, rel: rel, info: fi}, hit, buf, sc)
}

// addTree registers watches for a directory and everything beneath it.
func (w *watcher) addTree(root string) int {
	added := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if p != root && (alwaysSkipDir[name] || inertDirs[name] ||
			(w.agent.cfg.Quick && quickSkipDir[name])) {
			return filepath.SkipDir
		}
		w.mu.RLock()
		count := len(w.paths)
		w.mu.RUnlock()
		if count >= w.budget {
			w.dropped++
			return filepath.SkipDir
		}
		if w.watching(p) {
			// Roots overlap by design (wp-content contains plugins/themes), and
			// re-adding a path returns the SAME descriptor, which would corrupt
			// the count and the descriptor map.
			return nil
		}
		wd, err := syscall.InotifyAddWatch(w.fd, p, inotifyMask)
		if err != nil {
			// ENOSPC means the per-user watch budget is exhausted. Degrade to
			// the periodic sweep rather than failing outright.
			w.dropped++
			return nil
		}
		w.mu.Lock()
		w.paths[int32(wd)] = p
		w.byPath[p] = int32(wd)
		w.mu.Unlock()
		added++
		return nil
	})
	return added
}

// watching reports whether a directory already holds a watch.
func (w *watcher) watching(p string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.byPath[p]
	return ok
}

func (w *watcher) pathFor(wd int32) string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.paths[wd]
}

func (w *watcher) remove(wd int32) {
	w.mu.Lock()
	if p, ok := w.paths[wd]; ok {
		delete(w.byPath, p)
	}
	delete(w.paths, wd)
	w.mu.Unlock()
}

type inEvent struct {
	wd   int32
	mask uint32
	name string
}

// parseInotify decodes the packed event stream the kernel returns. Events are
// variable length: a fixed 16-byte header followed by Len bytes of NUL-padded
// name.
func parseInotify(b []byte) []inEvent {
	var out []inEvent
	const hdr = syscall.SizeofInotifyEvent // 16
	for off := 0; off+hdr <= len(b); {
		raw := (*syscall.InotifyEvent)(unsafe.Pointer(&b[off]))
		e := inEvent{wd: raw.Wd, mask: raw.Mask}
		nameStart := off + hdr
		nameEnd := nameStart + int(raw.Len)
		if raw.Len > 0 && nameEnd <= len(b) {
			e.name = strings.TrimRight(string(b[nameStart:nameEnd]), "\x00")
		}
		out = append(out, e)
		off = nameEnd
		if raw.Len == 0 {
			off = nameStart
		}
	}
	return out
}
