package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wordeye/internal/model"
)

// Containment.
//
// Three failure modes make naive cleanup useless, and the ordering below exists
// entirely to defeat them:
//
//  1. Deleting a web shell does not stop a process that is already running.
//     A beacon holding an open socket keeps beaconing from a deleted inode.
//  2. Killing the process does not stop the thing that launched it. Cron or an
//     rc file restarts it within the minute, and the only thing achieved is
//     telling the operator their detection worked.
//  3. Deleting a PHP file does not stop its compiled bytecode. OPcache keeps
//     serving the malware, and a long-lived FPM worker that eval'd a shell into
//     memory survives the file's removal entirely.
//
// Hence: neutralise persistence, THEN freeze, THEN capture, THEN kill, THEN
// verify no respawn, THEN flush the bytecode cache.
//
// Freezing before capturing matters. SIGSTOP suspends the process so it cannot
// react, fork, or clean up while its memory maps, open sockets and environment
// are read — all of which vanish the instant it is killed.
//
// Every destructive step is followed by an HTTP health check. If the site was
// serving before the action and is not serving after it, the action is rolled
// back and the sequence aborts. Combined with quarantine-by-move (never rm),
// that makes the whole engine reversible by construction.

// Processes that must never be signalled. Killing any of these takes the site
// down more effectively than the malware would.
var protectedProcs = []string{
	"systemd", "init", "sshd", "php-fpm", "nginx", "apache2", "httpd",
	"mysqld", "mariadbd", "lsphp", "litespeed", "dbus", "cron", "crond",
	"rsyslog", "docker", "containerd", "kthreadd",
}

func (a *Agent) evidenceDir() string {
	if a.cfg.EvidenceDir != "" {
		return a.cfg.EvidenceDir
	}
	stamp := a.rep.StartedAt.Format("20060102_150405")
	return filepath.Join(a.cfg.Home, ".wordeye", "evidence",
		fmt.Sprintf("%s_%s", sanitize(a.rep.Host), stamp))
}

func (a *Agent) runContainment(ctx context.Context) {
	dry := a.cfg.ContainDryRun
	maxActions := a.cfg.MaxActions
	if maxActions <= 0 {
		maxActions = 25
	}

	evDir := a.evidenceDir()
	if !dry {
		if err := os.MkdirAll(evDir, 0o700); err != nil {
			a.rep.AddContain(model.ContainAction{
				Kind: "setup", Target: evDir, Executed: true, Success: false,
				Error: "cannot create evidence directory: " + err.Error(),
			})
			return
		}
	}

	// --- Health baseline ---------------------------------------------------
	// Everything downstream is judged against this. Without it we cannot tell
	// "we broke the site" from "the site was already broken".
	baseline := a.probeHealth(ctx)
	a.rep.AddContain(model.ContainAction{
		Kind: "verify", Target: "site health baseline", Executed: true,
		Success: baseline.serving(), Detail: baseline.String(),
	})
	gateActive := baseline.serving()
	if !gateActive {
		a.rep.AddContain(model.ContainAction{
			Kind: "verify", Target: "health gate", Executed: false, Success: false,
			Detail: "Site was not serving before containment began, so the health gate cannot attribute a later failure to our actions. Destructive steps proceed without automatic rollback — review manually.",
		})
	}

	// --- Select targets ----------------------------------------------------
	procTargets, fileTargets := a.selectTargets()

	if len(procTargets) == 0 && len(fileTargets) == 0 {
		a.rep.AddContain(model.ContainAction{
			Kind: "verify", Target: "target selection", Executed: true, Success: true,
			Detail: "Nothing met the containment bar (confirmed confidence and actionable). Heuristic and review-grade findings are never auto-actioned.",
		})
		return
	}

	actions := 0
	budget := func() bool {
		if actions >= maxActions {
			a.rep.AddContain(model.ContainAction{
				Kind: "verify", Target: "circuit breaker", Executed: true, Success: false,
				Detail: fmt.Sprintf("Action limit of %d reached; remaining targets left untouched deliberately.", maxActions),
			})
			return false
		}
		actions++
		return true
	}

	// --- 1. Neutralise persistence ----------------------------------------
	// Must precede the kill, or the launcher simply restarts the payload.
	for _, f := range a.persistenceTargets() {
		if !budget() {
			return
		}
		a.neutralizePersistence(f, evDir, dry)
	}

	// --- 2-5. Freeze, capture, kill, verify --------------------------------
	for _, p := range procTargets {
		if !budget() {
			return
		}
		a.containProcess(ctx, p, evDir, dry)
	}

	// --- 6. Quarantine files, health-gated --------------------------------
	for _, f := range fileTargets {
		if !budget() {
			return
		}
		q, ok := a.quarantineFile(f, evDir, dry)
		if !ok || dry || !gateActive {
			continue
		}
		// Give the web server a moment to notice, then confirm the site still
		// serves. This is the check that makes automated removal safe.
		time.Sleep(400 * time.Millisecond)
		h := a.probeHealth(ctx)
		if h.serving() {
			a.rep.AddContain(model.ContainAction{
				Kind: "verify", Target: f.Path, Executed: true, Success: true,
				Detail: "Site still serving after quarantine — " + h.String(),
			})
			continue
		}
		// Regression: put it back and stop.
		err := restoreQuarantine(q, filepath.Join(a.cfg.Webroot, filepath.FromSlash(f.Path)))
		a.rep.AddContain(model.ContainAction{
			Kind: "verify", Target: f.Path, Executed: true, Success: false,
			Detail: fmt.Sprintf("Site stopped serving after quarantining this file (%s) — ROLLED BACK and aborting containment. The file is likely load-bearing, or the site was already fragile.", h.String()),
			Error:  errString(err),
		})
		return
	}

	// --- 7. Flush compiled bytecode ---------------------------------------
	if len(fileTargets) > 0 {
		a.flushOPcache(ctx, dry)
	}

	final := a.probeHealth(ctx)
	a.rep.AddContain(model.ContainAction{
		Kind: "verify", Target: "site health final", Executed: true,
		Success: final.serving(), Detail: final.String(),
	})
}

// selectTargets applies the confidence bar. Only findings the engine is certain
// about are eligible; heuristic detections inform a human and nothing more.
func (a *Agent) selectTargets() (procs []model.Finding, files []model.Finding) {
	for _, f := range a.rep.Findings {
		if f.Confidence != model.ConfConfirmed {
			continue
		}
		if f.ContainPID > 0 {
			procs = append(procs, f)
			continue
		}
		if f.Actionable && f.Path != "" {
			files = append(files, f)
		}
	}
	return procs, files
}

// persistenceTargets returns confirmed launcher findings, which must be
// disabled before anything is killed.
func (a *Agent) persistenceTargets() []model.Finding {
	var out []model.Finding
	for _, f := range a.rep.Findings {
		switch f.RuleID {
		case "osp.cron_persistence", "osp.shellrc_persistence", "osp.systemd_user_unit", "osp.git_hook":
			if f.Confidence == model.ConfConfirmed || f.Confidence == model.ConfLikely {
				out = append(out, f)
			}
		}
	}
	return out
}

// neutralizePersistence comments out a launcher line, keeping a full backup.
// Commenting rather than deleting means the original is recoverable in place
// and the change is obvious to the next person who reads the file.
func (a *Agent) neutralizePersistence(f model.Finding, evDir string, dry bool) {
	act := model.ContainAction{
		Kind:   "neutralize",
		Target: fmt.Sprintf("%s:%d", f.Path, f.Line),
		Detail: "Comment out the launcher line so the payload cannot respawn after it is killed.",
	}
	if dry {
		a.rep.AddContain(act)
		return
	}
	act.Executed = true

	if f.Path == "" || f.Line <= 0 {
		act.Error = "no file/line recorded for this finding"
		a.rep.AddContain(act)
		return
	}
	orig, err := os.ReadFile(f.Path)
	if err != nil {
		act.Error = err.Error()
		a.rep.AddContain(act)
		return
	}
	backup := filepath.Join(evDir, "persistence", sanitize(strings.TrimPrefix(f.Path, "/")))
	if err := os.MkdirAll(filepath.Dir(backup), 0o700); err == nil {
		_ = os.WriteFile(backup, orig, 0o600)
		act.EvidencePath = backup
	}

	lines := strings.Split(string(orig), "\n")
	if f.Line > len(lines) {
		act.Error = "line number beyond end of file; file changed since the scan"
		a.rep.AddContain(act)
		return
	}
	lines[f.Line-1] = "# wordeye-contained " + time.Now().UTC().Format(time.RFC3339) + " # " + lines[f.Line-1]

	fi, _ := os.Stat(f.Path)
	mode := os.FileMode(0o600)
	if fi != nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(f.Path, []byte(strings.Join(lines, "\n")), mode); err != nil {
		act.Error = err.Error()
	} else {
		act.Success = true
		act.Detail = "Launcher line commented out; original preserved in evidence."
	}
	a.rep.AddContain(act)
}

// containProcess runs the freeze/capture/kill/verify sequence for one PID.
func (a *Agent) containProcess(ctx context.Context, f model.Finding, evDir string, dry bool) {
	pid := f.ContainPID
	comm, _ := f.Meta["comm"].(string)

	if reason, ok := a.processIsProtected(pid, comm); !ok {
		a.rep.AddContain(model.ContainAction{
			Kind: "kill", Target: comm, PID: pid, Executed: false, Success: false,
			Detail: "Refused: " + reason,
		})
		return
	}

	if dry {
		for _, k := range []string{"freeze", "capture", "kill", "verify"} {
			a.rep.AddContain(model.ContainAction{
				Kind: k, Target: comm, PID: pid,
				Detail: dryDetail(k, pid, comm),
			})
		}
		return
	}

	// Guard against PID reuse. The scan happened seconds or minutes ago; if the
	// original process exited and the kernel recycled its PID, signalling now
	// would kill an unrelated — possibly critical — process.
	if !procStillIs(pid, comm) {
		a.rep.AddContain(model.ContainAction{
			Kind: "kill", Target: comm, PID: pid, Executed: false, Success: false,
			Detail: fmt.Sprintf("Refused: pid %d no longer reports comm %q. The process exited and the PID may have been reused.", pid, comm),
		})
		return
	}

	// FREEZE — before anything else, so the process cannot react to being
	// investigated, fork a replacement, or wipe its own artefacts.
	err := signalProcess(pid, sigSTOP)
	a.rep.AddContain(model.ContainAction{
		Kind: "freeze", Target: comm, PID: pid, Executed: true, Success: err == nil,
		Detail: "SIGSTOP — suspends the process so its volatile state can be captured intact.",
		Error:  errString(err),
	})
	if err != nil {
		return
	}

	// CAPTURE — everything that ceases to exist the moment it is killed.
	capDir := filepath.Join(evDir, fmt.Sprintf("proc_%d_%s", pid, sanitize(comm)))
	cerr := captureProcess(pid, capDir)
	a.rep.AddContain(model.ContainAction{
		Kind: "capture", Target: comm, PID: pid, Executed: true, Success: cerr == nil,
		Detail:       "Captured cmdline, exe image, maps, environ, open sockets and cwd.",
		EvidencePath: capDir,
		Error:        errString(cerr),
	})

	// KILL.
	kerr := signalProcess(pid, sigKILL)
	a.rep.AddContain(model.ContainAction{
		Kind: "kill", Target: comm, PID: pid, Executed: true, Success: kerr == nil,
		Detail: "SIGKILL.", Error: errString(kerr),
	})

	// VERIFY — a respawn means persistence was missed, which is more important
	// to report than the kill itself.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2500 * time.Millisecond):
	}
	if again := findRespawn(pid, comm, f.Path); again > 0 {
		a.rep.AddContain(model.ContainAction{
			Kind: "verify", Target: comm, PID: again, Executed: true, Success: false,
			Detail: fmt.Sprintf("RESPAWNED as pid %d. A launcher is still active — the persistence mechanism was not fully neutralised. Hunt cron, rc files, systemd units and at-jobs before retrying.", again),
		})
		return
	}
	a.rep.AddContain(model.ContainAction{
		Kind: "verify", Target: comm, PID: pid, Executed: true, Success: true,
		Detail: "No respawn observed after 2.5s.",
	})
}

// processIsProtected enforces the never-touch list and self-protection.
func (a *Agent) processIsProtected(pid int, comm string) (string, bool) {
	if pid <= 1 {
		return "pid <= 1 is never a valid target", false
	}
	if pid == os.Getpid() || pid == os.Getppid() {
		return "refusing to signal the agent or its parent", false
	}
	lc := strings.ToLower(comm)
	for _, p := range protectedProcs {
		if lc == p || strings.HasPrefix(lc, p) {
			return fmt.Sprintf("%q is on the protected list — killing it would take the site or the host down", comm), false
		}
	}
	return "", true
}

func dryDetail(kind string, pid int, comm string) string {
	switch kind {
	case "freeze":
		return fmt.Sprintf("Would SIGSTOP pid %d (%s) so it cannot react while evidence is captured.", pid, comm)
	case "capture":
		return fmt.Sprintf("Would capture /proc/%d state: cmdline, exe image, maps, environ, sockets, cwd.", pid)
	case "kill":
		return fmt.Sprintf("Would SIGKILL pid %d (%s).", pid, comm)
	default:
		return "Would re-check for a respawn after 2.5s."
	}
}

// ---------------------------------------------------------------------------
// file quarantine
// ---------------------------------------------------------------------------

type quarantined struct {
	from, to string
}

// quarantineFile moves a file into the evidence store with its permissions
// stripped. It never deletes: an incorrect detection has to be recoverable, and
// the file itself is evidence.
func (a *Agent) quarantineFile(f model.Finding, evDir string, dry bool) (quarantined, bool) {
	abs := f.Path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(a.cfg.Webroot, filepath.FromSlash(f.Path))
	}
	// Sanitise before joining: a finding path must never be able to write
	// outside the evidence store. Not reachable today (actionable findings carry
	// walk-relative paths) but this is the kind of assumption that quietly stops
	// holding when a new finding type is later marked actionable.
	dest := filepath.Join(evDir, "quarantine", safeRelPath(f.Path))

	act := model.ContainAction{
		Kind:   "quarantine",
		Target: f.Path,
		Detail: "Move to the evidence store and strip permissions (never deleted, so this is reversible).",
	}
	if dry {
		act.EvidencePath = dest
		a.rep.AddContain(act)
		return quarantined{}, false
	}
	act.Executed = true

	// Re-confirm the file still exists and still hashes to what the scan saw.
	// Between detection and action the site may have changed; acting on stale
	// information is how automation destroys the wrong file.
	cur, err := os.Stat(abs)
	if err != nil {
		act.Error = "file no longer present: " + err.Error()
		a.rep.AddContain(act)
		return quarantined{}, false
	}
	if f.SHA256 != "" {
		if now := hashFile(abs); now != f.SHA256 {
			act.Error = fmt.Sprintf("content changed since detection (was %s, now %s) — refusing to act on stale information", short(f.SHA256), short(now))
			a.rep.AddContain(act)
			return quarantined{}, false
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		act.Error = err.Error()
		a.rep.AddContain(act)
		return quarantined{}, false
	}
	if err := moveFile(abs, dest); err != nil {
		act.Error = err.Error()
		a.rep.AddContain(act)
		return quarantined{}, false
	}
	_ = os.Chmod(dest, 0o400)

	// Chain of custody alongside the artefact.
	meta, _ := json.MarshalIndent(map[string]any{
		"original_path": f.Path,
		"absolute_path": abs,
		"sha256":        f.SHA256,
		"size":          cur.Size(),
		"mode":          cur.Mode().String(),
		"rule_id":       f.RuleID,
		"title":         f.Title,
		"quarantined":   time.Now().UTC().Format(time.RFC3339),
		"host":          a.rep.Host,
		"agent_version": Version,
	}, "", "  ")
	_ = os.WriteFile(dest+".wordeye.json", meta, 0o600)

	act.Success = true
	act.EvidencePath = dest
	a.rep.AddContain(act)
	return quarantined{from: abs, to: dest}, true
}

func restoreQuarantine(q quarantined, original string) error {
	if q.to == "" {
		return nil
	}
	_ = os.Chmod(q.to, 0o644)
	return moveFile(q.to, original)
}

// moveFile renames, falling back to copy+remove across filesystems (the
// evidence directory is often on a different mount from the webroot).
func moveFile(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		return err
	}
	return os.Remove(from)
}

// ---------------------------------------------------------------------------
// OPcache
// ---------------------------------------------------------------------------

// flushOPcache evicts compiled bytecode for removed files.
//
// `php -r opcache_reset()` on the CLI resets the CLI's own cache, not the one
// PHP-FPM is using — they are separate processes with separate shared memory.
// The only way to reach FPM's cache without a restart is to have FPM itself
// execute the call, which means a real HTTP request.
func (a *Agent) flushOPcache(ctx context.Context, dry bool) {
	act := model.ContainAction{
		Kind:   "opcache",
		Target: "PHP-FPM opcache",
		Detail: "Drop a one-shot PHP file, request it through the origin so FPM executes opcache_reset(), then remove it. Cleaning a file does not evict its compiled bytecode.",
	}
	if dry {
		a.rep.AddContain(act)
		return
	}
	act.Executed = true

	if a.cfg.Webroot == "" {
		act.Error = "no webroot"
		a.rep.AddContain(act)
		return
	}
	name := fmt.Sprintf("wordeye_ocflush_%d_%d.php", time.Now().UnixNano(), os.Getpid())
	p := filepath.Join(a.cfg.Webroot, name)
	body := `<?php if(function_exists("opcache_reset")){echo opcache_reset()?"WORDEYE_OC_OK":"WORDEYE_OC_NOCHANGE";}else{echo "WORDEYE_OC_ABSENT";}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		act.Error = "cannot write flush stub: " + err.Error()
		a.rep.AddContain(act)
		return
	}
	// Removed unconditionally, including on every error path below.
	defer os.Remove(p)

	raw := a.siteURL(ctx)
	host := "localhost"
	scheme := "http"
	if raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			host, scheme = u.Hostname(), u.Scheme
		}
	}
	target := "http://127.0.0.1/" + name
	if scheme == "https" {
		target = "https://" + host + "/" + name
	}
	r := fetch(ctx, target, host, browserUA, "", true)
	switch {
	case r.err != nil:
		act.Error = r.err.Error()
		act.Detail = "Could not confirm the flush over HTTP. Restart PHP for this site to be certain the old bytecode is gone."
	case strings.Contains(r.body, "WORDEYE_OC_OK"), strings.Contains(r.body, "WORDEYE_OC_NOCHANGE"):
		act.Success = true
		act.Detail = "OPcache reset through PHP-FPM; compiled malware bytecode evicted."
	case strings.Contains(r.body, "WORDEYE_OC_ABSENT"):
		act.Success = true
		act.Detail = "OPcache is not enabled on this host, so there is no stale bytecode to evict."
	default:
		act.Detail = "Flush stub did not return an expected marker. Restart PHP for this site to be certain."
	}
	a.rep.AddContain(act)
}

// safeRelPath reduces a finding path to something that cannot escape the
// evidence directory: absolute roots and any ".." component are stripped.
func safeRelPath(p string) string {
	p = filepath.ToSlash(p)
	var keep []string
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".", "..":
			continue
		}
		// Strip a Windows drive prefix such as "C:".
		if i := strings.IndexByte(part, ':'); i >= 0 {
			part = part[i+1:]
			if part == "" {
				continue
			}
		}
		keep = append(keep, part)
	}
	if len(keep) == 0 {
		return "unnamed"
	}
	return filepath.Join(keep...)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
