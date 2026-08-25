//go:build linux

package agent

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"wordeye/internal/model"
)

// OS-account persistence.
//
// This is the whole reason the agent is a native binary rather than a plugin.
// A PHP security plugin runs inside the webroot with the web server's
// privileges and no visibility beyond it: it cannot enumerate /proc, read a
// crontab, or see an SSH key. Attackers know that, which is exactly why
// persistence migrates here once they have a shell.

// Interpreters and tools that a web server should never be the parent of.
var webShellChildren = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"perl": true, "python": true, "python2": true, "python3": true,
	"ruby": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"curl": true, "wget": true, "base64": true, "xterm": true, "telnet": true,
}

// Process names of common miners and relay backdoors. Generic, not tied to any
// one engagement — the process-identity checks below catch renamed variants.
var knownImplantNames = map[string]bool{
	"xmrig": true, "kdevtmpfsi": true, "kinsing": true, "masscan": true,
	"gs-dbus": true, "gs-netcat": true, "gsocket": true, "cnrig": true,
	"minerd": true, "cpuminer": true, "xmr-stak": true, "tsm": true,
}

// Directories from which a legitimate long-running daemon is never launched.
var suspiciousExeDirs = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
	"/.config/", "/.local/", "/.cache/", "/.fonts/",
	"/wp-content/", "/uploads/", "/public/", "/public_html/",
}

// Shell/cron content that indicates a launcher rather than ordinary config.
var persistLineRe = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`base64\s+-d`, `base64\s+--decode`,
	`\|\s*(ba)?sh\b`, `/dev/tcp/`, `/dev/udp/`,
	`curl[^|]*\|[^|]*sh`, `wget[^|]*\|[^|]*sh`,
	`\bexec\s+-a\b`, `gs-dbus`, `gs-netcat`, `gsocket`, `GS_ARGS`, `GS_PORT`,
	`python[23]?\s+-c`, `perl\s+-e`, `php\s+-r`, `ruby\s+-e`,
	`socat.*exec`, `\bnc\b\s+.*-e`, `\bncat\b\s+.*-e`,
	`LD_PRELOAD`, `\beval\s*\(`, `kcached`,
	`/tmp/[a-z0-9._-]+`, `/dev/shm/[a-z0-9._-]+`,
}, "|"))

// Benign matches that would otherwise trip persistLineRe on a normal account.
//
// certbot earned its place the hard way. Stock Debian ships
// /etc/cron.d/certbot containing `perl -e 'sleep int(rand(43200))'`, which
// matched the `perl -e` launcher pattern and was reported CRITICAL on a
// perfectly clean host during the first field run. The .dpkg-dist variant that
// actually tripped it is an unapplied package file that never even executes.
//
// The rest are the other packaged cron jobs that ship with a Debian-family
// base image and use the same shapes.
var persistBenignRe = regexp.MustCompile(`(?i)(lesspipe|dircolors|bash_completion|nvm\.sh|/conda|rbenv|pyenv|SDKMAN|cargo/env` +
	`|wp-cron\.php\?server_triggered|/usr/local/bin/wp\b` +
	`|certbot|letsencrypt|dpkg-dist|dpkg-old|dpkg-new|ucf-dist` +
	`|apt-compat|anacron|logrotate|man-db|mlocate|plocate|e2scrub|fstrim)`)

func (a *Agent) checkOSPersistence(ctx context.Context) {
	procs := readProcs()
	a.rep.Stats.ProcsExamined = int64(len(procs))
	a.setProcCache(procs)

	a.timed("osp.processes", func() (model.CheckState, string) {
		if len(procs) == 0 {
			return model.CheckError, "/proc unreadable — process checks did not run"
		}
		a.checkProcessIdentity(procs)
		return model.CheckOK, ""
	})
	a.timed("osp.cron", func() (model.CheckState, string) { return a.checkCron(ctx) })
	a.timed("osp.shellrc", func() (model.CheckState, string) { return a.checkShellRC() })
	a.timed("osp.ssh", func() (model.CheckState, string) { return a.checkSSH() })
	a.timed("osp.systemd", func() (model.CheckState, string) { return a.checkSystemdUser() })
	a.timed("osp.preload", func() (model.CheckState, string) { return a.checkPreload() })
	a.timed("osp.implants", func() (model.CheckState, string) { return a.checkHiddenImplants() })
	a.timed("osp.githooks", func() (model.CheckState, string) { return a.checkGitHooks() })
}

// checkProcessIdentity verifies that each process IS what it claims to be.
//
// argv0 is attacker-controlled (exec -a rewrites it freely); /proc/PID/exe is
// maintained by the kernel and is not. Comparing the two turns a whole class of
// masquerade into a deterministic detection rather than a guess.
func (a *Agent) checkProcessIdentity(procs []*procInfo) {
	byPID := make(map[int]*procInfo, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}

	for _, p := range procs {
		if !p.readable || p.PID == os.Getpid() {
			continue
		}

		// 1. Kernel-thread masquerade. A genuine kernel thread has no exe.
		if strings.HasPrefix(p.Argv0, "[") && strings.HasSuffix(p.Argv0, "]") && p.Exe != "" {
			a.procFinding(p, "osp.proc_masquerade", model.SevCritical, model.ConfConfirmed,
				"Userspace process disguised as a kernel thread",
				fmt.Sprintf("argv0 is %q, which by convention denotes a kernel thread, but the kernel reports a real executable at %s. Kernel threads never have one. This is how gsocket's [kcached] relay hides.", p.Argv0, p.Exe),
				"Contain it — but neutralise its launcher (cron/rc/systemd) first, or it respawns.")
		}

		// 2. Running from a deleted image: the file is gone from disk but the
		//    code is still executing, which defeats file-based scanning and
		//    file-based cleanup alike.
		if p.ExeDeleted {
			a.procFinding(p, "osp.proc_deleted_binary", model.SevCritical, model.ConfConfirmed,
				"Process is executing a deleted binary",
				fmt.Sprintf("%s was unlinked while running (%d socket(s) open). Deleting the file on disk did not stop this process, and never will.", p.Exe, len(p.SockInodes)),
				"Capture /proc/PID/exe before killing — it is the only remaining copy of the binary.")
		}

		// 3. Executing from a directory no daemon belongs in.
		for _, d := range suspiciousExeDirs {
			if strings.Contains(p.Exe, d) {
				a.procFinding(p, "osp.proc_bad_path", model.SevHigh, model.ConfLikely,
					"Process running from a suspicious location",
					fmt.Sprintf("Executable %s sits under %s. Packaged daemons run from /usr, /bin or /opt.", p.Exe, strings.Trim(d, "/")),
					"Identify the binary (sha256, strings) before acting.")
				break
			}
		}

		// 4. A web server that has spawned a shell. This is not persistence —
		//    it is active exploitation, happening now.
		if parent := byPID[p.PPID]; parent != nil {
			pc := strings.ToLower(parent.Comm)
			isWeb := strings.Contains(pc, "php-fpm") || strings.Contains(pc, "apache") ||
				strings.Contains(pc, "httpd") || strings.Contains(pc, "nginx") ||
				strings.Contains(pc, "lsphp") || pc == "php"
			if isWeb && webShellChildren[strings.ToLower(p.Comm)] {
				a.procFinding(p, "osp.webserver_spawned_shell", model.SevCritical, model.ConfConfirmed,
					"Web server has spawned an interactive shell or network tool",
					fmt.Sprintf("%s (pid %d) was launched by %s (pid %d). A web server executing %s means code execution through the site is happening right now.\nargv: %s",
						p.Comm, p.PID, parent.Comm, parent.PID, p.Comm, truncate(p.Cmdline, 200)),
					"Contain immediately, then find the request that spawned it in the access log.")
			}
		}

		// 5. Known implant names.
		if knownImplantNames[strings.ToLower(p.Comm)] || knownImplantNames[filepath.Base(p.Exe)] {
			a.procFinding(p, "osp.known_implant", model.SevCritical, model.ConfConfirmed,
				"Known miner or relay-backdoor process",
				fmt.Sprintf("Process %s (%s) matches a known implant family.", p.Comm, p.Exe),
				"Contain, then remove its persistence before killing.")
		}

		// 6. Reparented interactive process.
		//
		//    The kernel has no concept of a container, so a process entered
		//    through the runtime — lxc exec, docker exec, a hypervisor console —
		//    carries no ancestry back to a login. It simply appears parented to
		//    PID 1. Ancestry-based detection cannot observe that entry, but the
		//    ORPHANED RESULT is visible from inside, and on managed hosting that
		//    is what out-of-band access to your container looks like.
		//
		//    Restricted to interactive shells and network tools: in a system
		//    container ordinary daemons are legitimately children of PID 1, and
		//    flagging those would drown the signal entirely.
		if p.PPID == 1 && webShellChildren[strings.ToLower(p.Comm)] {
			a.procFinding(p, "osp.reparented_shell", model.SevMedium, model.ConfReview,
				"Interactive process with no parent chain",
				fmt.Sprintf(
					"%s (pid %d) is parented directly to PID 1 with no ancestry back to a login shell. "+
						"That is the signature of entry through the container runtime (lxc/docker exec), or of a "+
						"parent that exited deliberately to orphan it.\nargv: %s",
					p.Comm, p.PID, truncate(p.Cmdline, 200)),
				"Correlate with your host provider's access logs. If nobody entered this container, treat it as unexplained access.")
		}

		// 7. Process whose working directory is inside the webroot: normal for
		//    the web server itself, abnormal for anything else.
		if a.cfg.Webroot != "" && p.Cwd != "" && strings.HasPrefix(p.Cwd, a.cfg.Webroot) {
			pc := strings.ToLower(p.Comm)
			if !strings.Contains(pc, "php-fpm") && !strings.Contains(pc, "nginx") &&
				!strings.Contains(pc, "apache") && !strings.Contains(pc, "httpd") && pc != "wordeye-agent" {
				a.procFinding(p, "osp.proc_cwd_webroot", model.SevMedium, model.ConfReview,
					"Non-web-server process working inside the webroot",
					fmt.Sprintf("%s (pid %d) has cwd %s.", p.Comm, p.PID, p.Cwd),
					"Verify this is an expected maintenance task (wp-cli, backup agent).")
			}
		}
	}
}

func (a *Agent) procFinding(p *procInfo, id string, sev model.Severity, conf model.Confidence, title, detail, rem string) {
	a.emit(model.Finding{
		RuleID:      id,
		Class:       "OSP",
		Severity:    sev,
		Confidence:  conf,
		Title:       title,
		Detail:      detail,
		Remediation: rem,
		ContainPID:  p.PID,
		Path:        p.Exe,
		Meta: map[string]any{
			"pid": p.PID, "ppid": p.PPID, "comm": p.Comm, "argv0": p.Argv0,
			"cmdline": truncate(p.Cmdline, 400), "exe": p.Exe, "cwd": p.Cwd,
			"uid": p.UID, "sockets": len(p.SockInodes), "exe_deleted": p.ExeDeleted,
		},
	})
}

// ---------------------------------------------------------------------------
// scheduled execution
// ---------------------------------------------------------------------------

func (a *Agent) checkCron(ctx context.Context) (model.CheckState, string) {
	var sources []struct{ name, body string }

	if out, err := runCmd(ctx, 10*time.Second, "crontab", "-l"); err == nil {
		sources = append(sources, struct{ name, body string }{"crontab -l", out})
	}
	for _, p := range []string{
		"/var/spool/cron/crontabs/" + currentUser(),
		"/var/spool/cron/" + currentUser(),
		filepath.Join(a.cfg.Home, ".crontab"),
	} {
		if b, err := os.ReadFile(p); err == nil {
			sources = append(sources, struct{ name, body string }{p, string(b)})
		}
	}
	// System-wide cron is usually root-owned; read it when permitted, since a
	// root-level compromise puts persistence here.
	for _, p := range []string{"/etc/crontab"} {
		if b, err := os.ReadFile(p); err == nil {
			sources = append(sources, struct{ name, body string }{p, string(b)})
		}
	}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join("/etc/cron.d", e.Name())
			if b, err := os.ReadFile(p); err == nil {
				sources = append(sources, struct{ name, body string }{p, string(b)})
			}
		}
	}

	if len(sources) == 0 {
		return model.CheckUnavailable, "no readable crontab"
	}
	for _, s := range sources {
		a.scanPersistLines(s.name, s.body, "osp.cron_persistence",
			"Scheduled task looks like a malware launcher",
			"Remove the entry BEFORE killing the process it starts, or cron will simply restart it.")
	}
	return model.CheckOK, ""
}

func (a *Agent) checkShellRC() (model.CheckState, string) {
	found := 0
	for _, name := range []string{
		".bashrc", ".bash_profile", ".profile", ".bash_login", ".zshrc",
		".zprofile", ".kshrc", ".bash_logout", ".config/fish/config.fish",
	} {
		p := filepath.Join(a.cfg.Home, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found++
		a.scanPersistLines(p, string(b), "osp.shellrc_persistence",
			"Shell startup file contains a launcher",
			"Runs on every interactive login or shell invocation. Excise the line and check for a matching cron entry.")
	}
	if found == 0 {
		return model.CheckNotApplicable, "no shell rc files"
	}
	return model.CheckOK, ""
}

// scanPersistLines applies the launcher regex to a config file, line by line.
func (a *Agent) scanPersistLines(source, body, ruleID, title, rem string) {
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !persistLineRe.MatchString(t) || persistBenignRe.MatchString(t) {
			continue
		}
		a.emit(model.Finding{
			RuleID:      ruleID,
			Class:       "OSP",
			Severity:    model.SevCritical,
			Confidence:  model.ConfLikely,
			Title:       title,
			Detail:      fmt.Sprintf("%s line %d", source, line),
			Evidence:    truncate(t, 300),
			Path:        source,
			Line:        line,
			Remediation: rem,
		})
	}
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

func (a *Agent) checkSSH() (model.CheckState, string) {
	sshDir := filepath.Join(a.cfg.Home, ".ssh")
	if _, err := os.Stat(sshDir); err != nil {
		return model.CheckNotApplicable, "no ~/.ssh"
	}

	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		p := filepath.Join(sshDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var keys []string
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			t := strings.TrimSpace(sc.Text())
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			f := strings.Fields(t)
			comment := ""
			if len(f) >= 3 {
				comment = f[len(f)-1]
			}
			// A forced-command or restricted key is worth calling out
			// separately; attackers also abuse command= for stealth.
			if strings.Contains(t, "command=") {
				comment += " [forced-command]"
			}
			keys = append(keys, comment)
		}
		if len(keys) == 0 {
			continue
		}
		a.emit(model.Finding{
			RuleID:     "osp.ssh_authorized_key",
			Class:      "OSP",
			Severity:   model.SevHigh,
			Confidence: model.ConfReview,
			Title:      fmt.Sprintf("%d SSH key(s) authorised for this account", len(keys)),
			Detail: "An attacker-added key is passwordless persistence that survives every password reset and every file cleanup. Key comments: " +
				strings.Join(keys, ", "),
			Path:        p,
			Remediation: "Verify every key against your known-good inventory; remove anything unrecognised.",
			Meta:        map[string]any{"keys": keys},
		})
	}

	// ProxyCommand/LocalCommand in ssh config execute on connect.
	cfg := filepath.Join(sshDir, "config")
	if b, err := os.ReadFile(cfg); err == nil {
		low := strings.ToLower(string(b))
		if strings.Contains(low, "proxycommand") || strings.Contains(low, "localcommand") {
			a.emit(model.Finding{
				RuleID:      "osp.ssh_config_command",
				Class:       "OSP",
				Severity:    model.SevHigh,
				Confidence:  model.ConfReview,
				Title:       "SSH client config defines ProxyCommand/LocalCommand",
				Detail:      "These execute a shell command whenever this account initiates an SSH connection.",
				Path:        cfg,
				Remediation: "Confirm the directive is yours.",
			})
		}
	}
	return model.CheckOK, ""
}

// ---------------------------------------------------------------------------
// systemd, preload, implants, git hooks
// ---------------------------------------------------------------------------

func (a *Agent) checkSystemdUser() (model.CheckState, string) {
	dir := filepath.Join(a.cfg.Home, ".config", "systemd", "user")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return model.CheckNotApplicable, "no user systemd units"
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
			continue
		}
		n++
		p := filepath.Join(dir, name)
		b, _ := os.ReadFile(p)
		sev := model.SevMedium
		conf := model.ConfReview
		if persistLineRe.MatchString(string(b)) {
			sev, conf = model.SevCritical, model.ConfLikely
		}
		a.emit(model.Finding{
			RuleID:      "osp.systemd_user_unit",
			Class:       "OSP",
			Severity:    sev,
			Confidence:  conf,
			Title:       "User systemd unit: " + name,
			Detail:      "User units start automatically with lingering enabled and survive reboots, independently of cron.",
			Path:        p,
			Evidence:    truncate(strings.TrimSpace(string(b)), 300),
			Remediation: "Verify the unit is expected: systemctl --user status " + name,
		})
	}
	if n == 0 {
		return model.CheckNotApplicable, "no user systemd units"
	}
	return model.CheckOK, ""
}

// checkPreload looks for library-injection persistence, which subverts every
// dynamically linked binary on the host including any tool used to investigate.
func (a *Agent) checkPreload() (model.CheckState, string) {
	checked := 0
	if b, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		checked++
		if t := strings.TrimSpace(string(b)); t != "" {
			a.emit(model.Finding{
				RuleID:     "osp.ld_preload_global",
				Class:      "OSP",
				Severity:   model.SevCritical,
				Confidence: model.ConfLikely,
				Title:      "/etc/ld.so.preload is non-empty",
				Detail: "Every dynamically linked process on this host loads the listed libraries first — the standard mechanism for a userland rootkit, and it will hook the very tools used to investigate it. Contents: " +
					truncate(t, 300),
				Path:        "/etc/ld.so.preload",
				Remediation: "Treat as full host compromise. Verify findings from a known-good rescue environment.",
			})
		}
	}
	for _, name := range []string{".pam_environment", ".profile", ".bashrc"} {
		p := filepath.Join(a.cfg.Home, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		checked++
		if strings.Contains(string(b), "LD_PRELOAD") {
			a.emit(model.Finding{
				RuleID:      "osp.ld_preload_user",
				Class:       "OSP",
				Severity:    model.SevHigh,
				Confidence:  model.ConfLikely,
				Title:       "LD_PRELOAD set for this account",
				Detail:      "Injects a shared library into processes started by this user.",
				Path:        p,
				Remediation: "Verify the referenced library.",
			})
		}
	}
	if checked == 0 {
		return model.CheckUnavailable, "no preload config readable"
	}
	return model.CheckOK, ""
}

func (a *Agent) checkHiddenImplants() (model.CheckState, string) {
	roots := []string{
		filepath.Join(a.cfg.Home, ".config"),
		filepath.Join(a.cfg.Home, ".local"),
		filepath.Join(a.cfg.Home, ".cache"),
		filepath.Join(a.cfg.Home, ".fonts"),
	}
	found, scanned := 0, 0
	for _, root := range roots {
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		scanned++
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || found >= 25 {
				return nil
			}
			if d.IsDir() {
				if depth(p) > depth(root)+3 {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Mode().Perm()&0o111 == 0 {
				return nil
			}
			// Scripts and libraries in these trees are normal; a bare
			// executable with no extension is not.
			switch strings.ToLower(filepath.Ext(p)) {
			case ".so", ".py", ".sh", ".js", ".pl", ".rb", ".ts", ".fish":
				return nil
			}
			if strings.Contains(p, "/bin/") || strings.Contains(p, "/node_modules/") {
				return nil
			}
			found++
			a.emit(model.Finding{
				RuleID:      "osp.hidden_executable",
				Class:       "OSP",
				Severity:    model.SevHigh,
				Confidence:  model.ConfReview,
				Title:       "Executable in a hidden configuration directory",
				Detail:      "Config and cache directories should not hold executables; this is where relay backdoors stage themselves.",
				Path:        p,
				SHA256:      hashFile(p),
				Size:        info.Size(),
				Remediation: "Identify the binary before removing it: file, strings, sha256 lookup.",
			})
			return nil
		})
	}
	if scanned == 0 {
		return model.CheckNotApplicable, "no hidden config directories"
	}
	return model.CheckOK, ""
}

// checkGitHooks catches persistence in a repository checked out into the
// webroot: hooks are executable scripts that run on ordinary git operations and
// are not part of the tracked tree, so they survive a `git checkout .` cleanup.
func (a *Agent) checkGitHooks() (model.CheckState, string) {
	if a.cfg.Webroot == "" {
		return model.CheckUnavailable, "no webroot"
	}
	hooks := filepath.Join(a.cfg.Webroot, ".git", "hooks")
	entries, err := os.ReadDir(hooks)
	if err != nil {
		return model.CheckNotApplicable, "no git hooks directory"
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		p := filepath.Join(hooks, e.Name())
		info, err := e.Info()
		if err != nil || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		b, _ := os.ReadFile(p)
		sev, conf := model.SevMedium, model.ConfReview
		if persistLineRe.MatchString(string(b)) {
			sev, conf = model.SevCritical, model.ConfLikely
		}
		a.emit(model.Finding{
			RuleID:      "osp.git_hook",
			Class:       "OSP",
			Severity:    sev,
			Confidence:  conf,
			Title:       "Active git hook in the webroot: " + e.Name(),
			Detail:      "Hooks are untracked executables, so they survive a git-based redeploy or cleanup.",
			Path:        p,
			Evidence:    truncate(strings.TrimSpace(string(b)), 300),
			Remediation: "Verify the hook is yours.",
		})
	}
	return model.CheckOK, ""
}

// Shared helpers (truncate, runCmd, currentUser, depth) live in util.go so the
// portable checks can use them too.
