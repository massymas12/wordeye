//go:build linux

package agent

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"wordeye/internal/model"
)

// Memory inspection without privilege.
//
// Reading another process's memory CONTENT needs PTRACE_MODE_ATTACH, which is
// routinely unavailable in a container: CAP_SYS_PTRACE dropped, seccomp
// filtering the syscall, or yama restricting attach to descendants. That is
// probed at startup rather than assumed (see probeMemoryAccess).
//
// But the highest-value memory signals do not need it. /proc/<pid>/maps is
// readable for same-user processes with no special capability at all, and it
// answers the questions that matter most:
//
//   - Is any region writable AND executable? Legitimate programs almost never
//     need W+X; code that writes then runs its own bytes usually does.
//   - Is executable code backed by a DELETED file? The binary was unlinked
//     while running — the classic anti-forensic move, and unreachable by any
//     file-based scan precisely because the file is gone.
//   - Is a shared library loaded from a path no packaged software uses?
//
// A PHP-specific note on scope. PHP is share-nothing per request, so a shell
// eval'd into a worker normally dies with the request that created it. Durable
// in-memory PHP malware needs OPcache poisoning (handled by forcing eviction
// through FPM during containment) or an unusually long-lived worker. The real
// memory-resident threat on these hosts is a NATIVE implant — a relay backdoor
// or a miner — and if it shares our PID namespace, maps finds it unprivileged.

type mapping struct {
	Start, End uint64
	Perms      string // e.g. "rw-p"
	Path       string
	Deleted    bool
}

func (m mapping) size() uint64 { return m.End - m.Start }

func (m mapping) writable() bool   { return strings.Contains(m.Perms, "w") }
func (m mapping) executable() bool { return strings.Contains(m.Perms, "x") }

// parseMapping reads one line of /proc/<pid>/maps.
//
//	7f3c2a400000-7f3c2a600000 r-xp 00000000 08:01 1234  /usr/lib/libc.so.6
func parseMapping(line string) (mapping, bool) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return mapping{}, false
	}
	dash := strings.IndexByte(f[0], '-')
	if dash < 0 {
		return mapping{}, false
	}
	start, err1 := strconv.ParseUint(f[0][:dash], 16, 64)
	end, err2 := strconv.ParseUint(f[0][dash+1:], 16, 64)
	if err1 != nil || err2 != nil {
		return mapping{}, false
	}
	m := mapping{Start: start, End: end, Perms: f[1]}
	if len(f) >= 6 {
		m.Path = strings.Join(f[5:], " ")
		if strings.HasSuffix(m.Path, " (deleted)") {
			m.Deleted = true
			m.Path = strings.TrimSuffix(m.Path, " (deleted)")
		}
	}
	return m, true
}

func readMappings(pid int) ([]mapping, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []mapping
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if len(out) >= 4000 { // a pathological process must not blow up the scan
			break
		}
		if m, ok := parseMapping(sc.Text()); ok {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}

// Paths whose anonymous-executable or W+X mappings are expected. JIT compilers
// legitimately generate code at runtime, so flagging them would bury the signal.
var jitProcesses = []string{
	"java", "node", "chrome", "firefox", "mono", "dotnet", "python3.1",
	"ruby", "erl", "beam.smp", "julia", "wine",
}

func looksLikeJIT(comm, exe string) bool {
	c := strings.ToLower(comm)
	for _, j := range jitProcesses {
		if strings.Contains(c, j) || strings.Contains(strings.ToLower(exe), j) {
			return true
		}
	}
	return false
}

// checkMemory examines the mappings of every visible process.
func (a *Agent) checkMemory(ctx context.Context) {
	a.timed("mem.mappings", func() (model.CheckState, string) {
		procs := a.procSnapshot()
		if len(procs) == 0 {
			procs = readProcs()
		}
		if len(procs) == 0 {
			return model.CheckError, "/proc unreadable — memory mappings not examined"
		}

		examined := 0
		for _, p := range procs {
			if ctx.Err() != nil {
				break
			}
			if !p.readable || p.PID == os.Getpid() || p.Exe == "" {
				continue
			}
			maps, err := readMappings(p.PID)
			if err != nil {
				// Another user's process, or it exited. Not an error worth
				// reporting per process.
				continue
			}
			examined++
			a.inspectMappings(p, maps)
		}
		if examined == 0 {
			return model.CheckUnavailable, "no readable process mappings (all processes belong to other users)"
		}
		return model.CheckOK, fmt.Sprintf("%d process(es) examined", examined)
	})
}

func (a *Agent) inspectMappings(p *procInfo, maps []mapping) {
	jit := looksLikeJIT(p.Comm, p.Exe)

	var (
		wx          []mapping
		deletedExec []mapping
		anonExec    uint64
	)
	for _, m := range maps {
		switch {
		case m.writable() && m.executable():
			wx = append(wx, m)
		case m.executable() && m.Deleted:
			deletedExec = append(deletedExec, m)
		case m.executable() && m.Path == "":
			anonExec += m.size()
		}
	}

	// Executable code whose backing file has been unlinked. The file-based
	// scanner cannot possibly find this, because there is no longer a file.
	for _, m := range deletedExec {
		a.emit(model.Finding{
			RuleID:     "mem.deleted_executable_mapping",
			Class:      "OSP",
			Severity:   model.SevCritical,
			Confidence: model.ConfConfirmed,
			Title:      "Process is executing code from a deleted file",
			Detail: fmt.Sprintf(
				"%s (pid %d) has an executable mapping backed by %s, which has been unlinked. "+
					"Deleting the file on disk did not stop this code and no file-based scan can find it.",
				p.Comm, p.PID, m.Path),
			Remediation: "Capture /proc/<pid>/exe and the mapped region before killing — it may be the only remaining copy.",
			ContainPID:  p.PID,
			Path:        m.Path,
			Meta: map[string]any{
				"pid": p.PID, "comm": p.Comm, "exe": p.Exe,
				"mapping": m.Path, "perms": m.Perms,
			},
		})
	}

	// Writable AND executable. Legitimate native code essentially never needs
	// this; a JIT does, which is why those are excluded rather than reported.
	if len(wx) > 0 && !jit {
		total := uint64(0)
		for _, m := range wx {
			total += m.size()
		}
		a.emit(model.Finding{
			RuleID:     "mem.writable_executable_mapping",
			Class:      "OSP",
			Severity:   model.SevHigh,
			Confidence: model.ConfLikely,
			Title:      "Process has writable and executable memory",
			Detail: fmt.Sprintf(
				"%s (pid %d) holds %d W+X mapping(s) totalling %d KB. Code that writes then executes its own "+
					"bytes is the shape of an injected or unpacked payload; ordinary native code does not need it.",
				p.Comm, p.PID, len(wx), total/1024),
			Remediation: "Identify the process. If it is not a JIT runtime, treat as possible in-memory injection.",
			ContainPID:  p.PID,
			Path:        p.Exe,
			Meta: map[string]any{
				"pid": p.PID, "comm": p.Comm, "exe": p.Exe,
				"wx_regions": len(wx), "wx_bytes": total,
			},
		})
	}

	// A large anonymous executable region in a non-JIT process suggests code
	// mapped in from somewhere other than a file.
	const anonExecThreshold = 1 << 20
	if anonExec >= anonExecThreshold && !jit {
		a.emit(model.Finding{
			RuleID:     "mem.large_anonymous_exec",
			Class:      "OSP",
			Severity:   model.SevMedium,
			Confidence: model.ConfReview,
			Title:      "Large anonymous executable memory region",
			Detail: fmt.Sprintf(
				"%s (pid %d) maps %d KB of executable memory with no backing file.",
				p.Comm, p.PID, anonExec/1024),
			Remediation: "Expected for JIT runtimes; unusual otherwise. Correlate with the process's identity.",
			ContainPID:  p.PID,
			Path:        p.Exe,
			Meta:        map[string]any{"pid": p.PID, "comm": p.Comm, "anon_exec_bytes": anonExec},
		})
	}
}
