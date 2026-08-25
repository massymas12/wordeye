//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// /proc process introspection.
//
// This is the foundation of the checks a webroot-resident scanner cannot
// perform. Everything here reads the kernel's own view of what is running,
// which is authoritative in a way that a process name never is.

type procInfo struct {
	PID        int
	PPID       int
	Comm       string // kernel's name for the process (from /proc/PID/stat)
	Argv0      string // what the process calls itself (forgeable)
	Cmdline    string // full argv, NUL-joined for display
	Exe        string // resolved /proc/PID/exe (authoritative, unforgeable)
	ExeDeleted bool   // binary was unlinked while running
	Cwd        string
	UID        uint32
	State      string
	SockInodes []uint64 // for attributing network connections to this process
	StartTicks uint64
	readable   bool // we had permission to inspect it
}

// IsKernelThread reports whether this is a genuine kernel thread. Real kernel
// threads have no executable image, because they never left kernel space. This
// is precisely why a bracketed argv0 combined with a real Exe is proof of
// masquerade rather than a heuristic.
func (p *procInfo) IsKernelThread() bool {
	return p.readable && p.Exe == ""
}

func readProcs() []*procInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []*procInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if p := readProc(pid); p != nil {
			out = append(out, p)
		}
	}
	return out
}

func readProc(pid int) *procInfo {
	base := "/proc/" + strconv.Itoa(pid)
	p := &procInfo{PID: pid}

	statRaw, err := os.ReadFile(base + "/stat")
	if err != nil {
		// Process exited between the readdir and now, or belongs to another
		// user on a hidepid mount. Either way there is nothing to say.
		return nil
	}
	parseStat(string(statRaw), p)

	if b, err := os.ReadFile(base + "/cmdline"); err == nil && len(b) > 0 {
		parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		p.Argv0 = parts[0]
		p.Cmdline = strings.Join(parts, " ")
	}

	// A readable exe link is what separates "we inspected it" from "we were
	// denied". Distinguishing those matters: silently treating denied as clean
	// is how a scanner reports a compromised host as healthy.
	if link, err := os.Readlink(base + "/exe"); err == nil {
		p.readable = true
		if strings.HasSuffix(link, " (deleted)") {
			p.ExeDeleted = true
			link = strings.TrimSuffix(link, " (deleted)")
		}
		p.Exe = link
	} else if os.IsNotExist(err) {
		// No exe image at all: a kernel thread.
		p.readable = true
	}

	if link, err := os.Readlink(base + "/cwd"); err == nil {
		p.Cwd = link
	}
	if b, err := os.ReadFile(base + "/status"); err == nil {
		p.UID = parseStatusUID(string(b))
	}
	p.SockInodes = readSocketInodes(base + "/fd")
	return p
}

func parseStat(s string, p *procInfo) {
	// comm is parenthesised and may itself contain spaces or parentheses, so
	// the only safe anchor is the LAST closing paren.
	close := strings.LastIndexByte(s, ')')
	open := strings.IndexByte(s, '(')
	if open >= 0 && close > open {
		p.Comm = s[open+1 : close]
	}
	if close < 0 || close+2 > len(s) {
		return
	}
	f := strings.Fields(s[close+2:])
	// f[0] is field 3 (state), so field N maps to f[N-3].
	if len(f) > 0 {
		p.State = f[0]
	}
	if len(f) > 1 {
		p.PPID, _ = strconv.Atoi(f[1])
	}
	if len(f) > 19 {
		p.StartTicks, _ = strconv.ParseUint(f[19], 10, 64)
	}
}

func parseStatusUID(s string) uint32 {
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 1 {
			v, _ := strconv.ParseUint(f[1], 10, 32)
			return uint32(v)
		}
	}
	return 0
}

// readSocketInodes lists the socket inodes a process holds open. Joining these
// against /proc/net/tcp is how a connection gets attributed to a PID without
// shelling out to `ss -p`.
func readSocketInodes(fdDir string) []uint64 {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}
