//go:build linux

package agent

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wordeye/internal/model"
)

// Where am I, and what can I actually see?
//
// On managed WordPress hosting the agent runs unprivileged inside a container.
// That is not a failure mode to work around — it is the normal case — but it
// changes what every OS-level check MEANS. A crontab check that finds nothing
// inside a container has not established that the host has no malicious cron;
// it has established that this namespace has no crontab, which is expected and
// says nothing either way.
//
// Reporting the second as though it were the first is the single most dangerous
// thing a scanner can do, because it converts "I could not see" into "there was
// nothing to see". Everything here exists to keep those apart.

var (
	dockerCgroupRe = regexp.MustCompile(`(?:^|/)docker[-/]([0-9a-f]{12,64})`)
	crioCgroupRe   = regexp.MustCompile(`(?:^|/)cri-o-([0-9a-f]{12,64})`)
	ctrdCgroupRe   = regexp.MustCompile(`cri-containerd[-:]([0-9a-f]{12,64})`)
	libpodRe       = regexp.MustCompile(`libpod-([0-9a-f]{12,64})`)
	genericHexRe   = regexp.MustCompile(`/([0-9a-f]{64})(?:\.scope)?$`)
)

// DetectEnvironment inspects the runtime context.
//
// Detection is deliberately evidence-based and loose: cgroup path layouts vary
// considerably between Docker, containerd, CRI-O, Podman and cgroup v1 vs v2, so
// several weak signals are collected rather than one brittle parse.
func DetectEnvironment() *model.Environment {
	e := &model.Environment{}

	// --- direct runtime markers -------------------------------------------
	if _, err := os.Stat("/.dockerenv"); err == nil {
		e.Contained = true
		e.Runtime = "docker"
		e.Evidence = append(e.Evidence, "/.dockerenv present")
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		e.Contained = true
		if e.Runtime == "" {
			e.Runtime = "podman"
		}
		e.Evidence = append(e.Evidence, "/run/.containerenv present")
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		e.Contained = true
		e.Runtime = "kubernetes"
		e.Evidence = append(e.Evidence, "KUBERNETES_SERVICE_HOST is set")
	}

	// --- cgroup membership -------------------------------------------------
	if cg, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		text := string(cg)
		switch {
		case ctrdCgroupRe.MatchString(text):
			e.Contained = true
			if e.Runtime == "" || e.Runtime == "kubernetes" {
				if e.Runtime == "" {
					e.Runtime = "containerd"
				}
			}
			e.ID = firstSubmatch(ctrdCgroupRe, text)
			e.Evidence = append(e.Evidence, "cgroup names a containerd container")
		case crioCgroupRe.MatchString(text):
			e.Contained = true
			if e.Runtime == "" {
				e.Runtime = "cri-o"
			}
			e.ID = firstSubmatch(crioCgroupRe, text)
			e.Evidence = append(e.Evidence, "cgroup names a CRI-O container")
		case libpodRe.MatchString(text):
			e.Contained = true
			if e.Runtime == "" {
				e.Runtime = "podman"
			}
			e.ID = firstSubmatch(libpodRe, text)
			e.Evidence = append(e.Evidence, "cgroup names a libpod container")
		case dockerCgroupRe.MatchString(text):
			e.Contained = true
			if e.Runtime == "" {
				e.Runtime = "docker"
			}
			e.ID = firstSubmatch(dockerCgroupRe, text)
			e.Evidence = append(e.Evidence, "cgroup names a docker container")
		case strings.Contains(text, "kubepods"):
			e.Contained = true
			e.Runtime = "kubernetes"
			e.ID = firstSubmatch(genericHexRe, text)
			e.Evidence = append(e.Evidence, "cgroup is under kubepods")
		case strings.Contains(text, "/lxc"):
			e.Contained = true
			if e.Runtime == "" {
				e.Runtime = "lxc"
			}
			e.Evidence = append(e.Evidence, "cgroup is under /lxc")
		}
	}

	// --- LXD / LXC system containers ---------------------------------------
	// These need their own signals. An LXD container runs a full userspace —
	// systemd as PID 1, its own cron, dozens of processes, and commonly a ZFS
	// or btrfs root rather than overlayfs — so every heuristic aimed at
	// Docker-style application containers misses it completely. Managed
	// WordPress hosts use exactly this model, which makes it the case that
	// matters most rather than an edge case.
	if _, err := os.Stat("/dev/lxd/sock"); err == nil {
		e.Contained = true
		e.Runtime = "lxd"
		e.Evidence = append(e.Evidence, "/dev/lxd/sock present (LXD guest API)")
	}
	if b, err := os.ReadFile("/run/systemd/container"); err == nil {
		v := strings.TrimSpace(string(b))
		if v != "" {
			e.Contained = true
			if e.Runtime == "" || e.Runtime == "unknown" {
				e.Runtime = v
			}
			e.Evidence = append(e.Evidence, "systemd reports container="+v)
		}
	}
	// PID 1's environment carries container=lxc, though an unprivileged site
	// user usually cannot read it. Worth trying; never relied upon.
	if b, err := os.ReadFile("/proc/1/environ"); err == nil {
		env := string(b)
		if strings.Contains(env, "container=lxc") {
			e.Contained = true
			if e.Runtime == "" || e.Runtime == "unknown" {
				e.Runtime = "lxc"
			}
			e.Evidence = append(e.Evidence, "PID 1 environment contains container=lxc")
		}
	}
	if cg, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if strings.Contains(string(cg), "lxc.payload") {
			e.Contained = true
			if e.Runtime == "" || e.Runtime == "unknown" {
				e.Runtime = "lxd"
			}
			e.Evidence = append(e.Evidence, "cgroup is under an lxc.payload slice")
		}
	}

	// --- overlayfs root ----------------------------------------------------
	// A root filesystem on overlay is characteristic of a container image and
	// also tells us writes land in a discardable upper layer.
	if mi, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(mi)))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 5 {
				continue
			}
			if f[4] != "/" {
				continue
			}
			line := sc.Text()
			if strings.Contains(line, " overlay ") {
				e.Contained = true
				e.Evidence = append(e.Evidence, "root filesystem is overlayfs")
			}
			if strings.Contains(line, " ro,") || strings.HasSuffix(f[5], "ro") {
				e.ReadOnlyRoot = true
			}
		}
	}

	// --- namespaces --------------------------------------------------------
	e.PIDNamespace = nsLink("pid")
	e.NetNamespace = nsLink("net")
	e.MountNamespace = nsLink("mnt")

	// --- PID 1 identity: determines KIND, not containment -------------------
	// An init system as PID 1 used to be read as "probably a host". That is
	// wrong for LXD, where systemd IS PID 1 inside the container. It only tells
	// us which KIND of container we are in, which is what changes the meaning
	// of the OS-level checks.
	if comm, err := os.ReadFile("/proc/1/comm"); err == nil {
		c := strings.TrimSpace(string(comm))
		switch c {
		case "systemd", "init", "openrc-init", "runit", "s6-svscan":
			if e.Contained {
				e.Kind = "system"
				e.Evidence = append(e.Evidence,
					fmt.Sprintf("PID 1 is %q: a full init, so this is a system container", c))
			}
		default:
			if c != "" {
				e.Contained = true
				e.Kind = "application"
				e.Evidence = append(e.Evidence,
					fmt.Sprintf("PID 1 is %q rather than an init system", c))
			}
		}
	}

	e.ProcessesVisible = countProcs()
	if e.ProcessesVisible > 0 && e.ProcessesVisible < 25 && !e.Contained {
		// Few processes and no other evidence: probably a container or a jail,
		// just one we cannot name. Deliberately a LAST resort — a system
		// container runs a full process table and would sail past this.
		e.Contained = true
		e.Kind = "application"
		e.Evidence = append(e.Evidence,
			fmt.Sprintf("only %d processes visible, far fewer than a host", e.ProcessesVisible))
	}
	// Last resort: ask systemd directly. Bounded, and only when nothing else
	// concluded anything.
	if !e.Contained {
		if out, err := runCmd(context.Background(), 3*time.Second, "systemd-detect-virt", "--container"); err == nil {
			v := strings.TrimSpace(out)
			if v != "" && v != "none" {
				e.Contained = true
				e.Runtime = v
				e.Evidence = append(e.Evidence, "systemd-detect-virt reports "+v)
			}
		}
	}
	if e.Contained && e.Runtime == "" {
		e.Runtime = "unknown"
	}
	if e.Contained && e.Kind == "" {
		e.Kind = "application"
	}

	e.StartedAt = namespaceStartTime()
	e.MemoryReadable, e.MemoryReason = probeMemoryAccess()
	return e
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// nsLink returns the namespace identifier, e.g. "pid:[4026531836]".
func nsLink(kind string) string {
	l, err := os.Readlink("/proc/self/ns/" + kind)
	if err != nil {
		return ""
	}
	return l
}

func countProcs() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

// namespaceStartTime returns when PID 1 in this namespace started.
//
// On an immutable deployment this is effectively the deploy time, which makes
// it the reference point for "this file was written at runtime, not built into
// the image" — the strongest privilege-free signal available in a container.
func namespaceStartTime() time.Time {
	statRaw, err := os.ReadFile("/proc/1/stat")
	if err != nil {
		return time.Time{}
	}
	s := string(statRaw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 > len(s) {
		return time.Time{}
	}
	f := strings.Fields(s[closeParen+2:])
	// Field 22 overall is starttime; f[0] is field 3, so index 19.
	if len(f) <= 19 {
		return time.Time{}
	}
	ticks, err := strconv.ParseFloat(f[19], 64)
	if err != nil {
		return time.Time{}
	}
	upRaw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	upFields := strings.Fields(string(upRaw))
	if len(upFields) == 0 {
		return time.Time{}
	}
	uptime, err := strconv.ParseFloat(upFields[0], 64)
	if err != nil {
		return time.Time{}
	}
	// USER_HZ is 100 on every mainstream Linux build; determining it exactly
	// would require cgo, and being a few seconds out does not matter for a
	// reference point measured in days.
	const userHZ = 100.0
	bootTime := time.Now().Add(-time.Duration(uptime * float64(time.Second)))
	return bootTime.Add(time.Duration(ticks / userHZ * float64(time.Second)))
}

// probeMemoryAccess determines empirically whether another process's memory can
// be read.
//
// This is probed rather than inferred because it depends on three independent
// things that vary per host: CAP_SYS_PTRACE, the seccomp profile, and
// yama/ptrace_scope. Guessing produces either false confidence or a capability
// left unused.
func probeMemoryAccess() (bool, string) {
	// Yama policy is the most common blocker and is cheap to read.
	if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "2":
			return false, "yama ptrace_scope=2 (admin-only attach)"
		case "3":
			return false, "yama ptrace_scope=3 (attach disabled kernel-wide)"
		}
	}

	me := os.Getpid()
	uid := os.Getuid()
	for _, p := range readProcs() {
		if p.PID == me || !p.readable || p.Exe == "" {
			continue
		}
		if int(p.UID) != uid {
			continue // cross-user attach needs privilege we do not have
		}
		f, err := os.Open(fmt.Sprintf("/proc/%d/mem", p.PID))
		if err != nil {
			return false, "cannot open another process's memory: " + errKind(err)
		}
		defer f.Close()

		// Read from a mapped region rather than offset zero, which is unmapped.
		off, ok := firstReadableMapping(p.PID)
		if !ok {
			continue
		}
		buf := make([]byte, 8)
		if _, err := f.ReadAt(buf, int64(off)); err != nil {
			return false, "memory read refused: " + errKind(err)
		}
		return true, ""
	}
	return false, "no same-user process available to probe"
}

func errKind(err error) string {
	if os.IsPermission(err) {
		return "permission denied (likely CAP_SYS_PTRACE dropped or seccomp)"
	}
	return err.Error()
}

// firstReadableMapping returns the start address of a readable private mapping.
func firstReadableMapping(pid int) (uint64, bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m, ok := parseMapping(sc.Text())
		if !ok || !strings.HasPrefix(m.Perms, "r") {
			continue
		}
		return m.Start, true
	}
	return 0, false
}
