//go:build linux

package agent

import (
	"os"
	"strconv"
	"strings"
)

// oomEvidence reports whether the kernel's OOM killer has fired in this
// container, which is the benign explanation for a process disappearing without
// warning.
//
// Distinguishing the two matters. An agent killed because the container ran out
// of memory is a capacity problem; an agent killed by something on the host is a
// security event, and reporting one as the other wastes an analyst's night in
// either direction.
func oomEvidence() string {
	// cgroup v2 keeps a counter of kills in this cgroup.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.events"); err == nil {
		if n := oomKillCount(string(b)); n > 0 {
			return "The kernel's OOM killer has fired " + strconv.Itoa(n) +
				" time(s) in this container, which is the likely cause and is a memory-capacity problem rather than a security event."
		}
	}
	// cgroup v1.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.oom_control"); err == nil {
		if n := fieldValue(string(b), "oom_kill"); n > 0 {
			return "The kernel's OOM killer has fired " + strconv.Itoa(n) +
				" time(s) in this container, which is the likely cause."
		}
	}
	return ""
}

func oomKillCount(s string) int { return fieldValue(s, "oom_kill") }

func fieldValue(s, key string) int {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			n, err := strconv.Atoi(f[1])
			if err == nil {
				return n
			}
		}
	}
	return 0
}
