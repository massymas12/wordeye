//go:build linux

package agent

import (
	"os"
	"strconv"
	"strings"
)

// attributeSignal makes a best-effort guess at who asked the agent to stop.
//
// This is inference, not evidence, and is labelled as such everywhere it
// surfaces. The kernel knows the sender and will not tell a Go process, so the
// next best thing is a live process whose command line names this agent:
// kill <pid>, pkill wordeye, a script stopping the service. An attacker
// one-liner is usually still resident for the instant it takes to look.
//
// Returning nothing is the common and correct outcome for an ordinary service
// stop, which is why an empty suspect is treated as unremarkable.
func attributeSignal() (int, string) {
	me := strconv.Itoa(os.Getpid())
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, ""
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(b) == 0 {
			continue
		}
		cmd := strings.ToLower(strings.ReplaceAll(string(b), "\x00", " "))
		if !strings.Contains(cmd, "kill") {
			continue
		}
		// It has to be about US: our pid, or our binary by name.
		if strings.Contains(cmd, me) || strings.Contains(cmd, "wordeye") {
			exe, _ := os.Readlink("/proc/" + e.Name() + "/exe")
			if exe == "" {
				exe = strings.TrimSpace(cmd)
			}
			return pid, exe
		}
	}
	return 0, ""
}
