//go:build linux

package govern

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// setNice lowers the agent's scheduling priority so the web server always wins
// a CPU contest. PRIO_PROCESS with pid 0 means "this process".
func setNice(n int) error {
	return syscall.Setpriority(syscall.PRIO_PROCESS, 0, n)
}

// loadAvg1 reads the 1-minute load average from /proc/loadavg.
func loadAvg1() (float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	// Format: "0.42 0.31 0.28 1/234 5678"
	for i := 0; i < len(b); i++ {
		if b[i] == ' ' {
			v, err := strconv.ParseFloat(string(b[:i]), 64)
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// cpuPressure reads PSI: the share of the last 10 seconds during which some
// task was stalled waiting for CPU, as a percentage.
//
// This is the RIGHT signal inside a container, and loadavg is the wrong one.
// /proc/loadavg reports the HOST's run queue unless lxcfs masks it, so on
// shared hosting a per-core threshold tuned for a dedicated box is exceeded
// essentially always — throttling the scan against contention it is not
// causing and cannot relieve. PSI is delegated per-cgroup under cgroup v2, so
// it reflects contention this workload is actually part of.
func cpuPressure() (float64, bool) {
	b, err := os.ReadFile("/proc/pressure/cpu")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "some") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if !strings.HasPrefix(f, "avg10=") {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}
