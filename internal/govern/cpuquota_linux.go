//go:build linux

package govern

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// How many CPUs are we ACTUALLY allowed?
//
// runtime.NumCPU() reports the host's processors, not the share this container
// may use. On managed WordPress hosting that difference is the whole problem: a
// site container with a 1-CPU quota on a 32-core machine sizes its worker pool
// from 32, saturates its quota, and drives up load for every other tenant on
// the box. A field run did exactly that — roughly 2.8 cores of scanning on a
// shared host, taking the machine to 2.2x overload.
//
// The same blindness defeats the load-based throttle: MaxLoadPerCore divides by
// a core count the container does not have, so the threshold is never reached,
// and PSI inside the container reported ~5% pressure while the host was
// genuinely overloaded. Neither signal can be trusted here.
//
// So the agent sizes itself from its cgroup quota, which is the one number that
// describes what it may actually consume.

// cpuQuota returns the CPU allowance as a fraction of one core (1.0 == one full
// core), or 0 when there is no quota and the host count is the honest answer.
func cpuQuota() float64 {
	// cgroup v2: "<quota> <period>", or "max <period>" when unlimited.
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(strings.TrimSpace(string(b)))
		if len(f) == 2 && f[0] != "max" {
			q, err1 := strconv.ParseFloat(f[0], 64)
			p, err2 := strconv.ParseFloat(f[1], 64)
			if err1 == nil && err2 == nil && p > 0 && q > 0 {
				return q / p
			}
		}
	}
	// cgroup v1.
	q, err1 := readIntFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	p, err2 := readIntFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if err1 == nil && err2 == nil && q > 0 && p > 0 {
		return float64(q) / float64(p)
	}
	return 0
}

func readIntFile(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

// usableCPUs is the core count the agent may size itself against. It never
// exceeds the host count, and never returns less than one.
func usableCPUs() int {
	host := runtime.NumCPU()
	q := cpuQuota()
	if q <= 0 {
		return host
	}
	n := int(q) // deliberately floors: half a core should count as one, not two
	if n < 1 {
		n = 1
	}
	if n > host {
		n = host
	}
	return n
}
