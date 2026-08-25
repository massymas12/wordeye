//go:build !linux

package govern

import "runtime"

// usableCPUs has no cgroup notion off Linux; the host count is the honest
// answer there.
func usableCPUs() int { return runtime.NumCPU() }
