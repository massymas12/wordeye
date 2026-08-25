//go:build !linux

package agent

// oomEvidence is Linux-only; elsewhere there is no cgroup counter to consult.
func oomEvidence() string { return "" }
