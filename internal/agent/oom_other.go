//go:build !linux

package agent

// oomEvidence reports what the kernel's OOM killer did, and whether it could be
// consulted at all.
//
// The second return value exists because the stub used to return only "", and
// the caller turned that absence of evidence into a positive assertion —
// "No out-of-memory kill was recorded for this container" — and escalated the
// finding to High on the strength of it. That is the inversion the codebase
// elsewhere calls the single most dangerous thing a scanner can do: converting
// "I could not see" into "there was nothing to see".
//
// Only Linux exposes a cgroup kill counter, so everywhere else the honest
// answer is that we do not know.
func oomEvidence() (string, bool) { return "", false }
