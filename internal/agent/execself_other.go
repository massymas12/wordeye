//go:build !linux && !darwin && !freebsd

package agent

import "fmt"

// execSelf has no equivalent on platforms without exec semantics.
//
// Returning an error rather than pretending is deliberate: the caller falls
// back to a clean shutdown, which a supervisor turns into a restart on the new
// binary. Silently doing nothing here would leave the process running code that
// no longer matches the file on disk.
func execSelf(path string, args, env []string) error {
	return fmt.Errorf("re-exec is not supported on this platform")
}
