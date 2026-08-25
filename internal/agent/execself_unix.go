//go:build linux || darwin || freebsd

package agent

import "syscall"

// execSelf replaces the running process image, keeping the same pid.
//
// This is what lets an upgrade complete on a host with no supervisor: there is
// no window in which the agent is not running, and anything watching the pid
// sees no restart at all.
func execSelf(path string, args, env []string) error {
	return syscall.Exec(path, args, env)
}
