//go:build !linux

package agent

import (
	"io/fs"
	"time"
)

// Workstation stubs. ctime is unavailable outside Linux, so timestomp detection
// is reported as skipped rather than silently returning a wrong answer.

func fileTimes(info fs.FileInfo) (mtime, ctime time.Time, ok bool) {
	return info.ModTime(), time.Time{}, false
}

// permsMeaningful is false here: Windows and other non-POSIX platforms
// synthesize permission bits (typically 0666/0444) rather than reporting real
// ACLs, so a "world-writable" test would fire on every single file.
const permsMeaningful = false

func fileOwner(fs.FileInfo) (uint32, uint32, bool) { return 0, 0, false }

func inodeOf(fs.FileInfo) (uint64, bool) { return 0, false }
