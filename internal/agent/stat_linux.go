//go:build linux

package agent

import (
	"io/fs"
	"syscall"
	"time"
)

// fileTimes extracts mtime and ctime.
//
// ctime is the inode change time. Crucially, an unprivileged attacker CAN
// backdate mtime with touch() to make a dropped shell blend into an old plugin
// directory, but CANNOT forge ctime — the kernel updates it on any inode write
// and there is no userspace API to set it. A file whose mtime is far older than
// its ctime has therefore been deliberately timestomped, which is one of the
// highest-signal, lowest-false-positive detections available on Linux.
func fileTimes(info fs.FileInfo) (mtime, ctime time.Time, ok bool) {
	st, good := info.Sys().(*syscall.Stat_t)
	if !good {
		return info.ModTime(), time.Time{}, false
	}
	return info.ModTime(), time.Unix(st.Ctim.Sec, st.Ctim.Nsec), true
}

// fileOwner returns the numeric uid/gid of a file.
func fileOwner(info fs.FileInfo) (uid, gid uint32, ok bool) {
	st, good := info.Sys().(*syscall.Stat_t)
	if !good {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

// permsMeaningful reports whether FileMode permission bits reflect real
// filesystem ACLs. On Linux they do.
const permsMeaningful = true

// inodeOf identifies a file independently of its path, so a quarantine move can
// be verified as having relocated the same inode.
func inodeOf(info fs.FileInfo) (uint64, bool) {
	st, good := info.Sys().(*syscall.Stat_t)
	if !good {
		return 0, false
	}
	return st.Ino, true
}
