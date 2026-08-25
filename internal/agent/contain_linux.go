//go:build linux

package agent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	sigSTOP = syscall.SIGSTOP
	sigKILL = syscall.SIGKILL
)

func signalProcess(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// procStillIs guards against PID reuse. Between detection and containment the
// original process may have exited and its PID been recycled by something
// innocent; signalling blindly would then kill an unrelated process. Comparing
// the kernel's own comm is a cheap, effective guard.
func procStillIs(pid int, comm string) bool {
	if comm == "" {
		return true
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == comm
}

// captureProcess preserves volatile state that ceases to exist the moment the
// process is killed. Called while the target is SIGSTOPped, so nothing changes
// underneath it.
func captureProcess(pid int, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	base := "/proc/" + strconv.Itoa(pid)

	// Plain text artefacts. environ frequently holds C2 configuration, and maps
	// reveals injected libraries.
	for _, name := range []string{"cmdline", "environ", "maps", "status", "stat", "io", "wchan", "limits"} {
		b, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			continue
		}
		// cmdline and environ are NUL-separated; make them readable.
		if name == "cmdline" || name == "environ" {
			b = []byte(strings.ReplaceAll(string(b), "\x00", "\n"))
		}
		_ = os.WriteFile(filepath.Join(dir, name+".txt"), b, 0o600)
	}

	// Symlink targets.
	var links []string
	for _, name := range []string{"exe", "cwd", "root"} {
		if l, err := os.Readlink(filepath.Join(base, name)); err == nil {
			links = append(links, name+" -> "+l)
		}
	}
	// Open file descriptors, including socket inodes.
	if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		for _, e := range entries {
			if l, err := os.Readlink(filepath.Join(base, "fd", e.Name())); err == nil {
				links = append(links, "fd/"+e.Name()+" -> "+l)
			}
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "links.txt"), []byte(strings.Join(links, "\n")), 0o600)

	// The executable image itself. Reading through /proc/PID/exe works even
	// when the binary has been unlinked from disk, which is precisely the case
	// where it is the only copy left in existence.
	if err := copyExe(filepath.Join(base, "exe"), filepath.Join(dir, "exe.bin")); err != nil {
		_ = os.WriteFile(filepath.Join(dir, "exe.error.txt"), []byte(err.Error()), 0o600)
	}
	return nil
}

func copyExe(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	defer dst.Close()
	// Bound the copy: a captured image should never be able to fill the disk.
	n, err := io.Copy(dst, io.LimitReader(src, 256<<20))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("exe image was empty")
	}
	return nil
}

// findRespawn looks for the same implant running under a new PID. A respawn
// means the launcher is still live, which is a more actionable finding than the
// kill that preceded it.
func findRespawn(oldPID int, comm, exe string) int {
	for _, p := range readProcs() {
		if p.PID == oldPID || p.PID == os.Getpid() {
			continue
		}
		if comm != "" && p.Comm == comm {
			return p.PID
		}
		if exe != "" && p.Exe == exe {
			return p.PID
		}
	}
	return 0
}
