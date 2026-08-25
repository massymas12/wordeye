package agent

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// The catchable signals must actually be caught and reported. An agent that
// dies silently on SIGTERM tells an operator nothing, and SIGTERM is what a
// service stop, a container shutdown and a plain kill all send.
func TestCatchableSignalIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX signals to deliver to ourselves")
	}
	stop := make(chan struct{})
	defer close(stop)

	type result struct {
		rep *TerminationReport
		err error
	}
	done := make(chan result, 1)
	go func() {
		rep, err := WatchTermination(stop)
		done <- result{rep, err}
	}()
	// Let Notify register before the signal is raised, or the default
	// disposition terminates the test binary.
	time.Sleep(300 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("WatchTermination: %v", r.err)
		}
		if r.rep == nil {
			t.Fatal("SIGTERM produced no report; the agent would die silently")
		}
		if r.rep.SignalNum != int(syscall.SIGTERM) {
			t.Errorf("reported signal %d, want %d", r.rep.SignalNum, syscall.SIGTERM)
		}
		if r.rep.Reason == "" {
			t.Error("no reason recorded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the signal was never reported")
	}
}

// Closing the stop channel must unwind cleanly, or every ordinary shutdown
// leaks a goroutine and a signal registration.
func TestWatchTerminationStopsCleanly(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		rep, err := WatchTermination(stop)
		if rep != nil || err != nil {
			t.Errorf("expected a quiet exit, got rep=%v err=%v", rep, err)
		}
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WatchTermination did not return when stopped")
	}
}

// SIGKILL and SIGSTOP must never be claimed as watched. Listing them would
// imply a guarantee that cannot be made: the kernel does not deliver them to
// userspace at all, which is exactly why liveness.go exists.
func TestUncatchableSignalsAreNotClaimed(t *testing.T) {
	for _, s := range watchedSignals {
		if s == syscall.Signal(9) || s == syscall.Signal(19) {
			t.Errorf("%v is in the watch set but cannot be caught", s)
		}
	}
}

// An init system stopping a service is administration. A signal coinciding with
// the web server process tree would mean the stop came from inside the website.
func TestJudgeTerminationDistinguishesAdminFromIntruder(t *testing.T) {
	cases := []struct {
		name       string
		rep        TerminationReport
		suspicious bool
	}{
		{"systemd", TerminationReport{SuspectPID: 1, Suspect: "/usr/lib/systemd/systemd"}, false},
		{"php-fpm", TerminationReport{SuspectPID: 4821, Suspect: "/usr/sbin/php-fpm8.2"}, true},
		{"apache", TerminationReport{SuspectPID: 900, Suspect: "/usr/sbin/apache2"}, true},
		{"nginx", TerminationReport{SuspectPID: 901, Suspect: "/usr/sbin/nginx"}, true},
		{"admin shell", TerminationReport{SuspectPID: 5000, Suspect: "/usr/bin/bash"}, false},
		{"unattributed", TerminationReport{}, false},
	}
	for _, c := range cases {
		got, reason := judgeTermination(&c.rep)
		if got != c.suspicious {
			t.Errorf("%s: suspicious = %v, want %v (%s)", c.name, got, c.suspicious, reason)
		}
		if reason == "" {
			t.Errorf("%s: no reason given", c.name)
		}
	}
}
