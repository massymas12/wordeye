package agent

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// Knowing how the agent died.
//
// An intruder who finds an EDR agent on a host they control will try to stop
// it, and nothing running as an unprivileged user can prevent that. What it CAN
// do is refuse to die quietly. Three layers, because no single mechanism covers
// every way a process ends:
//
//  1. Catchable signals - SIGTERM, SIGINT, SIGHUP, SIGQUIT - are reported
//     before the agent exits.
//
//  2. SIGKILL cannot be caught. The kernel does not deliver it to userspace, so
//     nothing reports it from inside the dying process. Instead the agent
//     records a clean-shutdown marker on a deliberate exit, and the ABSENCE of
//     that marker on the next start is the evidence. See liveness.go: silence
//     becomes the signal.
//
//  3. The console notices hosts that stop reporting at all. An agent that
//     neither says goodbye nor comes back is the loudest case, and only the
//     server can see it.
//
// On the sender identity: the kernel knows it and struct signalfd_siginfo
// carries it, but signalfd is not usable from Go. The runtime installs its own
// handlers and deliberately unblocks signals on the threads it creates, so a
// process-directed signal reaches a runtime thread before any descriptor we
// block it on. Measured: it killed the test binary outright instead of being
// captured. The signal is therefore reported reliably through os/signal, and
// attribution is a separate, clearly-labelled best effort.

var watchedSignals = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
}

// TerminationReport describes how the agent was asked to stop.
type TerminationReport struct {
	Signal    string `json:"signal"`
	SignalNum int    `json:"signal_num"`
	// Suspect is best-effort and may be empty. It is never presented as
	// certainty: the kernel does not hand a signal sender to a Go process, so
	// this is inference from what is running nearby.
	Suspect    string `json:"suspect,omitempty"`
	SuspectPID int    `json:"suspect_pid,omitempty"`
	Suspicious bool   `json:"suspicious"`
	Reason     string `json:"reason"`
}

// WatchTermination blocks until a stop signal arrives or stop is closed.
func WatchTermination(stop <-chan struct{}) (*TerminationReport, error) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, watchedSignals...)
	defer signal.Stop(ch)

	select {
	case <-stop:
		return nil, nil
	case s := <-ch:
		sig, _ := s.(syscall.Signal)
		r := &TerminationReport{Signal: s.String(), SignalNum: int(sig)}
		r.SuspectPID, r.Suspect = attributeSignal()
		r.Suspicious, r.Reason = judgeTermination(r)
		return r, nil
	}
}

// judgeTermination decides whether being asked to stop is routine or alarming.
//
// The distinction is who plausibly asked. An init system stopping a service
// during a deploy is administration. A signal coinciding with the web server
// process tree would mean an intruder used the website to silence the thing
// watching them, which is only possible if code execution already happened.
func judgeTermination(r *TerminationReport) (bool, string) {
	exe := strings.ToLower(r.Suspect)
	switch {
	case exe == "":
		return false, "the agent was asked to stop and the sender could not be identified, " +
			"which is the normal shape of an ordinary service stop"
	case r.SuspectPID == 1 || strings.HasSuffix(exe, "/systemd") || strings.HasSuffix(exe, "/init"):
		return false, "consistent with the init system stopping a service"
	case containsAny(exe, "php", "httpd", "apache", "nginx", "litespeed", "fpm"):
		return true, "a process in the web server tree (" + r.Suspect + ") was signalling around this " +
			"moment, which would mean the stop came from code running inside the website"
	default:
		return false, "stop requested; the nearest signalling process was " + r.Suspect
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
