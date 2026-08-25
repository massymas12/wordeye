//go:build !linux

package agent

import (
	"context"

	"wordeye/internal/model"
)

// Non-Linux stubs. The agent is built for Linux hosts; these exist so the
// project compiles and tests on a workstation. Every stubbed check reports
// itself as skipped rather than silently passing — a check that did not run
// must never look like a check that found nothing.

type procInfo struct {
	PID        int
	PPID       int
	Comm       string
	Argv0      string
	Cmdline    string
	Exe        string
	ExeDeleted bool
	Cwd        string
	UID        uint32
	State      string
	SockInodes []uint64
	StartTicks uint64
}

func (p *procInfo) IsKernelThread() bool { return false }

func readProcs() []*procInfo { return nil }

func readProc(int) *procInfo { return nil }

func (a *Agent) checkOSPersistence(context.Context) {
	a.rep.AddCheck(model.CheckStatus{
		ID: "osp", State: model.CheckUnavailable,
		Reason: "OS persistence checks require Linux (/proc)",
	})
}

func (a *Agent) checkNetwork(context.Context) {
	a.rep.AddCheck(model.CheckStatus{
		ID: "net", State: model.CheckUnavailable,
		Reason: "socket enumeration requires Linux (/proc/net)",
	})
}
