//go:build !linux

package agent

import (
	"context"

	"wordeye/internal/model"
)

// Workstation stubs. Environment detection and memory-mapping inspection both
// depend on procfs.

func DetectEnvironment() *model.Environment {
	return &model.Environment{MemoryReason: "process inspection requires Linux"}
}

func (a *Agent) checkMemory(context.Context) {
	a.rep.AddCheck(model.CheckStatus{
		ID: "mem.mappings", State: model.CheckUnavailable,
		Reason: "memory mapping inspection requires Linux (/proc)",
	})
}
