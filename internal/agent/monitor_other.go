//go:build !linux

package agent

import (
	"context"
	"errors"
	"time"
)

// Monitor requires inotify, which is Linux-only.
func (a *Agent) Monitor(context.Context, time.Duration) error {
	return errors.New("monitor mode requires Linux (inotify)")
}
