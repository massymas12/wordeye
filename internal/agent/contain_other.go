//go:build !linux

package agent

import "errors"

// Process containment is Linux-only. These stubs let the tree build on a
// workstation; they always fail loudly rather than pretending to have contained
// anything.

type signalT int

const (
	sigSTOP signalT = 19
	sigKILL signalT = 9
)

var errNotLinux = errors.New("process containment requires Linux")

func signalProcess(int, signalT) error { return errNotLinux }

func procStillIs(int, string) bool { return false }

func captureProcess(int, string) error { return errNotLinux }

func findRespawn(int, string, string) int { return 0 }
