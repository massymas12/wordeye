//go:build !linux

package agent

// attributeSignal has no portable implementation; only Linux exposes the
// process table in a form worth reading here.
func attributeSignal() (int, string) { return 0, "" }
