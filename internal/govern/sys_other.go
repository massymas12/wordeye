//go:build !linux

package govern

// The agent targets Linux hosts; these stubs exist so the tree still builds,
// vets and tests on a Windows or macOS workstation.

func setNice(int) error { return nil }

func loadAvg1() (float64, bool) { return 0, false }

func cpuPressure() (float64, bool) { return 0, false }
