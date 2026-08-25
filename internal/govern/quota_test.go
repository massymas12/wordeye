package govern

import (
	"runtime"
	"testing"
)

// Resource sizing on shared hosting.
//
// A field deployment on managed WordPress hosting ran roughly 2.8 cores of
// scanning and took the shared physical host from loadavg ~5 to ~18 — 2.2x
// overload for every tenant on the machine. Three separate blind spots caused
// it, and all three come from the agent believing it owns the hardware:
//
//   - runtime.NumCPU() reports the HOST's cores, so a 1-CPU container sized its
//     worker pool from 32.
//   - MaxLoadPerCore divides by that same wrong count, so the load throttle's
//     threshold was never reachable.
//   - PSI inside the container reported ~5% pressure while the host was
//     genuinely saturated.
//
// The agent must therefore size itself from what it is ALLOWED, not what it can
// see, and its resident profile must be gentle by construction.

func TestUsableCPUsNeverExceedsHost(t *testing.T) {
	n := usableCPUs()
	if n < 1 {
		t.Errorf("usableCPUs() = %d, must be at least 1", n)
	}
	if n > runtime.NumCPU() {
		t.Errorf("usableCPUs() = %d exceeds the host's %d", n, runtime.NumCPU())
	}
}

// The resident profile is what runs unattended on a customer's production site.
// Every knob in it must be conservative; this is the profile whose defaults
// decide whether the product is safe to leave running.
func TestSafeProfileIsGentle(t *testing.T) {
	c := ForProfile(ProfileSafe)
	if c.Workers != 1 {
		t.Errorf("safe uses %d workers; a resident sweep should use one", c.Workers)
	}
	if c.IOBytesPerSec <= 0 || c.IOBytesPerSec > 16<<20 {
		t.Errorf("safe IO budget is %d bytes/s; expected a real cap under 16MB/s", c.IOBytesPerSec)
	}
	if c.Nice < 10 {
		t.Errorf("safe nice is %d; a background sweep should yield to the web server", c.Nice)
	}
}

// Worker counts must stay bounded regardless of how large the host looks. A
// 96-core machine must not persuade a site container to open 24 workers.
func TestWorkerCountsAreBounded(t *testing.T) {
	for _, p := range []Profile{ProfileSafe, ProfileBalanced} {
		c := ForProfile(p)
		if c.Workers < 1 {
			t.Errorf("%s: %d workers", p, c.Workers)
		}
		if c.Workers > 4 {
			t.Errorf("%s: %d workers is too many for a host that is also serving a website", p, c.Workers)
		}
		if c.Workers > usableCPUs() && usableCPUs() >= 1 {
			t.Errorf("%s: %d workers exceeds the %d CPUs this process may use",
				p, c.Workers, usableCPUs())
		}
	}
}

// Every profile that is not explicitly "remove the brakes" must cap IO. An
// uncapped sweep is indistinguishable from a backup job to the disk it shares.
func TestOnlyFastRemovesTheBrakes(t *testing.T) {
	if ForProfile(ProfileFast).IOBytesPerSec != 0 {
		t.Error("fast is documented as unthrottled")
	}
	for _, p := range []Profile{ProfileSafe, ProfileBalanced} {
		if ForProfile(p).IOBytesPerSec <= 0 {
			t.Errorf("%s does not cap IO", p)
		}
	}
}
