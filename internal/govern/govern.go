// Package govern keeps WordEye from becoming the incident.
//
// These are live production websites on shared or managed hosting with hard CPU
// and IO ceilings. A scanner that saturates the box has taken the site down
// just as surely as the malware would have. Every expensive operation in the
// agent passes through a Governor, which enforces three independent limits:
//
//  1. Concurrency — a deliberately small worker pool, sized to leave headroom
//     rather than to consume the machine.
//  2. IO rate — a token bucket over bytes read, so a 40GB uploads tree cannot
//     monopolise the disk.
//  3. System load — an adaptive sampler that pauses scanning outright when the
//     box is already busy serving real traffic.
//
// The third is the important one: it means the agent's impact is a function of
// how idle the server is, not of how big the site is.
package govern

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

type Profile string

const (
	// ProfileSafe is for production hosts under load or during business hours.
	ProfileSafe Profile = "safe"
	// ProfileBalanced is the default: noticeably faster than the bash script
	// while still yielding to the web server.
	ProfileBalanced Profile = "balanced"
	// ProfileFast removes the brakes. For maintenance windows, staging, or a
	// host already taken out of the load-balancer pool.
	ProfileFast Profile = "fast"
)

type Config struct {
	Workers int
	// MaxLoadPerCore pauses scanning while loadavg(1m)/NumCPU exceeds this.
	// Zero disables load-based throttling.
	MaxLoadPerCore float64
	// IOBytesPerSec caps file-read throughput. Zero means unlimited.
	IOBytesPerSec int64
	// Nice is the process priority adjustment (higher = more polite).
	Nice int
	// MemLimitMB sets a soft Go heap ceiling so the agent cannot OOM the box.
	MemLimitMB int64
	// Deadline bounds the whole run. A scan that never finishes is an outage
	// waiting to happen.
	Deadline time.Duration
}

// ForProfile returns tuned defaults. Workers are kept far below NumCPU on
// purpose — the goal is to finish without the site's visitors noticing, not to
// finish as fast as the hardware allows.
func ForProfile(p Profile) Config {
	// The CPUs this process may actually use, not the host's. See
	// cpuquota_linux.go: sizing from runtime.NumCPU() inside a quota-limited
	// container is what let a scan take a shared host to 2.2x overload.
	n := usableCPUs()
	switch p {
	case ProfileSafe:
		return Config{
			Workers:        1,
			MaxLoadPerCore: 0.6,
			IOBytesPerSec:  8 << 20,
			Nice:           15,
			MemLimitMB:     128,
			Deadline:       45 * time.Minute,
		}
	case ProfileFast:
		return Config{
			Workers:        n,
			MaxLoadPerCore: 0,
			IOBytesPerSec:  0,
			Nice:           0,
			MemLimitMB:     1024,
			Deadline:       30 * time.Minute,
		}
	default: // balanced
		w := n / 4
		if w < 2 {
			w = 2
		}
		if w > 4 {
			w = 4
		}
		// Never over-subscribe the allowance. The floor above assumes at least
		// two cores are available; inside a 1-CPU container it would otherwise
		// open two workers for one core — 200% of quota, which is how a scan
		// saturates a site container and drags on its neighbours.
		if w > n {
			w = n
		}
		return Config{
			Workers:        w,
			MaxLoadPerCore: 1.5,
			IOBytesPerSec:  48 << 20,
			Nice:           10,
			MemLimitMB:     256,
			Deadline:       30 * time.Minute,
		}
	}
}

func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileSafe, ProfileBalanced, ProfileFast:
		return Profile(s), nil
	case "":
		return ProfileBalanced, nil
	}
	return "", fmt.Errorf("unknown profile %q (want safe|balanced|fast)", s)
}

type Governor struct {
	cfg Config

	mu       sync.Mutex
	tokens   float64
	last     time.Time
	capacity float64

	throttled   atomic.Bool
	pausedNanos atomic.Int64
	loadMilli   atomic.Int64 // current 1m loadavg × 1000

	// usingPSI records which contention signal is in use, and pressure holds
	// the PSI reading × 100. Reported, because "we throttled" means something
	// very different depending on which signal drove it.
	usingPSI atomic.Bool
	pressure atomic.Int64
	// gaveUp is set when load-based pausing consumed more of the run than it
	// was worth and the gate switched itself off.
	gaveUp  atomic.Bool
	started time.Time

	stop chan struct{}
	once sync.Once
}

func New(cfg Config) *Governor {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	g := &Governor{
		cfg:      cfg,
		last:     time.Now(),
		started:  time.Now(),
		capacity: float64(cfg.IOBytesPerSec) * 2,
		stop:     make(chan struct{}),
	}
	g.tokens = g.capacity

	if cfg.MemLimitMB > 0 {
		debug.SetMemoryLimit(cfg.MemLimitMB << 20)
	}
	if cfg.Nice > 0 {
		// Best-effort: some containers forbid it, which is not fatal.
		_ = setNice(cfg.Nice)
	}
	if cfg.MaxLoadPerCore > 0 {
		go g.sampleLoad()
	}
	return g
}

func (g *Governor) Workers() int   { return g.cfg.Workers }
func (g *Governor) Config() Config { return g.cfg }

// Close stops background sampling.
func (g *Governor) Close() { g.once.Do(func() { close(g.stop) }) }

// maxPressurePct is the PSI threshold: the share of the last 10 seconds during
// which some task was stalled waiting for CPU. Above this the machine is
// genuinely contended and the scan should yield.
const maxPressurePct = 40.0

func (g *Governor) sampleLoad() {
	ncpu := float64(runtime.NumCPU())
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			// Prefer PSI. Inside a container /proc/loadavg reports the HOST's
			// run queue unless lxcfs masks it, so on shared hosting a per-core
			// threshold is exceeded essentially always — throttling the scan
			// against contention it neither causes nor can relieve. PSI is
			// delegated per-cgroup and reflects contention this workload is
			// actually part of.
			if p, ok := cpuPressure(); ok {
				g.usingPSI.Store(true)
				g.pressure.Store(int64(p * 100))
				g.throttled.Store(p > maxPressurePct)
				continue
			}
			l1, ok := loadAvg1()
			if !ok {
				continue
			}
			g.loadMilli.Store(int64(l1 * 1000))
			g.throttled.Store(l1/ncpu > g.cfg.MaxLoadPerCore)
		}
	}
}

// throttleBudgetExceeded reports whether load-based pausing has consumed so
// much of the run that it has stopped being politeness and become failure.
//
// This is the safety valve. If the contention signal is wrong — which it is by
// default inside a container reading the host's loadavg — the scan would
// otherwise crawl indefinitely while appearing healthy. Past the budget the
// gate gives up, and the report says it did.
func (g *Governor) throttleBudgetExceeded() bool {
	elapsed := time.Since(g.started)
	if elapsed < 60*time.Second {
		return false
	}
	paused := time.Duration(g.pausedNanos.Load())
	return paused > elapsed/2
}

// Gate blocks until it is acceptable to read n more bytes. It returns an error
// only if ctx is cancelled, so callers can treat it as a simple checkpoint.
//
// Two waits are combined here: a hard pause while the machine is over its load
// target, and a token-bucket wait for IO budget.
func (g *Governor) Gate(ctx context.Context, n int64) error {
	// Load pause. Poll rather than signal: the wait is inherently coarse and
	// this keeps the sampler lock-free.
	for g.throttled.Load() && !g.gaveUp.Load() {
		// Safety valve. If the contention signal is wrong — which it is by
		// default inside a container reading the host's loadavg — this loop
		// would otherwise pace the entire scan against a number that has
		// nothing to do with us. Past the budget the gate switches itself off
		// and says so in the report, rather than crawling while looking healthy.
		if g.throttleBudgetExceeded() {
			g.gaveUp.Store(true)
			break
		}
		start := time.Now()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		g.pausedNanos.Add(int64(time.Since(start)))
	}

	if g.cfg.IOBytesPerSec <= 0 {
		return nil
	}
	for {
		g.mu.Lock()
		now := time.Now()
		g.tokens += now.Sub(g.last).Seconds() * float64(g.cfg.IOBytesPerSec)
		g.last = now
		if g.tokens > g.capacity {
			g.tokens = g.capacity
		}
		want := float64(n)
		// A single file larger than the bucket must not deadlock; let it
		// through once the bucket is full.
		if want > g.capacity {
			want = g.capacity
		}
		if g.tokens >= want {
			g.tokens -= want
			g.mu.Unlock()
			return nil
		}
		deficit := want - g.tokens
		wait := time.Duration(deficit / float64(g.cfg.IOBytesPerSec) * float64(time.Second))
		g.mu.Unlock()

		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		if wait > 2*time.Second {
			wait = 2 * time.Second
		}
		start := time.Now()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		g.pausedNanos.Add(int64(time.Since(start)))
	}
}

// Stats reports how much the governor held the scan back. Surfaced in the
// report so a slow scan is legible as "the box was busy" rather than "the agent
// is broken".
type Stats struct {
	PausedMS       int64   `json:"paused_ms"`
	LoadAvg1       float64 `json:"load_avg_1m"`
	Throttling     bool    `json:"throttling"`
	Workers        int     `json:"workers"`
	IOBytesPerSec  int64   `json:"io_bytes_per_sec"`
	MaxLoadPerCore float64 `json:"max_load_per_core"`

	// UsingPSI reports which contention signal drove throttling. Inside a
	// container this matters a great deal: PSI is cgroup-scoped and meaningful,
	// loadavg usually reflects the host and is not.
	UsingPSI    bool    `json:"using_psi"`
	PressurePct float64 `json:"cpu_pressure_pct"`
	// ThrottleGaveUp is set when pausing consumed more than half the run and
	// the gate disabled itself.
	ThrottleGaveUp bool `json:"throttle_gave_up"`
}

func (g *Governor) Stats() Stats {
	return Stats{
		PausedMS:       g.pausedNanos.Load() / int64(time.Millisecond),
		LoadAvg1:       float64(g.loadMilli.Load()) / 1000,
		Throttling:     g.throttled.Load(),
		Workers:        g.cfg.Workers,
		IOBytesPerSec:  g.cfg.IOBytesPerSec,
		MaxLoadPerCore: g.cfg.MaxLoadPerCore,
		UsingPSI:       g.usingPSI.Load(),
		PressurePct:    float64(g.pressure.Load()) / 100,
		ThrottleGaveUp: g.gaveUp.Load(),
	}
}

// LoadAvg1 exposes the 1-minute load average for heartbeat reporting. Returns
// false where the platform does not provide one.
func LoadAvg1() (float64, bool) { return loadAvg1() }
