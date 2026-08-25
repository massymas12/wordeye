package agent

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wordeye/internal/govern"
	"wordeye/internal/model"
	"wordeye/internal/rules"
	"wordeye/internal/yara"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

type Config struct {
	Mode    string // scan|baseline|verify|monitor
	Webroot string
	Home    string
	Label   string

	Packs   []string
	Profile govern.Profile
	Gov     govern.Config

	// MaxFileSize bounds how much of any single file is examined. Files larger
	// than this are read up to the cap and marked truncated rather than
	// skipped, so an attacker cannot hide behind a padded file.
	MaxFileSize int64

	// Quick drops the expensive sweeps (media/cache trees, checksum
	// verification) for a fast triage pass on a heavily loaded host.
	Quick bool

	SkipFS    bool
	SkipDB    bool
	SkipOS    bool
	SkipNet   bool
	SkipProbe bool
	UseWPCLI  bool

	BaselinePath string
	EvidenceDir  string

	// YaraPaths are additional .yar files or directories to load alongside the
	// built-in ruleset. DisableYara turns the engine off entirely.
	YaraPaths   []string
	DisableYara bool

	// Offline suppresses every outbound request. Provenance then reports itself
	// as unavailable rather than silently verifying nothing.
	Offline bool
	// SkipProvenance disables the expected-set comparison entirely.
	SkipProvenance bool

	// VendorPacks are estate-consensus attestation files for code that
	// publishes no checksums (premium plugins, a host's own mu-plugin). They
	// travel with the binary so a standalone agent can still benefit from what
	// the fleet knows.
	VendorPacks []string

	// Containment. Off unless explicitly requested; DryRun produces the full
	// ordered plan without executing any step.
	Contain       bool
	ContainDryRun bool
	MaxActions    int
	HealthURL     string

	DBHost, DBName, DBUser, DBPass, DBPrefix string
}

type Agent struct {
	cfg  Config
	gov  *govern.Governor
	set  *rules.Set
	lits *literalIDs
	rep  *model.Report

	// yara is the compiled YARA ruleset; nil when disabled. yaraLit maps each
	// of its literals to a prefilter automaton id.
	yara    *yara.Set
	yaraLit map[string]int

	// dedupe suppresses repeat findings for the same rule+path, which happens
	// when the monitor mode re-observes a file or several checks converge on
	// one artefact.
	seen sync.Map

	// hashes accumulates sha256 -> paths for baseline writing and for the
	// controller's cross-site correlation.
	hashMu sync.Mutex
	hashes map[string]string

	// sink streams findings as they are discovered; see SetSink.
	sink FindingSink

	// procCache holds the single process snapshot taken during the OS checks.
	// The network check joins against it to attribute sockets to PIDs, and the
	// containment engine reuses it rather than re-reading /proc, so the picture
	// stays internally consistent.
	// Guarded: the periodic full sweep and the monitor's own process poll both
	// refresh this, and they run on different goroutines. The race detector
	// caught them writing it concurrently — a torn slice header here would be
	// read by the memory and network checks as a live process list.
	// prov is replaced wholesale by the periodic sweep goroutine while the
	// inotify event loop reads it on every real-time evaluation. Unsynchronised
	// this is a race with a wrong-output failure mode, not just a detector
	// warning: a shell written at the instant provenance reloads is judged
	// against a nil or half-built set, so the file is scored as if no publisher
	// authority existed — or a stock core file is re-analysed and reported
	// critical, which is the false-positive wall provenance exists to stop.
	provMu    sync.RWMutex
	procMu    sync.RWMutex
	procCache []*procInfo

	// The site's own URL, resolved once from the database and reused by both
	// the cloak probe and the containment health gate.
	urlOnce   sync.Once
	cachedURL string

	// env records where we are running and what that prevents us from seeing.
	env *model.Environment

	// monitorWatchSummary describes how much of the tree real-time monitoring
	// actually covers. Monitor mode runs forever and never emits its report, so
	// without surfacing this the one number that says whether monitoring works
	// is written somewhere nobody ever reads.
	// Written by Monitor on its own goroutine and read by the report and
	// heartbeat paths, so it needs synchronisation. The race detector caught it
	// under load: a torn string header would be read as coverage text.
	monitorWatchSummary atomic.Value // string

	// provFetch is injectable so provenance comparison can be tested without
	// reaching the network.
	provFetch provFetcher

	// prov is the expected set, built BEFORE the sweep so the sweep can use it
	// to exonerate verified files rather than re-analysing them.
	prov *provenanceSet

	// vendor holds estate-consensus attestations for code that publishes no
	// checksums; vendorAttested records which paths it vouched for.
	vendor         *VendorPack
	vendorAttested vendorAttestations
	provAttested   atomic.Int64

	provVerified atomic.Int64
	// provVerifiedPaths records which files matched their published manifest,
	// so post-sweep passes can exonerate them too. Exoneration is not only for
	// the content engines: a file byte-identical to its published release did
	// not have its timestamps forged by an attacker either.
	provVerifiedPaths sync.Map
	provModified      atomic.Int64
	provUnexpected    atomic.Int64
	provUncovered     atomic.Int64

	// Live counters, readable while the sweep runs so the CLI can report
	// progress. A six-minute silent scan is indistinguishable from a hang.
	filesSeen atomic.Int64
	filesRead atomic.Int64
	bytesRead atomic.Int64
	// filesSkippedType counts non-executable files that Quick mode header-probed
	// instead of analysing in full. Reported so the scope of a quick scan is
	// visible rather than implied.
	filesSkippedType atomic.Int64
	// ww accumulates world-writable PHP files so they are reported as one
	// property of the install rather than one finding per file.
	ww wwAccum

	// Per-phase nanoseconds, so slowness can be attributed rather than guessed.
	nsLex     atomic.Int64
	nsRules   atomic.Int64
	nsHeur    atomic.Int64
	nsYara    atomic.Int64
	nsDecode  atomic.Int64
	nsProv    atomic.Int64
	slowFiles atomic.Int64
}

// Progress reports live sweep counters for the CLI.
func (a *Agent) Progress() (seen, read, bytes int64) {
	return a.filesSeen.Load(), a.filesRead.Load(), a.bytesRead.Load()
}

// perFileBudget caps analysis of any single file. One pathological file must
// not be able to stall an entire scan; cutting it short and SAYING SO is the
// honest failure mode.
const perFileBudget = 2 * time.Second

func (a *Agent) recordPhases() {
	ms := func(v *atomic.Int64) int64 { return v.Load() / int64(time.Millisecond) }
	g := a.gov.Stats()
	a.rep.Stats.Phases = model.PhaseTiming{
		ThrottlePausedMS: g.PausedMS,
		LoadAvg1:         g.LoadAvg1,
		MaxLoadPerCore:   g.MaxLoadPerCore,
		Workers:          g.Workers,
		UsingPSI:         g.UsingPSI,
		CPUPressurePct:   g.PressurePct,
		ThrottleGaveUp:   g.ThrottleGaveUp,
		LexMS:            ms(&a.nsLex),
		RulesMS:          ms(&a.nsRules),
		HeuristicMS:      ms(&a.nsHeur),
		YaraMS:           ms(&a.nsYara),
		DecodeMS:         ms(&a.nsDecode),
		ProvenanceMS:     ms(&a.nsProv),
		Exonerated:       a.provVerified.Load(),
		SlowFiles:        a.slowFiles.Load(),
	}
}

// MonitorWatchSummary reports real-time coverage once Monitor has started.
func (a *Agent) MonitorWatchSummary() string {
	s, _ := a.monitorWatchSummary.Load().(string)
	return s
}

// setMonitorWatchSummary records coverage from the monitor goroutine.
func (a *Agent) setMonitorWatchSummary(s string) { a.monitorWatchSummary.Store(s) }

// SetProvenanceFetcher overrides how manifests are retrieved. Test-only.
func (a *Agent) SetProvenanceFetcher(f provFetcher) { a.provFetch = f }

func New(cfg Config) (*Agent, error) {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 4 << 20
	}
	if len(cfg.Packs) == 0 {
		cfg.Packs = []string{"core"}
	}
	if cfg.Home == "" {
		cfg.Home = homeDir()
	}

	// YARA loads first so its literals can be folded into the same prefilter
	// automaton as the rule gates and heuristic vocabulary — one pass per file
	// covers all three engines.
	var (
		yaraSet  *yara.Set
		yaraWarn []string
	)
	if !cfg.DisableYara {
		var err error
		yaraSet, yaraWarn, err = yara.LoadPaths(cfg.YaraPaths, true)
		if err != nil {
			return nil, fmt.Errorf("loading yara rules: %w", err)
		}
	}

	extras := HeuristicLiterals()
	if yaraSet != nil {
		extras = append(extras, yaraSet.Literals()...)
	}

	set, err := rules.Load(cfg.Packs, extras)
	if err != nil {
		return nil, fmt.Errorf("loading rule packs: %w", err)
	}

	host, _ := os.Hostname()
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}

	a := &Agent{
		cfg:    cfg,
		gov:    govern.New(cfg.Gov),
		set:    set,
		yara:   yaraSet,
		hashes: map[string]string{},
	}
	a.lits = resolveLiterals(set)

	// Resolve every YARA literal to its automaton id once, so the per-file gate
	// is a slice lookup rather than a search.
	if yaraSet != nil {
		a.yaraLit = make(map[string]int)
		for _, l := range yaraSet.Literals() {
			a.yaraLit[l] = set.LiteralID(l)
		}
	}

	if vp, err := LoadVendorPacks(cfg.VendorPacks); err != nil {
		return nil, err
	} else {
		a.vendor = vp
	}

	a.env = DetectEnvironment()

	a.rep = &model.Report{
		Schema:       model.SchemaVersion,
		AgentVersion: Version,
		Mode:         cfg.Mode,
		Host:         host,
		Webroot:      cfg.Webroot,
		Site:         siteName(cfg.Webroot),
		Label:        cfg.Label,
		StartedAt:    time.Now().UTC(),
	}
	a.rep.Environment = a.env
	for _, p := range set.Info() {
		a.rep.RulePacks = append(a.rep.RulePacks, model.RulePackInfo{
			Name: p.Name, Version: p.Version, SHA256: p.SHA256, Rules: p.Rules,
		})
	}
	if yaraSet != nil {
		a.rep.RulePacks = append(a.rep.RulePacks, model.RulePackInfo{
			Name: "yara", Version: "builtin", Rules: len(yaraSet.Rules),
		})
	}
	// A ruleset that failed to load protects nobody. Surface it loudly rather
	// than letting the operator assume coverage they do not have.
	for _, w := range yaraWarn {
		a.rep.AddError("yara ruleset NOT loaded — " + w)
	}
	return a, nil
}

func (a *Agent) Report() *model.Report { return a.rep }
func (a *Agent) Rules() *rules.Set     { return a.set }
func (a *Agent) Close()                { a.gov.Close() }

// Run executes the configured mode and returns the finished report.
func (a *Agent) Run(ctx context.Context) (*model.Report, error) {
	if a.cfg.Gov.Deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.cfg.Gov.Deadline)
		defer cancel()
	}

	switch a.cfg.Mode {
	case "baseline":
		a.runBaseline(ctx)
	case "verify":
		a.runVerify(ctx)
	default: // scan
		a.runScan(ctx)
	}

	// Containment runs last: every detection must exist before we decide what
	// to act on, and acting mid-scan would corrupt the evidence picture.
	if a.cfg.Contain {
		a.runContainment(ctx)
	}

	a.recordPhases()
	a.applyCoverage()
	a.rep.Finalize()
	if err := ctx.Err(); err != nil {
		a.rep.AddError("run did not complete: " + err.Error())
		// Recompute so the verdict degrades to "partial" rather than "clean".
		a.rep.Finalize()
	}
	return a.rep, nil
}

func (a *Agent) runScan(ctx context.Context) {
	// Provenance FIRST. The sweep consults it to skip files that match their
	// published release, so it has to exist before the sweep starts.
	if !a.cfg.SkipProvenance {
		a.loadProvenance(ctx)
	}
	if !a.cfg.SkipFS {
		a.scanFilesystem(ctx)
		a.checkWordPress(ctx)
	}
	if !a.cfg.SkipProvenance {
		a.reportProvenance()
	}
	if !a.cfg.SkipOS {
		a.checkOSPersistence(ctx)
		a.checkMemory(ctx)
	}
	if !a.cfg.SkipNet {
		a.checkNetwork(ctx)
	}
	if !a.cfg.SkipDB {
		a.checkDatabase(ctx)
	}
	if !a.cfg.SkipProbe {
		a.checkCloak(ctx)
	}
	if a.cfg.UseWPCLI && !a.cfg.Quick {
		a.checkIntegrity(ctx)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// timed records a CheckStatus for a check function, so the report can always
// distinguish "ran and was clean" from "never ran".
func (a *Agent) timed(id string, fn func() (model.CheckState, string)) {
	start := time.Now()
	before := a.rep.FindingCount()
	state, reason := fn()
	a.rep.AddCheck(model.CheckStatus{
		ID:       id,
		State:    state,
		Reason:   reason,
		Findings: a.rep.FindingCount() - before,
		Duration: time.Since(start).Round(time.Millisecond).String(),
	})
}

// emit records a finding unless an identical one was already reported.
func (a *Agent) emit(f model.Finding) {
	key := f.RuleID + "\x00" + f.Path
	if f.ContainPID != 0 {
		key = fmt.Sprintf("%s\x00%d", key, f.ContainPID)
	}
	if _, dup := a.seen.LoadOrStore(key, true); dup {
		return
	}
	a.rep.AddFinding(f)
	if a.sink != nil {
		a.sink(f)
	}
}

// sink, when set, streams findings as they are discovered. The monitor mode and
// the SIEM emitters use this so detections leave the host immediately rather
// than at the end of a long scan.
type FindingSink func(model.Finding)

func (a *Agent) SetSink(s FindingSink) { a.sink = s }

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return os.Getenv("HOME")
}

// siteName derives a human label from the webroot. Hosting layouts put the site
// identifier one level above the document root (/www/<site>/public), so prefer
// the parent unless it is a generic container.
func siteName(root string) string {
	if root == "" {
		return ""
	}
	root = filepath.Clean(root)
	base := filepath.Base(root)
	parent := filepath.Base(filepath.Dir(root))
	switch strings.ToLower(base) {
	case "public", "public_html", "html", "www", "htdocs", "web":
		if parent != "" && parent != "." && parent != string(filepath.Separator) {
			return parent
		}
	}
	return base
}

// applyCoverage annotates each check with what it was actually able to observe,
// and records the limitation as a finding.
//
// This exists because "ran and found nothing" and "ran but could only see one
// namespace" are different claims, and only one of them supports a conclusion
// about the host. Inside a container the OS-level checks are still worth
// running — a shell in this container is exactly what threatens the website —
// but they say nothing about the machine underneath.
func (a *Agent) applyCoverage() {
	if a.env == nil {
		return
	}
	scoped := func(id string) bool {
		return strings.HasPrefix(id, "osp.") ||
			strings.HasPrefix(id, "net.") ||
			strings.HasPrefix(id, "mem.")
	}
	for i := range a.rep.Checks {
		if a.env.Contained && scoped(a.rep.Checks[i].ID) {
			a.rep.Checks[i].Coverage = model.CoverageNamespace
		} else {
			a.rep.Checks[i].Coverage = model.CoverageFull
		}
	}
	if !a.env.Contained {
		return
	}

	detail := a.env.CoverageNote()
	if !a.env.MemoryReadable {
		detail += " Process memory could not be read (" + a.env.MemoryReason +
			"), so only memory MAPPINGS were examined, not their contents."
	}
	if len(a.env.Evidence) > 0 {
		detail += " Detected by: " + strings.Join(a.env.Evidence, "; ") + "."
	}

	a.emit(model.Finding{
		RuleID:     "env.container_scoped_coverage",
		Class:      "ENV",
		Severity:   model.SevInfo,
		Confidence: model.ConfConfirmed,
		Title:      "Scan scope limited to this container",
		Detail:     detail,
		Remediation: "A clean result here means this container is clean, not that the host is. " +
			"For host-level assurance an agent must run on the host itself, which managed hosting does not permit.",
		Meta: map[string]any{
			"runtime": a.env.Runtime, "container_id": a.env.ID,
			"processes_visible": a.env.ProcessesVisible,
			"memory_readable":   a.env.MemoryReadable,
			"pid_namespace":     a.env.PIDNamespace,
			"read_only_root":    a.env.ReadOnlyRoot,
		},
	})
}

// setProcCache replaces the shared process snapshot.
func (a *Agent) setProcCache(procs []*procInfo) {
	a.procMu.Lock()
	a.procCache = procs
	a.procMu.Unlock()
}

// procSnapshot returns the current process list for readers on other
// goroutines. The slice itself is never mutated after publication, so returning
// it directly is safe once the header has been read under the lock.
func (a *Agent) procSnapshot() []*procInfo {
	a.procMu.RLock()
	defer a.procMu.RUnlock()
	return a.procCache
}

// setProvenance publishes a freshly-built provenance set.
func (a *Agent) setProvenance(p *provenanceSet) {
	a.provMu.Lock()
	a.prov = p
	a.provMu.Unlock()
}

// provenance returns the current set for readers on other goroutines. The set
// is never mutated after publication, so the pointer is safe to use once read.
func (a *Agent) provenance() *provenanceSet {
	a.provMu.RLock()
	defer a.provMu.RUnlock()
	return a.prov
}
