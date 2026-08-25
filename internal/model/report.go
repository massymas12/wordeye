// Package model defines the wire format shared between the WordEye agent and
// the controller. The agent emits exactly one Report as JSON on stdout; the
// controller unmarshals it. Keeping this in one package means the two binaries
// can never drift out of sync.
package model

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is bumped whenever a breaking change is made to Report. The
// controller refuses to aggregate reports whose major version it does not know.
const SchemaVersion = "wordeye.report/1"

// ---------------------------------------------------------------------------
// Severity / confidence
// ---------------------------------------------------------------------------

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank gives a sortable weight, highest = most severe.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// Confidence separates "this IS malware" from "a human needs to look at this".
// Only Confirmed findings are ever eligible for automated action — this
// distinction is what keeps remediation from nuking legitimate plugin code.
type Confidence string

const (
	// ConfConfirmed: the structure of the finding is unambiguous (e.g. a file
	// that is both an asset extension AND starts with <?php AND carries an
	// obfuscation marker). Eligible for auto-quarantine.
	ConfConfirmed Confidence = "confirmed"
	// ConfLikely: strong heuristic signal, but legitimate code could in
	// principle produce it. Never auto-actioned.
	ConfLikely Confidence = "likely"
	// ConfReview: worth a human's eyes, expected to include false positives.
	ConfReview Confidence = "review"
)

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// Finding is a single detection. Path-based findings carry file metadata;
// process/DB/network findings leave those zero and populate Meta instead.
type Finding struct {
	// RuleID is a stable, machine-parseable identifier (e.g.
	// "shell.eval_request_password"). Stable across versions so that
	// suppressions and cross-site correlation keep working.
	RuleID string `json:"rule_id"`
	// Class buckets the finding for reporting: SHELL, CLOAK, OSP, DB, NET, WP.
	Class      string     `json:"class"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail,omitempty"`

	// File metadata, present for filesystem findings.
	Path     string     `json:"path,omitempty"`
	SHA256   string     `json:"sha256,omitempty"`
	Size     int64      `json:"size,omitempty"`
	ModTime  *time.Time `json:"mtime,omitempty"`
	CTime    *time.Time `json:"ctime,omitempty"`
	Mode     string     `json:"mode,omitempty"`
	Line     int        `json:"line,omitempty"`
	Evidence string     `json:"evidence,omitempty"`

	// Remediation is operator-facing guidance.
	Remediation string `json:"remediation,omitempty"`

	// Actionable marks a finding as eligible for automated quarantine or
	// containment. Requires ConfConfirmed; the engine enforces this.
	Actionable bool `json:"actionable"`

	// ContainPID is set for process findings so the containment engine knows
	// what to freeze/kill without re-deriving it.
	ContainPID int `json:"contain_pid,omitempty"`

	// Meta carries check-specific structured data (option names, PIDs, peers).
	Meta map[string]any `json:"meta,omitempty"`
}

// ---------------------------------------------------------------------------
// Check status
// ---------------------------------------------------------------------------

// CheckState distinguishes "ran and found nothing" from "never ran". In IR this
// distinction is everything: a skipped check is not a clean result, and a report
// that cannot express the difference will get someone owned.
type CheckState string

const (
	// CheckOK: the check ran and observed its subject.
	CheckOK CheckState = "ok"
	// CheckUnavailable: the check could NOT observe its subject. This is the
	// state that matters. "crontab -l returned nothing" means "no readable
	// crontab, therefore unknown" — never "no cron, therefore fine". A scanner
	// that cannot tell those apart manufactures false confidence, which is
	// precisely what lets an attacker persist through a clean bill of health.
	CheckUnavailable CheckState = "unavailable"
	// CheckNotApplicable: there was genuinely nothing to observe, and that was
	// itself observed — no redirect plugin is installed, no spam keywords are
	// configured. This does NOT degrade the verdict.
	CheckNotApplicable CheckState = "not_applicable"
	// CheckError: the check failed.
	CheckError CheckState = "error"

	// CheckSkipped is retained as an alias for CheckUnavailable so that any
	// missed call site defaults to the SAFE interpretation (degrades the
	// verdict) rather than the dangerous one.
	CheckSkipped = CheckUnavailable
)

// Coverage qualifies WHAT a check was able to see, which is separate from
// whether it ran. Inside a container an OS-level check runs perfectly well and
// finds nothing — but it has only examined one namespace, and reporting that as
// equivalent to examining the host is how "I could not see" silently becomes
// "there was nothing to see".
type Coverage string

const (
	CoverageFull Coverage = "full"
	// CoverageNamespace means the check saw only this container's namespace.
	CoverageNamespace Coverage = "namespace"
	// CoverageNone means the check could not observe its subject at all.
	CoverageNone Coverage = "none"
)

type CheckStatus struct {
	ID       string     `json:"id"`
	State    CheckState `json:"state"`
	Reason   string     `json:"reason,omitempty"`
	Findings int        `json:"findings"`
	Duration string     `json:"duration,omitempty"`
	// Coverage is empty for checks where the distinction does not apply.
	Coverage Coverage `json:"coverage,omitempty"`
}

// Environment describes where the agent ran and what that context prevented it
// from seeing. Reported verbatim so an operator can judge the scan's scope
// rather than inferring it.
type Environment struct {
	Contained bool   `json:"contained"`
	Runtime   string `json:"runtime,omitempty"`
	// Kind separates a SYSTEM container (LXD/LXC: full init, own cron, own
	// service manager — effectively a lightweight VM) from an APPLICATION
	// container (Docker-style: a handful of processes, no init, no cron).
	//
	// The distinction changes what a check MEANS. In an application container
	// "no crontab" is expected and says nothing. In a system container cron
	// should exist, so failing to read it means we were denied — which is a
	// materially different statement.
	Kind     string   `json:"kind,omitempty"`
	ID       string   `json:"container_id,omitempty"`
	Evidence []string `json:"evidence,omitempty"`

	PIDNamespace   string `json:"pid_namespace,omitempty"`
	NetNamespace   string `json:"net_namespace,omitempty"`
	MountNamespace string `json:"mount_namespace,omitempty"`

	ProcessesVisible int       `json:"processes_visible"`
	StartedAt        time.Time `json:"namespace_started_at,omitempty"`

	// MemoryReadable is probed, not assumed: it depends on capabilities,
	// seccomp and yama policy, which vary per host.
	MemoryReadable bool   `json:"memory_readable"`
	MemoryReason   string `json:"memory_reason,omitempty"`

	ReadOnlyRoot bool `json:"read_only_root"`
}

// CoverageNote states the scope limitation in the terms an operator needs.
func (e *Environment) CoverageNote() string {
	if e == nil || !e.Contained {
		return ""
	}
	rt := e.Runtime
	if rt == "" {
		rt = "unknown-runtime"
	}
	if e.Kind == "system" {
		// A system container runs its own init, cron and service manager, so
		// checks inside it are meaningful in their own right — they simply do
		// not extend to the hypervisor host.
		return fmt.Sprintf(
			"Running inside a %s SYSTEM container (%d processes visible). It has its own init, cron and services, "+
				"so the OS-level checks here are meaningful for this container — but they cover this container ONLY. "+
				"The hypervisor host and any sibling containers are not visible and were not checked.",
			rt, e.ProcessesVisible)
	}
	return fmt.Sprintf(
		"Running inside a %s application container (%d processes visible). OS-level checks cover THIS namespace only: "+
			"host crontabs, host SSH keys, host processes and other containers are not visible and were not checked.",
		rt, e.ProcessesVisible)
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

// ContainAction records one step of the containment sequence. Every action is
// recorded whether or not it was executed, so a dry run produces a plan with
// exactly the shape of a real run.
type ContainAction struct {
	Step     int    `json:"step"`
	Kind     string `json:"kind"` // neutralize|freeze|capture|kill|verify|quarantine|opcache
	Target   string `json:"target"`
	PID      int    `json:"pid,omitempty"`
	Executed bool   `json:"executed"`
	Success  bool   `json:"success"`
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
	// EvidencePath points at preserved volatile state (/proc capture, file copy).
	EvidencePath string `json:"evidence_path,omitempty"`
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

type Stats struct {
	FilesSeen   int64 `json:"files_seen"`
	FilesRead   int64 `json:"files_read"`
	BytesRead   int64 `json:"bytes_read"`
	DirsSkipped int64 `json:"dirs_skipped"`
	// FilesSkippedByType counts non-executable files that Quick mode
	// header-probed instead of analysing, so the scope of a quick scan is
	// visible in the report rather than implied by its speed.
	FilesSkippedByType int64 `json:"files_skipped_by_type"`
	ReadErrors         int64 `json:"read_errors"`
	ProcsExamined      int64 `json:"procs_examined"`

	// Phases records where scan time actually went. Added after a field run
	// failed to complete and the cause had to be guessed at from file counts;
	// a scanner that cannot say which engine is slow cannot be tuned.
	Phases PhaseTiming `json:"phases"`
}

type PhaseTiming struct {
	LexMS        int64 `json:"lex_ms"`
	RulesMS      int64 `json:"rules_ms"`
	HeuristicMS  int64 `json:"heuristic_ms"`
	YaraMS       int64 `json:"yara_ms"`
	DecodeMS     int64 `json:"decode_ms"`
	ProvenanceMS int64 `json:"provenance_ms"`
	// Exonerated counts files skipped because they matched their published
	// release — the single biggest saving available.
	Exonerated int64 `json:"exonerated"`
	// SlowFiles hit the per-file budget and had their analysis cut short.
	SlowFiles int64 `json:"slow_files"`

	// ThrottlePausedMS is time the GOVERNOR held the sweep back, as opposed to
	// time spent analysing. Without this the two are indistinguishable in a
	// report, and a scan that is being politely throttled looks identical to
	// one that is simply slow.
	ThrottlePausedMS int64 `json:"throttle_paused_ms"`
	// LoadAvg1 and MaxLoadPerCore are recorded because loadavg inside a
	// container frequently reflects the HOST, not the container — so a
	// per-core threshold tuned for a dedicated box can throttle almost
	// permanently on shared hosting.
	LoadAvg1       float64 `json:"load_avg_1m"`
	MaxLoadPerCore float64 `json:"max_load_per_core"`
	Workers        int     `json:"workers"`

	// UsingPSI reports which contention signal drove throttling. PSI is
	// cgroup-scoped and meaningful inside a container; loadavg usually
	// reflects the host and is not.
	UsingPSI       bool    `json:"using_psi"`
	CPUPressurePct float64 `json:"cpu_pressure_pct"`
	// ThrottleGaveUp is set when pausing consumed more than half the run and
	// the governor disabled it. Surfaced because a scan that was silently
	// paced against a meaningless number looks identical to a slow one.
	ThrottleGaveUp bool `json:"throttle_gave_up"`
}

type RulePackInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Rules   int    `json:"rules"`
}

type Report struct {
	Schema       string `json:"schema"`
	AgentVersion string `json:"agent_version"`
	Mode         string `json:"mode"`

	Host    string `json:"host"`
	Site    string `json:"site"`
	Webroot string `json:"webroot"`
	// Label is an operator-supplied tag from the controller inventory, so
	// aggregate output can use human names rather than hostnames.
	Label string `json:"label,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`

	RulePacks []RulePackInfo `json:"rule_packs"`
	Checks    []CheckStatus  `json:"checks"`
	Stats     Stats          `json:"stats"`

	// Environment records the execution context and its coverage limits.
	Environment *Environment `json:"environment,omitempty"`

	Findings    []Finding       `json:"findings"`
	Containment []ContainAction `json:"containment,omitempty"`

	// Errors holds non-fatal problems (permission denied on a subtree, DB
	// unreachable). Surfaced so a partial scan is never mistaken for a clean one.
	Errors []string `json:"errors,omitempty"`

	// Verdict is a rolled-up conclusion for quick triage.
	Verdict string `json:"verdict"` // clean|dirty|partial
	// VerdictDetail states what the verdict does and does not cover.
	VerdictDetail string `json:"verdict_detail,omitempty"`
	// Layers records which classes of check could actually observe their
	// subject, so "clean" is never mistaken for "fully assessed".
	Layers []Layer `json:"layers,omitempty"`

	mu sync.Mutex
}

// AddFinding is safe for concurrent use by the scan worker pool.
func (r *Report) AddFinding(f Finding) {
	// Enforce the invariant that only confirmed findings can be auto-actioned.
	// Doing it here rather than at each call site means no future check can
	// accidentally mark a heuristic hit as safe to delete.
	if f.Confidence != ConfConfirmed {
		f.Actionable = false
	}
	r.mu.Lock()
	r.Findings = append(r.Findings, f)
	r.mu.Unlock()
}

func (r *Report) AddError(msg string) {
	r.mu.Lock()
	r.Errors = append(r.Errors, msg)
	r.mu.Unlock()
}

func (r *Report) AddCheck(c CheckStatus) {
	r.mu.Lock()
	r.Checks = append(r.Checks, c)
	r.mu.Unlock()
}

// Reset clears accumulated findings, checks and errors, keeping the report's
// identity (host, site, webroot).
//
// A one-shot scan builds a report once and exits, so growth never mattered. A
// monitor daemon is expected to run for months and performs a full sweep on a
// timer; without this, every sweep's checks and findings accumulate in memory
// for the life of the process.
func (r *Report) Reset() {
	r.mu.Lock()
	r.Findings = nil
	r.Checks = nil
	r.Errors = nil
	r.mu.Unlock()
}

// FindingCount lets a caller measure how many findings a check produced by
// snapshotting before and after it runs.
func (r *Report) FindingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Findings)
}

func (r *Report) AddContain(a ContainAction) {
	r.mu.Lock()
	a.Step = len(r.Containment) + 1
	r.Containment = append(r.Containment, a)
	r.mu.Unlock()
}

// Finalize sorts findings, counts them per check, and computes the verdict.
func (r *Report) Finalize() {
	r.mu.Lock()
	defer r.mu.Unlock()

	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Path < b.Path
	})

	// Per-check finding counts are measured by the caller (see timed), not
	// inferred from rule-ID prefixes. The prefix approach credited every
	// "wp."-prefixed finding to all five wp.* checks, so a field report showed
	// each of them claiming four findings.

	r.FinishedAt = time.Now().UTC()
	r.DurationMS = r.FinishedAt.Sub(r.StartedAt).Milliseconds()

	r.Layers = computeLayers(r.Checks)

	dirty := false
	for _, f := range r.Findings {
		if f.Severity.Rank() >= SevMedium.Rank() {
			dirty = true
			break
		}
	}

	// A layer that could not be observed degrades the verdict. Reporting
	// "clean" while blind is the failure mode this whole structure exists to
	// prevent, so unavailability is treated as seriously as an error.
	var blind []string
	for _, l := range r.Layers {
		if l.State == LayerUnavailable || l.State == LayerDegraded {
			blind = append(blind, l.Name)
		}
	}
	degraded := len(r.Errors) > 0 || len(blind) > 0

	switch {
	case dirty:
		r.Verdict = "dirty"
	case degraded:
		r.Verdict = "partial"
	default:
		r.Verdict = "clean"
	}

	switch {
	case dirty && len(blind) > 0:
		r.VerdictDetail = fmt.Sprintf(
			"findings require action; additionally the %s layer(s) could not be assessed",
			strings.Join(blind, " and "))
	case dirty:
		r.VerdictDetail = "all layers assessed; findings require action"
	case len(blind) > 0:
		r.VerdictDetail = fmt.Sprintf(
			"no findings in the layers that WERE assessed, but the %s layer(s) could not be observed — this is not a clean bill of health",
			strings.Join(blind, " and "))
	default:
		r.VerdictDetail = "all layers assessed, nothing found"
	}
}

// LayerState summarises whether a whole class of checks could see its subject.
type LayerState string

const (
	LayerChecked     LayerState = "checked"
	LayerDegraded    LayerState = "degraded"
	LayerUnavailable LayerState = "unavailable"
	LayerNotPresent  LayerState = "not_present"
)

// Layer groups checks so a verdict can say WHICH parts of the system were
// actually examined. A single flat verdict cannot express "the application was
// fully checked and is clean, but the host could not be seen at all", which on
// managed hosting is the normal and most useful thing to say.
type Layer struct {
	Name        string     `json:"name"`
	State       LayerState `json:"state"`
	Checks      int        `json:"checks"`
	Observed    int        `json:"observed"`
	Unavailable []string   `json:"unavailable,omitempty"`
}

// layerFor maps a check id to the layer it belongs to.
func layerFor(id string) string {
	switch {
	case strings.HasPrefix(id, "fs."), strings.HasPrefix(id, "wp."):
		return "application"
	case strings.HasPrefix(id, "osp."), strings.HasPrefix(id, "mem."):
		return "operating system"
	case strings.HasPrefix(id, "net."):
		return "network"
	case strings.HasPrefix(id, "db."):
		return "database"
	case strings.HasPrefix(id, "probe."):
		return "behavioural"
	case strings.HasPrefix(id, "baseline."), strings.HasPrefix(id, "prov."):
		return "integrity"
	}
	return "other"
}

func computeLayers(checks []CheckStatus) []Layer {
	order := []string{"application", "operating system", "network", "database", "behavioural", "integrity", "other"}
	byName := map[string]*Layer{}

	for _, c := range checks {
		name := layerFor(c.ID)
		l, ok := byName[name]
		if !ok {
			l = &Layer{Name: name}
			byName[name] = l
		}
		// not_applicable means "observed, nothing there" and is not counted
		// against coverage at all.
		if c.State == CheckNotApplicable {
			continue
		}
		l.Checks++
		switch c.State {
		case CheckOK:
			l.Observed++
		default:
			l.Unavailable = append(l.Unavailable, c.ID)
		}
	}

	var out []Layer
	for _, name := range order {
		l, ok := byName[name]
		if !ok {
			continue
		}
		switch {
		case l.Checks == 0:
			l.State = LayerNotPresent
		case l.Observed == 0:
			l.State = LayerUnavailable
		case len(l.Unavailable) > 0:
			l.State = LayerDegraded
		default:
			l.State = LayerChecked
		}
		out = append(out, *l)
	}
	return out
}

func checkPrefix(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

// Counts returns findings grouped by severity, for summary rendering.
func (r *Report) Counts() map[Severity]int {
	out := map[Severity]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// MaxSeverity returns the highest severity present, or SevInfo when empty.
func (r *Report) MaxSeverity() Severity {
	best := SevInfo
	for _, f := range r.Findings {
		if f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
	}
	return best
}
