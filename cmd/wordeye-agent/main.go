// Command wordeye-agent is the on-host detection agent.
//
// It is a single static binary with no runtime dependencies: one scp, no
// package installs, nothing left behind but a JSON report. Everything it needs
// — rule packs included — is embedded.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"wordeye/internal/agent"
	"wordeye/internal/emit"
	"wordeye/internal/govern"
	"wordeye/internal/model"
	"wordeye/internal/rules"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// liveDestinations names where findings will actually land, for the startup
// banner. Returning empty means a monitor run would discard everything it
// detects, which the caller treats as a fatal misconfiguration rather than a
// warning.
func liveDestinations(ndjson, syslogTarget, webhook string) []string {
	var out []string
	if ndjson != "" {
		out = append(out, "ndjson "+ndjson)
	}
	if syslogTarget != "" {
		out = append(out, "syslog "+syslogTarget)
	}
	if webhook != "" {
		out = append(out, "webhook "+webhook)
	}
	return out
}

// isScanMode reports whether s names one of the one-shot/daemon scan modes.
// Kept as a single list so the argument parser and the validator can never
// disagree about what a mode is.
func isScanMode(s string) bool {
	switch s {
	case "scan", "baseline", "verify", "monitor":
		return true
	}
	return false
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	// Managed-mode subcommands carry their own flag sets. Without one, the
	// agent behaves exactly as before: a one-shot scanner that leaves nothing
	// behind.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		// "enroll" stays accepted: it was always a valid alias, and silently
		// rejecting a spelling that used to work is a worse outcome than
		// carrying one extra case label.
		case "enroll", "enrol":
			os.Exit(runEnroll(os.Args[2:]))
		case "connect":
			os.Exit(runConnect(os.Args[2:]))
		}
	}

	// A binary stamped by the console carries its own enrollment instructions,
	// so a site administrator runs ONE file with NO arguments and the host
	// appears in the console. Explicit arguments always win: an operator who
	// types a command meant that command, and silently doing something else
	// because of a hidden trailer would be indefensible.
	if len(os.Args) == 1 {
		if cfg, err := agent.LoadEmbeddedConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "wordeye: this installer is damaged: %v\n", err)
			os.Exit(2)
		} else if cfg != nil {
			os.Exit(runInstaller(cfg))
		}
	}
	os.Exit(run())
}

func run() int {
	var (
		packs    stringList
		webroot  = flag.String("webroot", "", "path to the WordPress document root (default: auto-detect)")
		allSites = flag.Bool("all-sites", false, "discover and scan every WordPress install on this host")
		label    = flag.String("label", "", "operator label for this host, carried into the report")
		profile  = flag.String("profile", "balanced", "resource profile: safe|balanced|fast")
		workers  = flag.Int("workers", 0, "override worker count (0 = profile default)")
		ioRate   = flag.Int64("io-rate", -1, "override read throughput in bytes/sec (0 = unlimited)")
		maxLoad  = flag.Float64("max-load", -1, "pause scanning above this loadavg-per-core (0 = never pause)")
		maxFile  = flag.Int64("max-file-size", 4<<20, "maximum bytes examined per file")
		deadline = flag.Duration("deadline", 0, "hard limit on total run time (0 = profile default)")
		quick    = flag.Bool("quick", false, "skip large media/cache trees and checksum verification")

		skipFS    = flag.Bool("skip-fs", false, "skip the filesystem sweep")
		skipDB    = flag.Bool("skip-db", false, "skip database checks")
		skipOS    = flag.Bool("skip-os", false, "skip OS persistence checks")
		skipNet   = flag.Bool("skip-net", false, "skip socket checks")
		skipProbe = flag.Bool("skip-probe", false, "skip the HTTP cloak probe")
		useWPCLI  = flag.Bool("wp-cli", false, "use wp-cli for core/plugin checksum verification if available")
		offline   = flag.Bool("offline", false, "make no outbound requests; provenance is then reported as unavailable")
		skipProv  = flag.Bool("skip-provenance", false, "skip the published-checksum comparison")

		jsonOut = flag.String("json", "-", "write the JSON report here ('-' for stdout, '' to disable)")
		pretty  = flag.Bool("pretty", false, "indent the JSON report")
		ndjson  = flag.String("ndjson", "", "append ECS events to this file (for Wazuh/Filebeat to tail)")
		syslogT = flag.String("syslog", "", "stream ECS events to a syslog collector, e.g. udp://10.0.0.5:514")
		webhook = flag.String("webhook", "", "POST ECS event batches to this URL")
		quiet   = flag.Bool("quiet", false, "suppress the human-readable summary on stderr")

		yaraPaths   stringList
		vendorPacks stringList
		noYara      = flag.Bool("no-yara", false, "disable the YARA engine entirely")

		baseline = flag.String("baseline-path", "", "baseline file location (default: ~/.wordeye/baseline_<site>.txt)")
		rescan   = flag.Duration("rescan", 6*time.Hour, "monitor mode: interval for the full backstop sweep")

		contain    = flag.Bool("contain", false, "ACTIVE: neutralise persistence, freeze/capture/kill implants, quarantine confirmed files")
		containDry = flag.Bool("contain-dry-run", false, "print the ordered containment plan without executing it")
		maxActions = flag.Int("max-actions", 25, "containment circuit breaker: maximum actions per run")
		evidence   = flag.String("evidence-dir", "", "evidence directory (default: ~/.wordeye/evidence/<host>_<stamp>)")
		healthURL  = flag.String("health-url", "", "site URL for the health gate and cloak probe (default: from the database)")

		dbHost   = flag.String("db-host", "", "override DB_HOST")
		dbName   = flag.String("db-name", "", "override DB_NAME")
		dbUser   = flag.String("db-user", "", "override DB_USER")
		dbPass   = flag.String("db-pass", "", "override DB_PASSWORD")
		dbPrefix = flag.String("db-prefix", "", "override $table_prefix")

		listPacks = flag.Bool("list-packs", false, "list the embedded rule packs and exit")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Var(&packs, "pack", "rule pack: an embedded name or a path to a YAML file (repeatable, later packs win)")
	flag.Var(&yaraPaths, "yara", "additional .yar file or directory, loaded alongside the built-in ruleset (repeatable)")
	flag.Var(&vendorPacks, "vendor-pack", "estate-consensus attestation pack for premium/bespoke code (repeatable)")

	flag.Usage = usage

	// The mode may LEAD the arguments: `wordeye-agent monitor --ndjson X`.
	//
	// Go's flag package stops parsing at the first non-flag argument, so that
	// invocation previously parsed ZERO flags and discarded every one of them
	// without a word. In the field it meant a monitor daemon started, watched
	// the right tree, detected correctly — and wrote its findings nowhere,
	// because --ndjson had been silently dropped. The daemon looked healthy and
	// was useless, which is the worst way for a tool to fail.
	//
	// Both orders are now accepted, and anything left over is an error rather
	// than something quietly ignored.
	args := os.Args[1:]
	leadMode := ""
	if len(args) > 0 && isScanMode(args[0]) {
		leadMode, args = args[0], args[1:]
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		return 2
	}

	if *showVer {
		fmt.Printf("wordeye-agent %s\n", version)
		return 0
	}
	if *listPacks {
		for _, n := range rules.EmbeddedNames() {
			fmt.Println(n)
		}
		return 0
	}

	agent.Version = version

	// Mode from wherever it was given; leading form wins.
	mode := leadMode
	rest := flag.Args()
	if mode == "" {
		mode = "scan"
		if len(rest) > 0 {
			mode, rest = rest[0], rest[1:]
		}
	}
	if !isScanMode(mode) {
		fmt.Fprintf(os.Stderr, "unknown mode %q (want scan, baseline, verify or monitor)\n", mode)
		return 2
	}
	// Refuse leftovers. A stray argument here is almost always a flag that
	// landed in the wrong place, and accepting it silently is how a misconfigured
	// agent ends up looking healthy while doing nothing useful.
	if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n", rest[0])
		if strings.HasPrefix(rest[0], "-") {
			fmt.Fprintf(os.Stderr, "flags must not follow another positional argument; try:\n  %s %s %s ...\n",
				filepath.Base(os.Args[0]), mode, strings.Join(rest, " "))
		}
		return 2
	}

	if len(packs) == 0 {
		packs = stringList{"core"}
	}

	prof, err := govern.ParseProfile(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	gcfg := govern.ForProfile(prof)
	if *workers > 0 {
		gcfg.Workers = *workers
	}
	if *ioRate >= 0 {
		gcfg.IOBytesPerSec = *ioRate
	}
	if *maxLoad >= 0 {
		gcfg.MaxLoadPerCore = *maxLoad
	}
	if *deadline > 0 {
		gcfg.Deadline = *deadline
	}

	// --- resolve targets ---------------------------------------------------
	home, _ := os.UserHomeDir()
	var roots []string
	switch {
	case *webroot != "":
		roots = []string{*webroot}
	case *allSites:
		roots = agent.DiscoverWebroots(home, 0)
	default:
		if r := agent.FindWebroot(home); r != "" {
			roots = []string{r}
		}
	}
	if len(roots) == 0 {
		fmt.Fprintln(os.Stderr, "no WordPress installation found — pass --webroot explicitly")
		return 2
	}

	// --- output sinks ------------------------------------------------------
	sinks, cleanup, err := buildSinks(*jsonOut, *pretty, *ndjson, *syslogT, *webhook)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	worst := 0
	for _, root := range roots {
		cfg := agent.Config{
			Mode: mode, Webroot: root, Home: home, Label: *label,
			Packs: packs, Profile: prof, Gov: gcfg,
			MaxFileSize: *maxFile, Quick: *quick,
			SkipFS: *skipFS, SkipDB: *skipDB, SkipOS: *skipOS,
			SkipNet: *skipNet, SkipProbe: *skipProbe, UseWPCLI: *useWPCLI,
			Offline: *offline, SkipProvenance: *skipProv,
			VendorPacks:  vendorPacks,
			BaselinePath: *baseline, EvidenceDir: *evidence,
			YaraPaths: yaraPaths, DisableYara: *noYara,
			Contain: *contain || *containDry, ContainDryRun: *containDry,
			MaxActions: *maxActions, HealthURL: *healthURL,
			DBHost: *dbHost, DBName: *dbName, DBUser: *dbUser,
			DBPass: *dbPass, DBPrefix: *dbPrefix,
		}

		a, err := agent.New(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", root, err)
			worst = maxOf(worst, 2)
			continue
		}

		ectx := emit.Context{
			Host: a.Report().Host, Site: a.Report().Site,
			Webroot: root, Label: *label, Version: version,
		}
		// Stream findings as they are discovered so a SIEM sees them during a
		// long scan rather than only at the end.
		a.SetSink(func(f model.Finding) { sinks.Finding(f, ectx) })

		if mode == "monitor" {
			// State plainly where detections will go, and refuse to run as a
			// silent no-op.
			//
			// A resident detector with nowhere to report is the most dangerous
			// state this program has: the process is up, memory is flat, the
			// watches are registered, and an operator reasonably concludes the
			// site is monitored. In the field exactly that happened — findings
			// were produced and discarded because the output flag had been
			// swallowed by the argument parser. A monitor that cannot report
			// is not monitoring.
			live := liveDestinations(*ndjson, *syslogT, *webhook)
			if len(live) == 0 {
				fmt.Fprintln(os.Stderr,
					"wordeye: refusing to monitor with nowhere to send detections.")
				fmt.Fprintln(os.Stderr,
					"  Add --ndjson FILE (or --syslog / --webhook) to record findings locally,")
				fmt.Fprintln(os.Stderr,
					"  or use `wordeye-agent connect --monitor` to report to a console.")
				return 2
			}
			if !*quiet {
				fmt.Fprintf(os.Stderr, "wordeye: monitoring %s (backstop sweep every %s) — ctrl-c to stop\n", root, *rescan)
				fmt.Fprintf(os.Stderr, "wordeye: detections -> %s\n", strings.Join(live, ", "))
				fmt.Fprintln(os.Stderr,
					"wordeye: this mode does NOT report to a console; use `connect --monitor` for that")
			}
			// Report coverage shortly after the watches are registered. A
			// field run left 72% of a webroot unwatched and reported nothing:
			// the process looked healthy, and the operator reasonably believed
			// the site was covered.
			if !*quiet {
				go func() {
					time.Sleep(2 * time.Second)
					if s := a.MonitorWatchSummary(); s != "" {
						fmt.Fprintf(os.Stderr, "wordeye: %s\n", s)
					}
				}()
			}
			err := a.Monitor(ctx, *rescan)
			a.Close()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "monitor: %v\n", err)
				return 2
			}
			return 0
		}

		// Live progress. A six-minute silent scan is indistinguishable from a
		// hang, which is exactly how the first field run was interpreted — and
		// reasonably so. Reporting throughput also makes a stalled sweep
		// obvious immediately rather than after the fact.
		progressDone := make(chan struct{})
		if !*quiet {
			go func() {
				t := time.NewTicker(15 * time.Second)
				defer t.Stop()
				start := time.Now()
				var lastRead int64
				for {
					select {
					case <-progressDone:
						return
					case <-t.C:
						seen, read, bytes := a.Progress()
						rate := float64(read-lastRead) / 15.0
						lastRead = read
						fmt.Fprintf(os.Stderr,
							"  … %s elapsed: %d files seen, %d read (%.0f/s), %d MB\n",
							time.Since(start).Round(time.Second), seen, read, rate, bytes>>20)
					}
				}
			}()
		}

		rep, _ := a.Run(ctx)
		close(progressDone)
		a.Close()

		if err := sinks.Report(rep); err != nil {
			fmt.Fprintf(os.Stderr, "emit: %v\n", err)
		}
		if !*quiet {
			renderSummary(os.Stderr, rep)
		}
		worst = maxOf(worst, exitFor(rep))
	}
	return worst
}

func exitFor(r *model.Report) int {
	switch r.Verdict {
	case "dirty":
		return 1
	case "partial":
		return 2
	}
	return 0
}

func maxOf(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// buildSinks assembles the emitter fan-out. A SIEM sink that fails to connect
// is reported but never fatal — losing the collector must not cost the local
// report.
func buildSinks(jsonOut string, pretty bool, ndjson, syslogTarget, webhook string) (emit.Emitter, func(), error) {
	var sinks []emit.Emitter
	var closers []func()

	if jsonOut == "-" {
		sinks = append(sinks, emit.NewJSONReport(os.Stdout, pretty))
	} else if jsonOut != "" {
		if err := os.MkdirAll(filepath.Dir(jsonOut), 0o700); err != nil {
			return nil, func() {}, err
		}
		j, err := emit.NewJSONReportFile(jsonOut, pretty)
		if err != nil {
			return nil, func() {}, err
		}
		sinks = append(sinks, j)
		closers = append(closers, func() { j.Close() })
	}

	if ndjson != "" {
		n, err := emit.NewNDJSONFile(ndjson)
		if err != nil {
			return nil, func() {}, fmt.Errorf("ndjson: %w", err)
		}
		sinks = append(sinks, n)
		closers = append(closers, func() { n.Close() })
	}

	if syslogTarget != "" {
		u, err := url.Parse(syslogTarget)
		if err != nil || u.Host == "" {
			return nil, func() {}, fmt.Errorf("syslog target must look like udp://host:port")
		}
		network := u.Scheme
		if network != "tcp" && network != "udp" {
			network = "udp"
		}
		s, err := emit.NewSyslog(network, u.Host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wordeye: syslog sink unavailable (%v) — continuing without it\n", err)
		} else {
			sinks = append(sinks, s)
			closers = append(closers, func() { s.Close() })
		}
	}

	if webhook != "" {
		w := emit.NewWebhook(webhook, nil)
		sinks = append(sinks, w)
		closers = append(closers, func() { w.Close() })
	}

	return emit.NewMulti(sinks...), func() {
		for _, c := range closers {
			c()
		}
	}, nil
}

// ---------------------------------------------------------------------------
// human-readable summary
// ---------------------------------------------------------------------------

func renderSummary(w *os.File, r *model.Report) {
	fmt.Fprintf(w, "\n─── wordeye %s │ %s │ %s │ %s ───\n",
		r.AgentVersion, orDash(r.Site), r.Host, r.Mode)
	fmt.Fprintf(w, "webroot : %s\n", r.Webroot)
	fmt.Fprintf(w, "duration: %s   files: %d seen / %d read\n",
		time.Duration(r.DurationMS)*time.Millisecond, r.Stats.FilesSeen, r.Stats.FilesRead)
	if e := r.Environment; e != nil && e.Contained {
		mem := "readable"
		if !e.MemoryReadable {
			mem = "NOT readable (" + e.MemoryReason + ")"
		}
		kind := e.Kind
		if kind == "" {
			kind = "container"
		} else {
			kind += " container"
		}
		fmt.Fprintf(w, "scope   : %s %s, %d processes visible, process memory %s\n",
			e.Runtime, kind, e.ProcessesVisible, mem)
	}

	// Checks that did not run are as important as findings: a skipped check is
	// not a clean result.
	var skipped, errored []string
	for _, c := range r.Checks {
		switch c.State {
		case model.CheckSkipped:
			skipped = append(skipped, c.ID)
		case model.CheckError:
			errored = append(errored, fmt.Sprintf("%s (%s)", c.ID, c.Reason))
		}
	}
	if len(errored) > 0 {
		fmt.Fprintf(w, "FAILED  : %s\n", strings.Join(errored, ", "))
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "skipped : %s\n", strings.Join(skipped, ", "))
	}

	// Where the time went. Analysis cost and governor throttling are
	// indistinguishable from the outside, and conflating them sends you tuning
	// the wrong thing.
	if p := r.Stats.Phases; p.ThrottlePausedMS > 0 || p.LexMS+p.RulesMS+p.HeuristicMS+p.YaraMS > 0 {
		fmt.Fprintf(w, "time    : lex %dms, rules %dms, heuristics %dms, yara %dms, decode %dms, provenance %dms\n",
			p.LexMS, p.RulesMS, p.HeuristicMS, p.YaraMS, p.DecodeMS, p.ProvenanceMS)
		if p.ThrottlePausedMS > 0 {
			signal := fmt.Sprintf("loadavg %.2f vs %.2f/core", p.LoadAvg1, p.MaxLoadPerCore)
			if p.UsingPSI {
				signal = fmt.Sprintf("cpu pressure %.1f%%", p.CPUPressurePct)
			}
			note := ""
			if p.ThrottleGaveUp {
				note = " — GAVE UP: pausing exceeded half the run, so throttling was disabled"
			}
			fmt.Fprintf(w, "throttle: paused %ds of the run (%s)%s\n",
				p.ThrottlePausedMS/1000, signal, note)
		}
		if p.Exonerated > 0 {
			fmt.Fprintf(w, "verified: %d files matched their published release and skipped content analysis\n",
				p.Exonerated)
		}
		if p.SlowFiles > 0 {
			fmt.Fprintf(w, "slow    : %d file(s) hit the per-file budget and were cut short\n", p.SlowFiles)
		}
	}

	counts := r.Counts()
	fmt.Fprintf(w, "findings: %d critical, %d high, %d medium, %d low, %d info\n",
		counts[model.SevCritical], counts[model.SevHigh], counts[model.SevMedium],
		counts[model.SevLow], counts[model.SevInfo])

	shown := 0
	for _, f := range r.Findings {
		if f.Severity.Rank() < model.SevMedium.Rank() || shown >= 25 {
			continue
		}
		shown++
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		if f.ContainPID > 0 {
			loc = fmt.Sprintf("pid %d %s", f.ContainPID, f.Path)
		}
		fmt.Fprintf(w, "  [%-8s %-9s] %s\n", strings.ToUpper(string(f.Severity)), f.Confidence, f.Title)
		if loc != "" {
			fmt.Fprintf(w, "             %s\n", loc)
		}
	}
	if remaining := countAtLeast(r, model.SevMedium) - shown; remaining > 0 {
		fmt.Fprintf(w, "  … and %d more (see the JSON report)\n", remaining)
	}

	if len(r.Containment) > 0 {
		fmt.Fprintf(w, "\ncontainment:\n")
		for _, a := range r.Containment {
			status := "planned"
			switch {
			case a.Executed && a.Success:
				status = "done"
			case a.Executed && !a.Success:
				status = "FAILED"
			case !a.Executed && a.Error != "":
				status = "refused"
			}
			fmt.Fprintf(w, "  %2d. %-11s %-8s %s\n", a.Step, a.Kind, status, a.Target)
			if a.Detail != "" {
				fmt.Fprintf(w, "      %s\n", a.Detail)
			}
			if a.Error != "" {
				fmt.Fprintf(w, "      error: %s\n", a.Error)
			}
		}
	}

	// Per-layer coverage. A single verdict cannot express "the application was
	// fully examined and is clean, but the host could not be seen at all", and on
	// managed hosting that is both the normal case and the most useful thing to
	// say. Printing it keeps "checked and clean" apart from "could not check".
	if len(r.Layers) > 0 {
		fmt.Fprintf(w, "\ncoverage:\n")
		for _, l := range r.Layers {
			mark := "checked"
			switch l.State {
			case model.LayerUnavailable:
				mark = "UNAVAILABLE — not assessed"
			case model.LayerDegraded:
				mark = fmt.Sprintf("PARTIAL — %d of %d checks could not observe", len(l.Unavailable), l.Checks)
			case model.LayerNotPresent:
				continue
			}
			fmt.Fprintf(w, "  %-17s %s\n", l.Name, mark)
			if len(l.Unavailable) > 0 {
				fmt.Fprintf(w, "  %-17s   (%s)\n", "", strings.Join(l.Unavailable, ", "))
			}
		}
	}

	fmt.Fprintf(w, "\nVERDICT : %s\n", strings.ToUpper(r.Verdict))
	if r.VerdictDetail != "" {
		fmt.Fprintf(w, "          %s\n", r.VerdictDetail)
	}
	// Qualify the verdict rather than letting it overclaim. A clean result from
	// inside a container says this container is clean; it says nothing about the
	// host, and an unqualified "CLEAN" invites exactly the wrong conclusion.
	if e := r.Environment; e != nil && e.Contained {
		fmt.Fprintln(w, "          Scope: THIS CONTAINER ONLY. Host crontabs, host SSH keys, host")
		fmt.Fprintln(w, "          processes and sibling containers were not visible and were not checked.")
	}
}

func countAtLeast(r *model.Report, s model.Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity.Rank() >= s.Rank() {
			n++
		}
	}
	return n
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func usage() {
	fmt.Fprintf(os.Stderr, `wordeye-agent %s — WordPress intrusion detection and containment

USAGE
  wordeye-agent [mode] [flags]

MODES
  scan       detect (default)
  baseline   record SHA-256 of every PHP file — run on a state you believe clean
  verify     report drift against the baseline
  monitor    run as a daemon, detecting file writes in real time via inotify

MANAGED MODE (optional)
  enroll     join a console-managed fleet using a token issued by the console
  connect    run resident: check in, stream detections, execute queued work
             (see: wordeye-agent enroll --help)

EXAMPLES
  wordeye-agent                              scan the detected site, JSON to stdout
  wordeye-agent --pack core --pack incident.yaml --pretty
  wordeye-agent --profile safe --quick       gentlest possible pass on a busy host
  wordeye-agent --all-sites --json out.ndjson
  wordeye-agent --contain-dry-run            show the containment plan, change nothing
  wordeye-agent monitor --ndjson /var/log/wordeye.ndjson

UPTIME
  The scan yields to the website. --profile safe uses one worker, caps reads at
  8 MB/s, and pauses whenever loadavg-per-core exceeds 0.6. Containment probes
  the site over HTTP after every destructive step and rolls back automatically
  if it stops serving.

EXIT CODES
  0 clean   1 findings   2 error or incomplete scan

FLAGS
`, version)
	flag.PrintDefaults()
}
