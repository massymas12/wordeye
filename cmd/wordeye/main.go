// Command wordeye is the estate controller: it deploys the agent, runs it
// across many hosts concurrently, collects the JSON reports, and correlates
// findings across the estate.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"wordeye/internal/controller"
)

var version = "dev"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() { os.Exit(run()) }

func run() int {
	// Subcommand dispatch. 'wordeye serve' runs the management console; with no
	// subcommand the binary behaves as the sweep controller it started as.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			return runServe(os.Args[2:])
		case "gensignkey":
			return runGenSignKey(os.Args[2:])
		case "sign-release":
			return runSignRelease(os.Args[2:])
		case "gencert":
			return runGencert(os.Args[2:])
		case "healthcheck":
			return runHealthcheck(os.Args[2:])
		case "token":
			return runToken(os.Args[2:])
		case "help", "-h", "--help":
			usage()
			return 0
		}
	}

	var (
		packs     stringList
		extra     stringList
		inventory = flag.String("inventory", "", "inventory file: YAML, or one ssh target per line")
		agentBin  = flag.String("agent", "", "path to the linux agent binary (default: ./dist/wordeye-agent-linux-amd64)")
		mode      = flag.String("mode", "scan", "scan|baseline|verify")
		profile   = flag.String("profile", "balanced", "remote resource profile: safe|balanced|fast")
		quick     = flag.Bool("quick", false, "skip large media/cache trees on every host")
		conc      = flag.Int("concurrency", 8, "hosts to work on at once")
		timeout   = flag.Duration("timeout", 20*time.Minute, "per-host timeout")
		outDir    = flag.String("out", "", "directory for per-host reports and aggregate.json")
		contain   = flag.Bool("contain", false, "ACTIVE: run containment on every host (destructive)")
		dryRun    = flag.Bool("contain-dry-run", false, "collect the containment plan from each host, change nothing")
		keepAgent = flag.Bool("keep-agent", false, "leave the agent installed for faster repeat runs")
		quiet     = flag.Bool("quiet", false, "suppress progress output")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Var(&packs, "pack", "rule pack: embedded name, or a local YAML file to ship to each host (repeatable)")
	flag.Var(&extra, "agent-flag", "extra flag passed verbatim to the remote agent (repeatable)")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("wordeye %s\n", version)
		return 0
	}

	// --- inventory ---------------------------------------------------------
	var inv *controller.Inventory
	if *inventory != "" {
		var err error
		inv, err = controller.LoadInventory(*inventory)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else if flag.NArg() > 0 {
		inv = &controller.Inventory{}
		for _, t := range flag.Args() {
			h, err := controller.ParseTarget(t)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			inv.Hosts = append(inv.Hosts, h)
		}
	} else {
		usage()
		return 2
	}

	// --- agent binary ------------------------------------------------------
	bin := *agentBin
	if bin == "" {
		bin = defaultAgentPath()
	}
	if _, err := os.Stat(bin); err != nil {
		fmt.Fprintf(os.Stderr, "agent binary not found at %s\n", bin)
		fmt.Fprintln(os.Stderr, "build it first:  ./build.ps1   (or: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/wordeye-agent-linux-amd64 ./cmd/wordeye-agent)")
		return 2
	}

	// A --pack that names a local file is shipped to each host; anything else
	// is treated as the name of a pack already embedded in the agent.
	var shipped, names []string
	for _, p := range packs {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			shipped = append(shipped, p)
		} else {
			names = append(names, p)
		}
	}
	if len(names) > 0 {
		for i := range inv.Hosts {
			inv.Hosts[i].Packs = append(inv.Hosts[i].Packs, names...)
		}
	}

	if *contain && *dryRun {
		fmt.Fprintln(os.Stderr, "--contain and --contain-dry-run are mutually exclusive")
		return 2
	}
	if *contain {
		fmt.Fprintf(os.Stderr,
			"WARNING: containment is ACTIVE across %d host(s). Persistence will be disabled,\n"+
				"implant processes frozen/captured/killed, and confirmed malicious files quarantined.\n"+
				"Each host health-checks its own site after every destructive step and rolls back on regression.\n\n",
			len(inv.Hosts))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	progress := func(s string) {}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "wordeye %s — %d host(s), %d at a time, mode=%s profile=%s\n\n",
			version, len(inv.Hosts), *conc, *mode, *profile)
		progress = func(s string) { fmt.Fprintln(os.Stderr, "  "+s) }
	}

	start := time.Now()
	results := controller.Run(ctx, inv, controller.Options{
		AgentBinary:   bin,
		Packs:         shipped,
		Mode:          *mode,
		Profile:       *profile,
		Quick:         *quick,
		Concurrency:   *conc,
		Timeout:       *timeout,
		Contain:       *contain,
		ContainDryRun: *dryRun,
		KeepAgent:     *keepAgent,
		Extra:         extra,
		Progress:      progress,
	})

	agg := controller.Aggregated(results, *mode)

	if *outDir != "" {
		if err := writeOutputs(*outDir, agg, results); err != nil {
			fmt.Fprintf(os.Stderr, "writing reports: %v\n", err)
		} else if !*quiet {
			fmt.Fprintf(os.Stderr, "\nreports written to %s\n", *outDir)
		}
	}

	if !*quiet {
		agg.Render(os.Stderr)
		fmt.Fprintf(os.Stderr, "\nelapsed: %s\n", time.Since(start).Round(time.Second))
	}
	if *outDir == "" {
		// With no output directory, the aggregate goes to stdout so it can be
		// piped straight into jq or another tool.
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(agg)
	}

	switch {
	case agg.Failed > 0:
		return 2
	case agg.Dirty > 0:
		return 1
	}
	return 0
}

func writeOutputs(dir string, agg *controller.Aggregate, results []controller.Result) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, res := range results {
		if !res.OK() || len(res.Reports) == 0 {
			continue
		}
		name := sanitize(res.Host.Name()) + ".json"
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		var payload any = res.Reports
		if len(res.Reports) == 1 {
			payload = res.Reports[0]
		}
		err = enc.Encode(payload)
		f.Close()
		if err != nil {
			return err
		}
	}
	f, err := os.Create(filepath.Join(dir, "aggregate.json"))
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(agg)
}

func defaultAgentPath() string {
	candidates := []string{
		filepath.Join("dist", "wordeye-agent-linux-amd64"),
		filepath.Join("dist", "wordeye-agent"),
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(d, "wordeye-agent-linux-amd64"),
			filepath.Join(d, "wordeye-agent"))
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return candidates[0]
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func usage() {
	fmt.Fprintf(os.Stderr, `wordeye %s — WordPress estate IR controller (%s)

USAGE
  wordeye serve [flags]                       run the management console
  wordeye --inventory hosts.yaml [flags]      sweep an estate over ssh
  wordeye [flags] user@host1 user@host2:2222 …

MODES
  Two ways to work, and they compose:

    sweep   ephemeral. Deploys the agent over ssh, runs it, collects JSON,
            removes it. Nothing is installed on the client host.

    serve   resident. Runs the console; agents enrolled with a console-minted
            token check in continuously, stream detections, and can be sent
            work. Run wordeye serve --help for its flags.

WHAT IT DOES
  For each host, concurrently: deploy the agent (skipped when the remote copy
  already matches), ship any incident rule packs, run the scan, stream back the
  JSON report, then remove the binary. Finally it correlates findings across the
  whole estate — identical SHA-256s on several hosts mean one campaign, not
  several coincidences.

EXAMPLES
  wordeye --inventory estate.yaml --pack incident.yaml --out ./reports
  wordeye --profile safe --quick user@site1 user@site2
  wordeye --inventory estate.yaml --contain-dry-run --out ./plans

INVENTORY (YAML)
  defaults:
    user: deploy
    packs: [core]
  hosts:
    - host: site1.example.com
      label: Marketing site
    - host: 10.0.0.9
      port: 2222
      webroot: /var/www/html
      ssh_opts: ["-J", "bastion.example.com"]

  A plain text file with one ssh target per line works too.

TRANSPORT
  Uses the system ssh/scp, so ~/.ssh/config, ProxyJump, agent forwarding and
  known_hosts all apply exactly as they do for an interactive login.

EXIT CODES
  0 clean   1 findings   2 a host was unreachable or errored

FLAGS
`, version, runtime.GOOS)
	flag.PrintDefaults()
}
