package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wordeye/internal/agent"
	"wordeye/internal/govern"
)

// Managed mode: enrollment against a console, then a resident check-in loop.
//
// Both subcommands are opt-in. Without them the agent behaves exactly as it did
// before — a one-shot binary that scans, prints JSON, and leaves nothing behind.

// managedFlags are shared by `enroll` and `connect`.
type managedFlags struct {
	server    *string
	token     *string
	state     *string
	label     *string
	webroot   *string
	profile   *string
	packs     *stringList
	ca        *string
	insecure  *bool
	skipDB    *bool
	skipOS    *bool
	skipNet   *bool
	skipProbe *bool
	skipProv  *bool
	allowCont *bool
	heartbeat *time.Duration
	monitor   *bool
	rescan    *time.Duration
	quick     *bool
}

func addManagedFlags(fs *flag.FlagSet, packs *stringList) *managedFlags {
	home, _ := os.UserHomeDir()
	m := &managedFlags{
		server:  fs.String("server", "", "console ingest URL, e.g. https://console.example.com:8444"),
		token:   fs.String("token", "", "enrollment token issued by the console"),
		state:   fs.String("state", agent.DefaultStateFile(home), "path to the enrollment credential file"),
		label:   fs.String("label", "", "operator label for this host"),
		webroot: fs.String("webroot", "", "WordPress document root (default: auto-detect)"),
		profile: fs.String("profile", "balanced", "resource profile: safe|balanced|fast"),
		packs:   packs,
		ca: fs.String("ca", "",
			"PEM certificate to verify the console against. Preferred over --insecure for a "+
				"self-signed console: it VERIFIES the certificate instead of trusting anything."),
		insecure: fs.Bool("insecure", false,
			"skip TLS verification entirely. Exposes the enrollment token and agent credential "+
				"to anyone on the path; use --ca instead wherever possible."),
		allowCont: fs.Bool("allow-remote-contain", false,
			"permit the console to order containment ON THIS HOST. Without this the agent refuses "+
				"destructive orders even if the console grants them."),
		heartbeat: fs.Duration("heartbeat", 60*time.Second, "check-in interval"),
		monitor:   fs.Bool("monitor", true, "run real-time inotify detection alongside check-in"),
		// Zero by default: steady state is event-driven. A recurring full sweep
		// on a live customer host is opt-in, not something they inherit.
		rescan: fs.Duration("rescan", 0,
			"recurring full sweep interval (0 = none; monitoring stays event-driven)"),
		quick: fs.Bool("quick", false, "skip large media/cache trees"),
		// The resident agent performs a full sweep at startup and on every
		// rescan. Without these it always runs the network-bound checks, which
		// an operator may have good reason to decline on a customer's host.
		skipDB:    fs.Bool("skip-db", false, "skip database checks in the periodic sweep"),
		skipOS:    fs.Bool("skip-os", false, "skip OS persistence and memory checks"),
		skipNet:   fs.Bool("skip-net", false, "skip socket checks"),
		skipProbe: fs.Bool("skip-probe", false, "skip the HTTP cloak probe"),
		skipProv:  fs.Bool("skip-provenance", false, "skip the published-checksum comparison"),
	}
	fs.Var(packs, "pack", "rule pack: embedded name or path to a YAML file (repeatable)")
	return m
}

// baseConfig builds the scan configuration that queued commands execute with.
func (m *managedFlags) baseConfig() (agent.Config, error) {
	prof, err := govern.ParseProfile(*m.profile)
	if err != nil {
		return agent.Config{}, err
	}
	home, _ := os.UserHomeDir()
	root := *m.webroot
	if root == "" {
		root = agent.FindWebroot(home)
	}
	packs := *m.packs
	if len(packs) == 0 {
		packs = stringList{"core"}
	}
	return agent.Config{
		Webroot:     root,
		Home:        home,
		Label:       *m.label,
		Packs:       packs,
		Profile:     prof,
		Gov:         govern.ForProfile(prof),
		MaxFileSize: 4 << 20,
		Quick:       *m.quick,
		UseWPCLI:    false,
		MaxActions:  25,
		// Honoured by the resident agent's startup and periodic sweeps.
		SkipDB:         *m.skipDB,
		SkipOS:         *m.skipOS,
		SkipNet:        *m.skipNet,
		SkipProbe:      *m.skipProbe,
		SkipProvenance: *m.skipProv,
	}, nil
}

func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var packs stringList
	m := addManagedFlags(fs, &packs)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wordeye-agent enroll — join a console-managed fleet

  Exchanges a console-minted enrollment token for a durable credential stored at
  --state. The token is consumed server-side, so it cannot be reused from here.

  An agent CANNOT join a fleet without a token an operator issued explicitly.

REMOTE CONTAINMENT
  --allow-remote-contain opts this host in to accepting destructive orders.
  Containment additionally requires the enrollment token to grant it, so BOTH
  sides must agree. Leave it off and this host will only ever be scanned.

EXAMPLE
  wordeye-agent enroll --server https://console.example.com:8444 --token wek_...

FLAGS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	base, err := m.baseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	agent.Version = version

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	st, err := agent.Enroll(ctx, agent.ClientConfig{
		Server: *m.server, Token: *m.token, StateFile: *m.state,
		Label: *m.label, AllowRemoteContain: *m.allowCont,
		Base: base, CAPEM: readCA(*m.ca), Insecure: *m.insecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "enrollment failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "enrolled as %s\n", st.AgentID)
	fmt.Fprintf(os.Stderr, "credential stored at %s (mode 0600)\n", *m.state)
	if st.AllowRemoteContain {
		fmt.Fprintln(os.Stderr, "remote containment: PERMITTED on this host (subject to the console's grant)")
	} else {
		fmt.Fprintln(os.Stderr, "remote containment: refused on this host")
	}
	fmt.Fprintln(os.Stderr, "\nstart the resident agent with:  wordeye-agent connect")
	return 0
}

func runConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	var packs stringList
	m := addManagedFlags(fs, &packs)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wordeye-agent connect — run as a resident managed agent

  Checks in to the console on an interval, streams real-time detections, and
  executes work the console queues. All traffic is outbound: nothing connects
  inbound to this host, so no port needs opening.

  Run it under systemd, supervisor, or a process manager of your choice.

EXAMPLE
  wordeye-agent connect --profile safe

FLAGS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	st, err := agent.LoadState(*m.state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	base, err := m.baseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if base.Webroot == "" {
		fmt.Fprintln(os.Stderr, "no WordPress installation found — pass --webroot")
		return 2
	}
	agent.Version = version

	logger := log.New(os.Stderr, "", log.LstdFlags)
	client := agent.NewClient(agent.ClientConfig{
		Server: st.Server, StateFile: *m.state, Label: *m.label,
		AllowRemoteContain: st.AllowRemoteContain,
		Base:               base,
		HeartbeatInterval:  *m.heartbeat,
		Monitor:            *m.monitor,
		RescanPeriod:       *m.rescan,
		CAPEM:              readCA(*m.ca),
		Insecure:           *m.insecure,
	}, st)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := client.Run(ctx, logger.Printf); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "agent stopped: %v\n", err)
		return 1
	}
	return 0
}

// readCA loads a PEM certificate for pinning. A missing or unreadable file is
// fatal rather than a silent fall-back to the system roots: an operator who
// passed --ca asked for a specific trust anchor, and quietly using a different
// one would defeat the reason they asked.
func readCA(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading --ca "+path+": "+err.Error())
		os.Exit(2)
	}
	return string(b)
}
