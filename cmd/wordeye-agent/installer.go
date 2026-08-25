package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wordeye/internal/agent"
	"wordeye/internal/govern"
)

// runInstaller is the zero-argument path taken by a console-stamped binary.
//
// The person running this is a site administrator, not an operator of this
// tool. They should not have to supply a server address, a token, or a webroot,
// and they should be told plainly what just happened to their machine. So the
// output is deliberately prose rather than log lines.
//
// Enrollment is idempotent: if a credential already exists, the binary connects
// with it rather than burning another token use. Someone running the installer
// twice is a normal event, not an error.
func runInstaller(cfg *agent.EmbeddedConfig) int {
	agent.Version = version
	home, _ := os.UserHomeDir()
	statePath := agent.DefaultStateFile(home)

	fmt.Fprintf(os.Stderr, "WordEye installer — %s\n", cfg.Estate)
	fmt.Fprintf(os.Stderr, "console: %s\n\n", cfg.Server)

	webroot := agent.FindWebroot(home)
	if webroot == "" {
		fmt.Fprintln(os.Stderr, "No WordPress installation was found from this account's home directory.")
		fmt.Fprintln(os.Stderr, "Run the installer as the user that owns the site, or pass --webroot.")
		return 2
	}
	fmt.Fprintf(os.Stderr, "WordPress found at %s\n", webroot)

	// A RESIDENT agent runs on someone's production site, unattended, forever.
	// "balanced" is the right default for a one-shot scan an operator is
	// watching; it is the wrong one for a daemon. A field deployment ran the
	// startup sweep at balanced and took a shared host to 2.2x overload.
	//
	// safe means one worker, 8MB/s of IO and nice 15 — the sweep takes longer
	// and nobody is waiting for it. Uptime is the product requirement here.
	prof := govern.ProfileSafe
	base := agent.Config{
		Webroot:     webroot,
		Home:        home,
		Label:       cfg.Label,
		Packs:       []string{"core"},
		Profile:     prof,
		Gov:         govern.ForProfile(prof),
		MaxFileSize: 4 << 20,
		MaxActions:  25,
		// Header-probe non-executable files rather than reading all of them.
		// The installer's sweep previously read every byte of a 68,000-file
		// site — 679MB — because Quick defaulted to false. A script wearing an
		// asset extension is still caught from its first bytes.
		Quick: true,
	}

	st, err := agent.LoadState(statePath)
	switch {
	case err == nil && st != nil && st.AgentID != "":
		fmt.Fprintf(os.Stderr, "Already enrolled as %s; reusing the existing credential.\n", st.AgentID)
	default:
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		st, err = agent.Enroll(ctx, agent.ClientConfig{
			Server: cfg.Server, Token: cfg.Token, StateFile: statePath,
			Label: cfg.Label, CAPEM: cfg.CAPEM, SigningKey: cfg.SigningKey,
			// Deliberately NOT taken from the embedded config: the two-key rule
			// means a host must opt in to destructive orders itself. A file
			// that arrives pre-authorised to destroy the machine it lands on
			// would make the second key decorative.
			AllowRemoteContain: false,
			Base:               base,
		})
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nEnrollment failed: %v\n\n", err)
			// Name the RIGHT next step. Telling someone their token expired
			// when the real problem was DNS sends them to request a new
			// installer that will fail in exactly the same way.
			switch classifyEnrollError(err) {
			case enrollNetwork:
				fmt.Fprintf(os.Stderr, "This host could not reach the console at %s.\n", cfg.Server)
				fmt.Fprintln(os.Stderr, "Check outbound access and DNS from this machine, then run the installer again.")
			case enrollTLS:
				fmt.Fprintln(os.Stderr, "The console's TLS certificate was not accepted.")
				fmt.Fprintln(os.Stderr, "If the console uses a private CA, regenerate this installer so it carries the certificate.")
			default:
				fmt.Fprintln(os.Stderr, "The console refused the enrollment token. It may have expired or already been used.")
				fmt.Fprintln(os.Stderr, "Ask for a fresh installer from the console.")
			}
			return 1
		}
		fmt.Fprintf(os.Stderr, "Enrolled as %s\n", st.AgentID)
		fmt.Fprintf(os.Stderr, "Credential stored at %s (mode 0600)\n", statePath)
	}

	fmt.Fprintln(os.Stderr, "Remote containment: NOT permitted on this host.")
	fmt.Fprintln(os.Stderr, "  Nothing on this machine can be deleted or killed from the console")
	fmt.Fprintln(os.Stderr, "  unless an administrator here explicitly opts in.")

	if !cfg.Monitor {
		fmt.Fprintln(os.Stderr, "\nRunning a first scan; results will appear in the console.")
		return runManagedOnce(st, base, cfg)
	}

	// One baseline scan, then event-driven monitoring — the EDR model.
	//
	// A resident agent that re-scans an entire site on a timer is a periodic
	// scanner wearing a monitor's clothes, and it costs a production host real
	// CPU and IO forever. The useful division is the one mature EDR products
	// make:
	//
	//	install    ONE full scan, establishing what is already on disk
	//	steady     inotify only: evaluate what CHANGES, and nothing else
	//	on demand  the operator presses "Run scan" when they have a reason
	//
	// That makes the expensive operation an explicit, attributable choice
	// rather than a surprise at 3am, and it is why RescanPeriod stays zero
	// below. An operator who wants a recurring sweep can still ask for one
	// with `connect --rescan 24h`.
	fmt.Fprintln(os.Stderr, "\nRunning the initial baseline scan; results will appear in the console.")
	if code := runManagedOnce(st, base, cfg); code != 0 {
		fmt.Fprintln(os.Stderr, "the baseline scan did not complete; monitoring will still start")
	}

	fmt.Fprintln(os.Stderr, "\nStarting real-time monitoring. Leave this running, or install it as a service:")
	fmt.Fprintf(os.Stderr, "  %s connect\n", exeName())
	fmt.Fprintln(os.Stderr, "From here it only evaluates files as they change. Use \"Run scan\" in the")
	fmt.Fprintln(os.Stderr, "console for a full sweep whenever you want one.")

	logger := log.New(os.Stderr, "", log.LstdFlags)
	client := agent.NewClient(agent.ClientConfig{
		Server: st.Server, StateFile: statePath, Label: cfg.Label,
		CAPEM:              cfg.CAPEM,
		SigningKey:         cfg.SigningKey,
		AllowRemoteContain: st.AllowRemoteContain,
		Base:               base,
		Monitor:            true,
		// Zero disables the recurring full sweep: steady state is event-driven.
		RescanPeriod: 0,
	}, st)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.Run(ctx, logger.Printf); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "agent stopped: %v\n", err)
		return 1
	}
	return 0
}

// runManagedOnce performs a single scan and reports it, then exits.
func runManagedOnce(st *agent.ClientState, base agent.Config, cfg *agent.EmbeddedConfig) int {
	client := agent.NewClient(agent.ClientConfig{
		Server: st.Server, StateFile: agent.DefaultStateFile(base.Home),
		Label: cfg.Label, CAPEM: cfg.CAPEM, SigningKey: cfg.SigningKey, Base: base,
	}, st)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := client.ScanAndReport(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Done. This host now appears in the console.")
	return 0
}

// Enrollment failure categories. The three have completely different remedies,
// and an installer that names the wrong one wastes an administrator's afternoon.
type enrollFailure int

const (
	enrollRejected enrollFailure = iota // the console answered and said no
	enrollNetwork                       // we never reached the console
	enrollTLS                           // we reached it but would not trust it
)

func classifyEnrollError(err error) enrollFailure {
	// net.Error and x509 types are wrapped through several layers by the time
	// they surface here, so match on the text the standard library produces.
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "certificate"), strings.Contains(s, "x509"),
		strings.Contains(s, "tls"):
		return enrollTLS
	case strings.Contains(s, "no such host"), strings.Contains(s, "lookup"),
		strings.Contains(s, "connection refused"), strings.Contains(s, "timeout"),
		strings.Contains(s, "timed out"), strings.Contains(s, "unreachable"),
		strings.Contains(s, "dial tcp"), strings.Contains(s, "network is down"):
		return enrollNetwork
	default:
		return enrollRejected
	}
}

func exeName() string {
	p, err := os.Executable()
	if err != nil {
		return "wordeye-agent"
	}
	return p
}
