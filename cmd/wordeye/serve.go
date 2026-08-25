package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"wordeye/internal/console"
	"wordeye/internal/sign"
)

// runServe starts the management console.
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var (
		dbPath      = fs.String("db", defaultDBPath(), "path to the console database")
		consoleAddr = fs.String("console", "127.0.0.1:8443", "operator console listen address")
		ingestAddr  = fs.String("ingest", "", "agent ingest listen address (empty disables agent check-in)")
		tlsCert     = fs.String("tls-cert", "", "TLS certificate for the ingest listener")
		tlsKey      = fs.String("tls-key", "", "TLS private key")
		consoleTLS  = fs.Bool("console-tls", false, "also serve the operator console over TLS")
		issuer      = fs.String("issuer", "WordEye", "issuer name shown in authenticator apps")
		publicURL   = fs.String("public-url", "", "address agents should report to, e.g. https://console.example.com:8444 (required to generate installers)")
		agentBins   = fs.String("agent-binaries", "", "directory of release binaries named wordeye-agent-<os>-<arch>, stamped to produce estate installers")
		signKey     = fs.String("signing-key", "", "PUBLIC release-signing key stamped into installers so agents can verify upgrades (never the private half)")
		adminUser   = fs.String("admin-user", "admin", "username created on first run")
		insecure    = fs.Bool("insecure-allow-plaintext-ingest", false,
			"permit a non-loopback ingest listener without TLS (only when TLS terminates at a proxy)")

		syslogTo   = fs.String("syslog", "", "forward detections and audit events to a SIEM, e.g. tls://siem.example.com:6514 (TLS only)")
		syslogCA   = fs.String("syslog-ca", "", "PEM CA bundle pinning the collector's certificate")
		syslogCert = fs.String("syslog-cert", "", "client certificate for mutual TLS to the collector")
		syslogKey  = fs.String("syslog-key", "", "client private key for mutual TLS")
		syslogSNI  = fs.String("syslog-server-name", "", "override the expected certificate name (when addressing the collector by IP)")
		syslogFac  = fs.Int("syslog-facility", 16, "syslog facility (16 = local0)")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wordeye serve — management console

  The console runs two listeners with different exposure:

    --console  operator UI and API. Loopback by default. This is where
               containment can be ordered, so it should never face the
               internet. Session auth with mandatory MFA.

    --ingest   agent check-in. Must be reachable from client hosts, so in
               practice it faces the internet. Agents only ever connect
               outbound to it; nothing connects inbound to an agent.

SIEM FORWARDING
  --syslog forwards every detection, scan summary and operator action to a
  collector as RFC 5424 messages over TLS (RFC 5425 octet framing).

  TLS is mandatory. Plaintext udp:// and tcp:// are refused, not warned about:
  this stream names which client sites are compromised and what was found.

EXAMPLES
  wordeye serve
  wordeye serve --ingest 0.0.0.0:8444 --tls-cert fullchain.pem --tls-key key.pem
  wordeye serve --syslog tls://siem.internal:6514 --syslog-ca siem-ca.pem
  wordeye serve --syslog tls://siem.internal:6514 --syslog-cert client.pem --syslog-key client.key

FLAGS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create database directory: %v\n", err)
		return 2
	}

	// Check the ingest certificate BEFORE anything else starts.
	//
	// Previously a missing cert.pem surfaced as a one-line error after both
	// listeners had already logged that they were up, and Docker's restart
	// policy then looped the process forever. `docker compose ps` reported
	// "Restarting" with no reason, the real message scrolled past in logs, and
	// the console looked deployed when it was not. A rebuild that wipes volumes
	// lands in exactly this state, which is the same path taken when standing a
	// console up for a new customer.
	//
	// The cert is deliberately NOT generated here. Agents pin it, so its subject
	// names have to match the addresses agents will use, and this process cannot
	// know those. Guessing would produce a certificate that fails verification
	// on every host in the estate — worse than refusing to start.
	if code := checkIngestTLS(*tlsCert, *tlsKey, *insecure); code != 0 {
		return code
	}

	// Refuse a PRIVATE signing key here, loudly.
	//
	// The two strings differ by a prefix, and pasting the wrong one would put
	// the key that authorises code execution across the estate onto the
	// internet-facing host — silently, because everything would otherwise work.
	// That is the single worst configuration mistake available in this system,
	// so it is worth refusing to start over.
	if strings.HasPrefix(strings.TrimSpace(*signKey), sign.PrivatePrefix) {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "--signing-key was given a PRIVATE key.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Only the public half belongs on a console. Anything holding the private")
		fmt.Fprintln(os.Stderr, "key can make every agent in the estate run arbitrary code, and this host")
		fmt.Fprintln(os.Stderr, "faces the internet.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Run `wordeye gensignkey` on your build machine and pass the wordeye-pub-v1")
		fmt.Fprintln(os.Stderr, "value here, keeping the wordeye-priv-v1 value off this server entirely.")
		fmt.Fprintln(os.Stderr)
		return 2
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	srv, err := console.New(console.Config{
		DBPath:                       *dbPath,
		ConsoleAddr:                  *consoleAddr,
		IngestAddr:                   *ingestAddr,
		TLSCert:                      *tlsCert,
		TLSKey:                       *tlsKey,
		ConsoleTLS:                   *consoleTLS,
		Issuer:                       *issuer,
		PublicURL:                    *publicURL,
		AgentBinaryDir:               *agentBins,
		ReleaseSigningPublicKey:      *signKey,
		InsecureAllowPlaintextIngest: *insecure,
		Logger:                       logger,
		Forward: console.ForwardConfig{
			Target:     *syslogTo,
			CAFile:     *syslogCA,
			ClientCert: *syslogCert,
			ClientKey:  *syslogKey,
			ServerName: *syslogSNI,
			Facility:   *syslogFac,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	defer srv.Close()

	if err := bootstrapAdmin(srv, *adminUser); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	scheme := "http"
	if *consoleTLS {
		scheme = "https"
	}
	logger.Printf("database %s", *dbPath)
	logger.Printf("open the console at %s://%s", scheme, *consoleAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}

// bootstrapAdmin creates the first account on an empty database and prints its
// password once, to stderr only.
//
// Generated rather than defaulted: a console that ships with a known default
// credential is a console that gets found and used by someone else.
func bootstrapAdmin(srv *console.Server, username string) error {
	n, err := srv.DB().CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pw, err := generatePassword(24)
	if err != nil {
		return err
	}
	if _, err := srv.DB().CreateUser(username, pw, "admin"); err != nil {
		return fmt.Errorf("creating the first administrator: %w", err)
	}
	_ = srv.DB().Audit("system", "user.bootstrap", username, "first-run administrator created", "local", "ok")

	line := strings.Repeat("─", 68)
	fmt.Fprintf(os.Stderr, "\n%s\n", line)
	fmt.Fprintf(os.Stderr, "  First run: an administrator account has been created.\n\n")
	fmt.Fprintf(os.Stderr, "    username  %s\n", username)
	fmt.Fprintf(os.Stderr, "    password  %s\n\n", pw)
	fmt.Fprintf(os.Stderr, "  This is shown once and is not stored in recoverable form.\n")
	fmt.Fprintf(os.Stderr, "  You will be required to set up an authenticator app on first sign-in.\n")
	fmt.Fprintf(os.Stderr, "%s\n\n", line)
	return nil
}

// generatePassword produces a readable high-entropy passphrase-style string.
// Ambiguous characters are excluded because this gets transcribed by hand.
func generatePassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 && i%6 == 0 {
			sb.WriteByte('-')
		}
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		sb.WriteByte(alphabet[idx.Int64()])
	}
	return sb.String(), nil
}

func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wordeye.db"
	}
	return filepath.Join(home, ".wordeye", "console.db")
}

// checkIngestTLS verifies the ingest certificate exists and is readable, and
// explains precisely how to create it when it does not.
//
// An operator standing up a console reads the first error and acts on it. That
// error therefore has to name the command to run, not the file that was absent.
func checkIngestTLS(certPath, keyPath string, insecure bool) int {
	if insecure {
		// The operator explicitly asked for plaintext ingest; the listener will
		// warn about it on its own.
		return 0
	}
	if certPath == "" && keyPath == "" {
		return 0
	}
	missing := make([]string, 0, 2)
	for _, p := range []string{certPath, keyPath} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return 0
	}

	fmt.Fprintf(os.Stderr, "\nThe ingest listener has no TLS certificate, so the console cannot start.\n\n")
	for _, p := range missing {
		fmt.Fprintf(os.Stderr, "    missing  %s\n", p)
	}
	fmt.Fprintf(os.Stderr, "\nAgents verify this certificate by pinning, so it must name every address\n")
	fmt.Fprintf(os.Stderr, "they will use to reach the console. Generate it with:\n\n")
	fmt.Fprintf(os.Stderr, "    docker compose --profile tools run --rm certgen\n\n")
	fmt.Fprintf(os.Stderr, "which reads WORDEYE_HOSTS from .env. Outside Docker:\n\n")
	fmt.Fprintf(os.Stderr, "    wordeye gencert --hosts console.example.com,203.0.113.10 --out /certs\n\n")
	fmt.Fprintf(os.Stderr, "Then start the console again. Installers generated afterwards embed the\n")
	fmt.Fprintf(os.Stderr, "new certificate; any generated before it will no longer verify.\n\n")
	return 2
}
