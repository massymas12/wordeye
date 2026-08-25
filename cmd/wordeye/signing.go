package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wordeye/internal/sign"
)

// Release signing lives here, in the CLI, and deliberately not in the console.
//
// The private key is the thing that decides what code runs on every customer's
// production server. Putting it on the internet-facing component would mean a
// console compromise is a fleet compromise, which is the outcome the whole
// design exists to prevent. So the key is generated on a build machine, kept
// there, and only its public half ever ships.

func runGenSignKey(args []string) int {
	fs := flag.NewFlagSet("gensignkey", flag.ContinueOnError)
	out := fs.String("out", "", "file to write the private key to (default: stdout only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pub, priv, err := sign.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generating key: %v\n", err)
		return 1
	}

	if *out != "" {
		// 0600 and a fresh file: this key authorises code execution across the
		// estate, so it must never be group- or world-readable.
		if err := os.WriteFile(*out, []byte(priv+"\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "writing %s: %v\n", *out, err)
			return 1
		}
		_ = os.Chmod(*out, 0o600) // defeat a mode-preserving create over an existing file
		fmt.Fprintf(os.Stderr, "private key written to %s (mode 0600)\n\n", *out)
	}

	fmt.Fprintf(os.Stderr, "PUBLIC KEY — stamp this into installers with --signing-key:\n\n  %s\n\n", pub)
	if *out == "" {
		fmt.Fprintf(os.Stderr, "PRIVATE KEY — keep on the build machine, never deploy it:\n\n  %s\n\n", priv)
	}
	fmt.Fprintln(os.Stderr, "Anything holding the private key can make every agent in the estate run")
	fmt.Fprintln(os.Stderr, "arbitrary code. It must not be copied to the console, a CI runner with")
	fmt.Fprintln(os.Stderr, "broad access, or any host an agent reports to.")
	return 0
}

func runSignRelease(args []string) int {
	fs := flag.NewFlagSet("sign-release", flag.ContinueOnError)
	keyFile := fs.String("key", "", "file containing the private signing key (required)")
	dir := fs.String("dir", "", "directory of wordeye-agent-<os>-<arch> binaries (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyFile == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: wordeye sign-release --key signing.key --dir ./agents")
		return 2
	}

	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading key: %v\n", err)
		return 1
	}
	priv := strings.TrimSpace(string(raw))
	pub, err := sign.PublicOf(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", *dir, err)
		return 1
	}
	signed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "wordeye-agent-") || strings.HasSuffix(name, ".sig") {
			continue
		}
		p := filepath.Join(*dir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}
		sig, err := sign.Sign(priv, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}
		if err := os.WriteFile(p+".sig", []byte(sig+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(os.Stderr, "  signed %-34s sha256 %s\n", name, hex.EncodeToString(sum[:])[:16])
		signed++
	}
	if signed == 0 {
		fmt.Fprintln(os.Stderr, "no wordeye-agent-<os>-<arch> binaries found")
		return 1
	}
	fmt.Fprintf(os.Stderr, "\n%d binaries signed. Public key for installers:\n\n  %s\n", signed, pub)
	return 0
}
