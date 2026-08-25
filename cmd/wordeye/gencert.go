package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runGencert writes a self-signed certificate for the ingest listener.
//
// This exists because the alternative is worse. Standing a console up in a
// hurry — which is when consoles get stood up — the fastest path is
// --insecure-allow-plaintext-ingest, and that puts agent credentials on the
// wire in clear. The second fastest is an openssl invocation with a SAN
// extension, which is fiddly enough that people get it wrong and end up back at
// plaintext.
//
// A self-signed certificate is NOT a weak option here: generated installers
// carry the certificate and pin it, so an agent verifies the console properly
// rather than trusting whatever answers. That is stronger than a public CA
// certificate with no pinning, because it does not trust every other CA on
// earth to not mis-issue for this name.
//
// Use a real certificate if the console has a DNS name and you want browsers
// to be happy. Use this when it has an IP and you want agents secured today.
func runGencert(args []string) int {
	fs := flag.NewFlagSet("gencert", flag.ExitOnError)
	var (
		hosts = fs.String("hosts", "", "comma-separated DNS names and IPs the console answers on (required)")
		dir   = fs.String("out", ".", "directory to write cert.pem and key.pem into")
		days  = fs.Int("days", 825, "validity in days")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wordeye gencert — self-signed certificate for the ingest listener

  Writes cert.pem and key.pem. Point --tls-cert/--tls-key at them.

  Generated installers embed this certificate and PIN it, so agents verify the
  console rather than trusting it blindly. Include every name or address agents
  will use to reach the console: an agent connecting to an address that is not
  in the certificate will refuse, which is the point.

EXAMPLES
  wordeye gencert --hosts console.example.com
  wordeye gencert --hosts 20.1.2.3,console.example.com --out /etc/wordeye

FLAGS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*hosts) == "" {
		fmt.Fprintln(os.Stderr, "--hosts is required: agents must reach the console by a name or address in the certificate")
		return 2
	}

	var dnsNames []string
	var ips []net.IP
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "no usable hosts supplied")
		return 2
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generating key: %v\n", err)
		return 1
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Fprintf(os.Stderr, "generating serial: %v\n", err)
		return 1
	}

	name := dnsNames
	if len(name) == 0 {
		name = []string{ips[0].String()}
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name[0], Organization: []string{"WordEye Console"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, *days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		// Self-signed and self-issuing: the agent pins this exact certificate
		// as its trust root, so it must be a valid CA for that check to pass.
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating certificate: %v\n", err)
		return 1
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "creating %s: %v\n", *dir, err)
		return 1
	}
	certPath := filepath.Join(*dir, "cert.pem")
	keyPath := filepath.Join(*dir, "key.pem")

	if err := writePEM(certPath, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encoding key: %v\n", err)
		return 1
	}
	// 0600: the private key authenticates the console to every agent in the
	// estate.
	if err := writePEM(keyPath, 0o600, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", certPath, keyPath)
	fmt.Fprintf(os.Stderr, "valid for %d days, covering: %s\n", *days,
		strings.Join(append(dnsNames, ipStrings(ips)...), ", "))
	fmt.Fprintln(os.Stderr, "\nAgents reach the console by one of those names. Generated installers")
	fmt.Fprintln(os.Stderr, "embed this certificate and verify against it.")
	return 0
}

func writePEM(path string, mode os.FileMode, blk *pem.Block) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, blk); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	// Re-assert the mode: an existing file keeps its own permissions through
	// O_CREATE, so a key written over a world-readable file would stay one.
	return os.Chmod(path, mode)
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
