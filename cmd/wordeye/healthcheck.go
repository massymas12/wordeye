package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runHealthcheck probes a running console and exits 0 if it is serving.
//
// The runtime image is distroless: no shell, no curl, no wget. That is a
// deliberate choice for a service that faces the internet, and it means the
// container's health probe has to be the binary itself.
//
// It checks the INGEST listener rather than the process table, because "the
// process exists" is not the question anyone cares about. The question is
// whether agents can currently check in.
func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	var (
		url     = fs.String("url", "https://127.0.0.1:8444/v1/ping", "endpoint to probe")
		caFile  = fs.String("ca", "", "PEM certificate to verify the endpoint against")
		timeout = fs.Duration("timeout", 5*time.Second, "probe timeout")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wordeye healthcheck — probe a running console

  Exits 0 when the ingest listener answers, non-zero otherwise. Intended for
  container health probes, where the image deliberately has no shell.

FLAGS
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	tlsCfg := &tls.Config{}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %v\n", *caFile, err)
			return 1
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fmt.Fprintf(os.Stderr, "no certificates found in %s\n", *caFile)
			return 1
		}
		tlsCfg.RootCAs = pool
		// The console's certificate covers the public name agents use, which is
		// not "127.0.0.1". Verification still happens — against the pinned
		// certificate — but the name check would otherwise fail for a probe
		// that is, by construction, talking to itself over loopback.
		tlsCfg.ServerName = ""
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = pinnedVerifier(pool)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	client := &http.Client{Transport: tr, Timeout: *timeout}

	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unhealthy: %s\n", resp.Status)
		return 1
	}
	return 0
}

// pinnedVerifier checks the presented chain against a pinned pool while
// ignoring the hostname. Used only by the loopback self-probe: skipping
// verification entirely would let anything answering on the port report the
// console as healthy.
func pinnedVerifier(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}
}
