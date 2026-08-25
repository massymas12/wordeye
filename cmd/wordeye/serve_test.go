package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A console that cannot start must say why, once, in terms an operator can act
// on. The failure this guards against was not a crash — it was a console that
// looked deployed: both listeners logged that they were up, the process then
// exited on a missing certificate, and Docker restarted it in a loop. The only
// visible symptom was "Restarting" in docker compose ps.
//
// Wiping volumes to rebuild cleanly lands in precisely this state, and so does
// standing a console up for a new customer for the first time.

func TestMissingIngestCertRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")

	if code := checkIngestTLS(cert, key, false); code == 0 {
		t.Error("the console started with no ingest certificate; agents would have no way to connect")
	}
}

// Half a keypair is still unusable, and the half that exists is the one an
// operator is most likely to believe is sufficient.
func TestPartialKeypairRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := checkIngestTLS(cert, filepath.Join(dir, "key.pem"), false); code == 0 {
		t.Error("the console started with a certificate but no private key")
	}
}

func TestCompleteKeypairStarts(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code := checkIngestTLS(cert, key, false); code != 0 {
		t.Errorf("a complete keypair was rejected: code %d", code)
	}
}

// An operator who explicitly asked for plaintext ingest has already been warned
// by the listener; this check must not override that choice.
func TestPlaintextIngestIsNotBlocked(t *testing.T) {
	dir := t.TempDir()
	if code := checkIngestTLS(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), true); code != 0 {
		t.Error("--insecure was overridden by the certificate check")
	}
}

func TestNoTLSConfiguredIsNotAnError(t *testing.T) {
	if code := checkIngestTLS("", "", false); code != 0 {
		t.Error("a console with no TLS flags at all was blocked")
	}
}
