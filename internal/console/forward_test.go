package console

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wordeye/internal/store"
)

// SIEM forwarding tests.
//
// These run against a real TLS listener rather than a mock, because the two
// things most likely to be wrong — certificate handling and RFC 5425 octet
// framing — only manifest over an actual connection.

// selfSignedCert produces a certificate valid for 127.0.0.1, returning the
// PEM CA path a client can pin.
func selfSignedCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wordeye-test-collector"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return pair, caPath
}

// collector is a minimal RFC 5425 receiver: it reads octet-counted frames and
// hands the payloads back.
type collector struct {
	addr     string
	messages chan string
	ln       net.Listener
}

func startCollector(t *testing.T, cert tls.Certificate) *collector {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{addr: ln.Addr().String(), messages: make(chan string, 64), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					// RFC 5425 framing: decimal length, space, then that many octets.
					lenStr, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(lenStr))
					if err != nil || n <= 0 || n > 1<<20 {
						return
					}
					buf := make([]byte, n)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					select {
					case c.messages <- string(buf):
					default:
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *collector) next(t *testing.T, within time.Duration) string {
	t.Helper()
	select {
	case m := <-c.messages:
		return m
	case <-time.After(within):
		t.Fatal("no syslog message arrived within the timeout")
		return ""
	}
}

// Plaintext transports must be refused outright, not warned about.
func TestForwarderRefusesPlaintextTransports(t *testing.T) {
	for _, target := range []string{
		"udp://siem.example.com:514",
		"tcp://siem.example.com:601",
		"http://siem.example.com",
		"siem.example.com:514",
	} {
		_, err := NewForwarder(ForwardConfig{Target: target}, log.New(io.Discard, "", 0))
		if err == nil {
			t.Errorf("accepted insecure syslog target %q", target)
		}
	}
	// And the secure form is accepted.
	if _, err := NewForwarder(ForwardConfig{Target: "tls://siem.example.com:6514"},
		log.New(io.Discard, "", 0)); err != nil {
		t.Errorf("rejected a valid TLS target: %v", err)
	}
}

func TestForwarderDeliversFindingOverTLS(t *testing.T) {
	cert, caPath := selfSignedCert(t)
	col := startCollector(t, cert)

	f, err := NewForwarder(ForwardConfig{
		Target:     "tls://" + col.addr,
		CAFile:     caPath,
		ServerName: "127.0.0.1",
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	f.Start()
	defer f.Close()

	agent := &store.Agent{
		ID: "ag_test", Hostname: "web01", Label: "Client site",
		Site: "clientsite", Webroot: "/var/www/html", Version: "1.0",
	}
	f.ForwardFinding(agent, store.FindingInput{
		RuleID: "shell.eval_request_var", Class: "SHELL",
		Severity: "critical", Confidence: "confirmed",
		Title:  "eval() of a request-controlled variable",
		Path:   "wp-content/plugins/p/x.php",
		SHA256: "abc123",
	})

	raw := col.next(t, 10*time.Second)

	// Header: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
	if !strings.HasPrefix(raw, "<") {
		t.Fatalf("message does not start with a priority field: %.60s", raw)
	}
	// facility 16 (local0) * 8 + severity 2 (crit) = 130
	if !strings.HasPrefix(raw, "<130>1 ") {
		t.Errorf("expected <130>1 for a critical finding, got %.20s", raw)
	}
	if !strings.Contains(raw, "detection") {
		t.Errorf("MSGID missing: %.120s", raw)
	}

	// The payload must be the ECS JSON.
	idx := strings.Index(raw, "{")
	if idx < 0 {
		t.Fatalf("no JSON payload: %.200s", raw)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(raw[idx:]), &ev); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	rule, _ := ev["rule"].(map[string]any)
	if rule == nil || rule["id"] != "shell.eval_request_var" {
		t.Errorf("rule.id missing or wrong: %v", ev["rule"])
	}
	we, _ := ev["wordeye"].(map[string]any)
	if we == nil || we["agent_id"] != "ag_test" {
		t.Errorf("wordeye.agent_id missing: %v", ev["wordeye"])
	}
	if we["forwarded_by"] != "console" {
		t.Errorf("expected forwarded_by=console, got %v", we["forwarded_by"])
	}
}

// Operator actions matter to a SOC as much as detections: who ordered
// containment across a client estate, and when.
func TestAuditEventsAreForwardedAutomatically(t *testing.T) {
	cert, caPath := selfSignedCert(t)
	col := startCollector(t, cert)

	srv, err := New(Config{
		DBPath: filepath.Join(t.TempDir(), "t.db"),
		Logger: log.New(io.Discard, "", 0),
		Forward: ForwardConfig{
			Target: "tls://" + col.addr, CAFile: caPath, ServerName: "127.0.0.1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Any audited action should reach the collector without the call site
	// knowing forwarding exists.
	_ = srv.DB().Audit("alice", "command.approve", "cmd_x", "kind=contain", "10.0.0.1", "ok")

	raw := col.next(t, 10*time.Second)
	idx := strings.Index(raw, "{")
	if idx < 0 {
		t.Fatalf("no JSON payload: %.200s", raw)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(raw[idx:]), &ev); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	user, _ := ev["user"].(map[string]any)
	if user == nil || user["name"] != "alice" {
		t.Errorf("actor missing from audit event: %v", ev)
	}
	// A containment approval must be elevated above informational so it is
	// visible in a SIEM without a custom rule.
	if !strings.HasPrefix(raw, "<131>") {
		t.Errorf("expected severity err (<131>) for a containment approval, got %.10s", raw)
	}
}

// A dead or slow collector must never stall ingest.
func TestForwarderDoesNotBlockWhenCollectorIsDown(t *testing.T) {
	f, err := NewForwarder(ForwardConfig{
		// Nothing is listening here.
		Target: "tls://127.0.0.1:1",
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	f.Start()
	defer f.Close()

	agent := &store.Agent{ID: "ag_x", Hostname: "h"}
	done := make(chan struct{})
	go func() {
		for i := 0; i < forwardQueueDepth*2; i++ {
			f.ForwardFinding(agent, store.FindingInput{
				RuleID: "x.y", Severity: "high", Title: "t",
			})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("enqueueing blocked while the collector was unreachable")
	}
	// Overflow must be counted, not silently lost.
	_, dropped, _ := f.Stats()
	if dropped == 0 {
		t.Error("queue overflowed but nothing was counted as dropped")
	}
	t.Logf("dropped %d events with the collector down, without blocking", dropped)
}

// Framing must be exact, or a collector cannot find message boundaries.
func TestOctetFraming(t *testing.T) {
	msg := "<134>1 2026-01-01T00:00:00Z host app 1 id - {\"a\":1}"
	framed := string(frame(msg))
	sp := strings.IndexByte(framed, ' ')
	if sp < 0 {
		t.Fatal("no length prefix")
	}
	n, err := strconv.Atoi(framed[:sp])
	if err != nil {
		t.Fatalf("length prefix is not a number: %q", framed[:sp])
	}
	if n != len(msg) {
		t.Errorf("declared length %d, actual %d", n, len(msg))
	}
	if framed[sp+1:] != msg {
		t.Error("framed body does not match the original message")
	}
	// A payload containing newlines must survive framing intact, which is the
	// whole reason octet counting is used instead of line delimiting.
	multi := "<134>1 t h a 1 id - {\"x\":\"line1\nline2\"}"
	f2 := string(frame(multi))
	sp2 := strings.IndexByte(f2, ' ')
	n2, _ := strconv.Atoi(f2[:sp2])
	if n2 != len(multi) || f2[sp2+1:] != multi {
		t.Error("multi-line payload was not framed correctly")
	}
}
