package console

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for the findings of the security review. Each one failed
// before its fix.

// The TLS preflight must recognise every way of binding publicly. ":8444" binds
// all interfaces but was classified as loopback, silently disabling the guard.
func TestLoopbackDetection(t *testing.T) {
	cases := []struct {
		addr         string
		wantLoopback bool
	}{
		{"127.0.0.1:8443", true},
		{"localhost:8443", true},
		{"[::1]:8443", true},
		{"0.0.0.0:8444", false},
		{"192.168.1.10:8444", false},
		{"[::]:8444", false},
		{":8444", false},
		{"console.example.com:8444", false},
	}
	for _, c := range cases {
		if got := isLoopbackAddr(c.addr); got != c.wantLoopback {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", c.addr, got, c.wantLoopback)
		}
	}
}

func TestPreflightRefusesPlaintextPublicIngest(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8444", ":8444", "192.168.1.5:8444", "[::]:8444"} {
		srv, err := New(Config{
			DBPath:      filepath.Join(t.TempDir(), "t.db"),
			ConsoleAddr: "127.0.0.1:8443",
			IngestAddr:  addr,
			Logger:      log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		err = srv.preflight()
		srv.Close()
		if err == nil {
			t.Errorf("preflight accepted plaintext ingest on %q — credentials would cross the network in clear", addr)
		} else if !strings.Contains(err.Error(), "without TLS") {
			t.Errorf("unexpected error for %q: %v", addr, err)
		}
	}
	// Loopback without TLS stays allowed: nothing leaves the machine.
	srv, err := New(Config{
		DBPath:      filepath.Join(t.TempDir(), "t.db"),
		ConsoleAddr: "127.0.0.1:8443",
		IngestAddr:  "127.0.0.1:8444",
		Logger:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := srv.preflight(); err != nil {
		t.Errorf("preflight refused loopback ingest: %v", err)
	}
}

// Login must reject a request that carries no custom header, which is what
// stops an attacker forcing a victim's browser to sign in as them.
func TestLoginRequiresCustomHeader(t *testing.T) {
	h := newHarness(t)
	if _, err := h.srv.DB().CreateUser("tester", "correct-horse-battery", "admin"); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"username": "tester", "password": "correct-horse-battery"})

	req, _ := http.NewRequest(http.MethodPost, h.console.URL+"/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("login without the custom header returned %d, want 403", resp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodPost, h.console.URL+"/api/login", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-WordEye-CSRF", "pre-session")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("login WITH the header returned %d, want 200", resp2.StatusCode)
	}
}

// A single compromised session must not be able to both order and authorise
// destruction — whenever a second approver actually exists.
func TestSeparateApproverEnforcedWithMultipleOperators(t *testing.T) {
	h := newHarness(t)
	ag, _, _ := h.enroll(h.mintToken(1, true), true)

	// Sole operator: self-approval is permitted, since nothing else is possible.
	if _, err := h.srv.DB().CreateUser("solo", "correct-horse-battery", "admin"); err != nil {
		t.Fatal(err)
	}
	cmd, err := h.srv.DB().CreateCommand(ag.AgentID, "contain", map[string]any{}, "solo", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.DB().ApproveCommand(cmd.ID, "solo"); err != nil {
		t.Fatalf("sole operator could not self-approve: %v", err)
	}

	// Add a second operator; self-approval must now be refused.
	if _, err := h.srv.DB().CreateUser("second", "correct-horse-battery", "operator"); err != nil {
		t.Fatal(err)
	}
	cmd2, err := h.srv.DB().CreateCommand(ag.AgentID, "contain", map[string]any{}, "solo", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.DB().ApproveCommand(cmd2.ID, "solo"); err == nil {
		t.Error("an operator approved their own destructive command while a second approver existed")
	}
	if err := h.srv.DB().ApproveCommand(cmd2.ID, "second"); err != nil {
		t.Errorf("a different operator could not approve: %v", err)
	}
}

// An agent must not be able to mark a command complete that was never
// dispatched to it — that would fake an approval having happened.
func TestAgentCannotCompleteUndispatchedCommand(t *testing.T) {
	h := newHarness(t)
	ag, _, _ := h.enroll(h.mintToken(1, true), true)

	cmd, err := h.srv.DB().CreateCommand(ag.AgentID, "contain", map[string]any{}, "creator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := h.postJSON(h.ingest.URL, "/v1/command/result", ag.auth(),
		map[string]any{"id": cmd.ID, "status": "done", "result": "nope"}, nil)
	if code == http.StatusOK {
		t.Error("agent completed a pending, unapproved command")
	}
	after, _ := h.srv.DB().GetCommand(cmd.ID)
	if after.Status != "pending" {
		t.Errorf("command status = %q, want pending", after.Status)
	}
}

// Oversized reports must not be retained verbatim.
func TestOversizedReportIsSummarised(t *testing.T) {
	h := newHarness(t)
	ag, _, _ := h.enroll(h.mintToken(1, false), false)

	// A valid report padded past the retention threshold.
	big := strings.Repeat("A", maxRawRetained+2048)
	report := map[string]any{
		"schema": "wordeye.report/1", "mode": "scan", "verdict": "clean",
		"stats":  map[string]any{"files_seen": 1, "files_read": 1},
		"errors": []string{big},
	}
	raw, _ := json.Marshal(report)
	if len(raw) <= maxRawRetained {
		t.Fatalf("test payload too small: %d", len(raw))
	}
	req, _ := http.NewRequest(http.MethodPost, h.ingest.URL+"/v1/report", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", ag.auth())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("report rejected: %d", resp.StatusCode)
	}

	var stored string
	if err := h.srv.DB().SQL().QueryRow(`SELECT raw FROM reports LIMIT 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) > maxRawRetained {
		t.Errorf("stored raw report is %d bytes; it should have been summarised", len(stored))
	}
	if !strings.Contains(stored, "verbatim report omitted") {
		t.Errorf("expected a summary marker, got %.80s", stored)
	}
}
