//go:build linux

package console

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wordeye/internal/agent"
	"wordeye/internal/govern"
	"wordeye/internal/store"
)

// The whole loop, end to end: a real agent against a real console.
//
// Every piece of this was verified in isolation and the JOIN still did not
// work. In the field an agent enrolled, heartbeated 32 times, and delivered
// zero findings — while a plain scan of the same webroot detected the planted
// shell immediately. Reading the code proved nothing: the client path looked
// correct, the server handler looked correct, and the result was still zero.
//
// So this test wires the actual components together — store, ingest listener,
// agent.Enroll, agent.Client, inotify monitor — and asserts that a shell
// written to disk ends up as a row in the console's database. It is the only
// claim that matters, and the only one that was never true.
//
// Linux-only: real-time monitoring needs inotify.

func testWebroot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("wp-includes/version.php", "<?php\n$wp_version = '6.5.2';\n")
	must("index.php", "<?php\ndefine('WP_USE_THEMES', true);\n")
	must("wp-config.php", "<?php\ndefine('DB_NAME','demo');\n$table_prefix='wp_';\n")
	if err := os.MkdirAll(filepath.Join(root, "wp-content/mu-plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// findingsFor returns rule ids stored against any agent, newest first.
func storedFindings(t *testing.T, h *harness) []store.Finding {
	t.Helper()
	f, err := h.srv.DB().ListFindings(store.FindingFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAgentReportsFindingsToConsole(t *testing.T) {
	h := newHarness(t)
	root := testWebroot(t)
	state := filepath.Join(t.TempDir(), "agent.json")

	// 1. Enroll, exactly as a generated installer does.
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	base := agent.Config{
		Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		// No database or network in the test environment; the filesystem layer
		// is what carries the finding under test.
		SkipDB: true, SkipNet: true, SkipProbe: true, SkipProvenance: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	st, err := agent.Enroll(ctx, agent.ClientConfig{
		Server: h.ingest.URL, Token: h.mintToken(1, false),
		StateFile: state, Label: "loop test", Base: base,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if st.AgentID == "" {
		t.Fatal("enrolled without an agent id")
	}

	// 2. Run the resident client with real-time monitoring, beating fast so
	//    queued detections flush promptly.
	client := agent.NewClient(agent.ClientConfig{
		Server: st.Server, StateFile: state, Label: "loop test",
		Base: base, Monitor: true, HeartbeatInterval: time.Second,
	}, st)
	// Capture the agent's own log: a monitor that fails to start says so here,
	// and discarding it is how this failure stayed opaque.
	var logMu sync.Mutex
	var logs []string
	logf := func(f string, a ...any) {
		logMu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		logMu.Unlock()
	}
	dumpLogs := func() string {
		logMu.Lock()
		defer logMu.Unlock()
		return strings.Join(logs, "\n    ")
	}
	go func() { _ = client.Run(ctx, logf) }()

	// Let the monitor register its watches and finish the startup sweep.
	time.Sleep(3 * time.Second)

	// 3. Plant a shell, the way an attacker would.
	shell := "<?php " + "sys" + "tem($_REQUEST['c']); " + "ev" + "al(" + "base64_" + "decode($_POST['p'])); ?>"
	if err := os.WriteFile(filepath.Join(root, "wp-content/mu-plugins/planted.php"),
		[]byte(shell), 0o644); err != nil {
		t.Fatal(err)
	}

	// 4. It must arrive in the console's database.
	deadline := time.Now().Add(45 * time.Second)
	var found []store.Finding
	for time.Now().Before(deadline) {
		found = storedFindings(t, h)
		for _, f := range found {
			if strings.HasSuffix(filepath.ToSlash(f.Path), "mu-plugins/planted.php") {
				t.Logf("detection reached the console: %s (%s) on %s",
					f.RuleID, f.Severity, f.Path)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	var got []string
	for _, f := range found {
		got = append(got, f.RuleID+" "+f.Path)
	}
	sent, flushErr := client.FlushStats()
	t.Fatalf("the planted shell never reached the console.\n"+
		"  agent:        %s\n"+
		"  stored:       %d %v\n"+
		"  last flush:   %d finding(s) handed to the console, err=%q\n"+
		"  agent log:\n    %s",
		st.AgentID, len(found), got, sent, flushErr, dumpLogs())
}

// The startup sweep must also deliver. A shell already on disk when the agent
// is installed is the common case — the site is compromised before anyone
// deploys monitoring, which is usually WHY monitoring is being deployed.
func TestAgentReportsPreexistingShellOnInstall(t *testing.T) {
	h := newHarness(t)
	root := testWebroot(t)
	state := filepath.Join(t.TempDir(), "agent.json")

	// Already compromised before the agent ever runs.
	shell := "<?php " + "sys" + "tem($_REQUEST['c']); ?>"
	if err := os.WriteFile(filepath.Join(root, "wp-content/mu-plugins/preexisting.php"),
		[]byte(shell), 0o644); err != nil {
		t.Fatal(err)
	}

	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	base := agent.Config{
		Webroot: root, Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg, MaxFileSize: 4 << 20,
		SkipDB: true, SkipNet: true, SkipProbe: true, SkipProvenance: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	st, err := agent.Enroll(ctx, agent.ClientConfig{
		Server: h.ingest.URL, Token: h.mintToken(1, false),
		StateFile: state, Label: "install sweep", Base: base,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	client := agent.NewClient(agent.ClientConfig{
		Server: st.Server, StateFile: state, Base: base,
		Monitor: true, HeartbeatInterval: time.Second,
	}, st)
	go func() { _ = client.Run(ctx, func(string, ...any) {}) }()

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range storedFindings(t, h) {
			if strings.HasSuffix(filepath.ToSlash(f.Path), "preexisting.php") {
				t.Logf("startup sweep reported: %s on %s", f.RuleID, f.Path)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("a shell present at install time was never reported — the startup sweep did not deliver")
}
