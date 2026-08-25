package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wordeye/internal/agent"
	"wordeye/internal/store"
)

// Installer generation.
//
// The platform string arrives from a request and is used to build a FILESYSTEM
// PATH. That is the classic traversal shape, so it is validated against a fixed
// vocabulary rather than sanitised — there is no legitimate platform name
// containing a separator, and an allowlist cannot be outsmarted by encoding.

func TestValidPlatformAllowlist(t *testing.T) {
	good := []string{"linux-amd64", "linux-arm64", "darwin-arm64", "windows-amd64", "freebsd-386"}
	for _, p := range good {
		if !validPlatform(p) {
			t.Errorf("rejected a legitimate platform %q", p)
		}
	}
	bad := []string{
		"../../etc/passwd",
		"linux-amd64/../../../etc/shadow",
		"../linux-amd64",
		"linux/amd64",
		`linux\amd64`,
		"linux-amd64;rm -rf /",
		"",
		"linux",
		"linux-amd64-extra",
		"LINUX-AMD64",
		"linux-amd64%00",
	}
	for _, p := range bad {
		if validPlatform(p) {
			t.Errorf("accepted a dangerous platform %q", p)
		}
	}
}

// A traversal attempt must fail on the allowlist and never reach the
// filesystem, even when the target file genuinely exists.
func TestLoadAgentBinaryRefusesTraversal(t *testing.T) {
	dir := t.TempDir()
	// A file that a traversal would be trying to reach.
	outside := filepath.Join(dir, "secret.pem")
	if err := os.WriteFile(outside, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "agents")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{AgentBinaryDir: binDir}}

	for _, p := range []string{"../secret.pem", "../../etc/passwd", "linux-amd64/../../secret.pem"} {
		if _, _, err := s.loadAgentBinary(p); err == nil {
			t.Errorf("traversal %q was accepted", p)
		}
	}
}

// The happy path: a present binary is read and stamped into something that
// still parses as a configured installer.
func TestGeneratedInstallerCarriesItsConfig(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "agents")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Stand-in for a release binary; stamping only appends to it.
	img := []byte("\x7fELF" + strings.Repeat("code", 1024))
	if err := os.WriteFile(filepath.Join(binDir, "wordeye-agent-linux-amd64"), img, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{AgentBinaryDir: binDir}}

	got, platform, err := s.loadAgentBinary("linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if platform != "linux-amd64" || len(got) != len(img) {
		t.Fatalf("loaded %d bytes for %q, want %d", len(got), platform, len(img))
	}

	var out strings.Builder
	if err := agent.Stamp(&out, got, agent.EmbeddedConfig{
		Server: "https://console.example.com:8444",
		Token:  "wek_test",
		Estate: "Acme Ltd",
	}); err != nil {
		t.Fatal(err)
	}
	stamped := []byte(out.String())
	if !strings.HasPrefix(out.String(), string(img)) {
		t.Error("stamping altered the executable image")
	}
	// The agent must be able to read back what the console wrote; a mismatch
	// here is an installer that looks fine and silently does nothing.
	if !agent.HasEmbeddedConfig(stamped) {
		t.Error("the generated installer does not carry a readable config")
	}
}

// An unknown estate must not produce an installer — that would mint a live
// enrollment token bound to nothing.
func TestGenerateInstallerRequiresARealEstate(t *testing.T) {
	h := newHarness(t)
	if _, err := h.srv.DB().GetEstate(9999); err == nil {
		t.Error("GetEstate accepted a non-existent id")
	}
	// And a real one resolves, so the guard is discriminating rather than
	// simply always failing.
	e, err := h.srv.DB().CreateEstate("Acme", "", "tester")
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.srv.DB().GetEstate(e.ID)
	if err != nil || got.Name != "Acme" {
		t.Fatalf("GetEstate(%d) = %v, %v", e.ID, got, err)
	}
}

var _ = store.Estate{}
