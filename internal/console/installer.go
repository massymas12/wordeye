package console

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wordeye/internal/agent"
	"wordeye/internal/store"
)

// Generated installers.
//
// An estate gets covered only if rolling the agent out is trivial. Asking a
// customer's administrator to copy a binary, then a token, then compose a
// command line with a server URL, loses hosts to typos and to people who never
// get round to it. So the console produces ONE file that takes NO arguments:
// run it, and the host appears in the console under the right customer.
//
// The console does not compile anything. It appends a configuration blob to a
// copy of the release binary (see internal/agent/embedded.go), so no toolchain
// is needed and the executable code is byte-for-byte the release build.
//
// SECURITY POSTURE
//
// A generated installer contains a live enrollment token and is therefore a
// credential. Three things bound the damage:
//
//   - The token is SINGLE-USE and short-lived. Once a host enrolls, the file is
//     inert; an installer that leaks after use grants nothing.
//   - It CANNOT grant remote containment. The two-key rule (console token AND
//     host opt-in) exists so console compromise cannot order destruction across
//     an estate; letting a generated file carry both keys would make the second
//     decorative, and a leaked installer would arrive pre-authorised to destroy
//     whatever host ran it. Containment stays an explicit act on the host.
//   - Generation is an admin-only action and is audited, so an unexpected
//     installer is attributable.

// installerMaxBinary caps what will be read from the binary directory. A
// stamped agent is ~9MB; this is generous enough for any future build and
// small enough that a mis-pointed directory cannot exhaust memory.
const installerMaxBinary = 128 << 20

type installerRequest struct {
	// Platform selects which release binary to stamp, e.g. "linux-amd64".
	Platform string `json:"platform"`
	// Label is applied to hosts enrolled with this installer.
	Label string `json:"label"`
	// Monitor makes the installed agent resident rather than one-shot.
	Monitor bool `json:"monitor"`
	// Uses allows one installer to cover several hosts. Defaults to 1.
	Uses int `json:"uses"`
	// TTLHours bounds the enrollment window. Defaults to 72.
	TTLHours int `json:"ttl_hours"`
}

// handleGenerateInstaller stamps a release binary with enrollment instructions
// for one estate and returns it as a download.
func (s *Server) handleGenerateInstaller(w http.ResponseWriter, r *http.Request, c *ctx) {
	if s.cfg.AgentBinaryDir == "" {
		writeErr(w, http.StatusNotImplemented,
			"this console has no agent binary directory configured (--agent-binaries)")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad estate id")
		return
	}
	est, err := s.db.GetEstate(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	var req installerRequest
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Uses <= 0 {
		req.Uses = 1
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 72
	}
	if req.Uses > 500 || req.TTLHours > 24*30 {
		writeErr(w, http.StatusBadRequest, "uses or ttl_hours beyond the permitted range")
		return
	}

	bin, platform, err := s.loadAgentBinary(req.Platform)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Mint the token LAST among the failure-prone steps, so a failed generation
	// does not leave a live unused token behind.
	//
	// allowContain is hard-wired false: see the note at the top of this file.
	plain, tok, err := s.db.CreateEnrollToken(
		fmt.Sprintf("installer: %s (%s)", est.Name, platform),
		c.user.Username, time.Duration(req.TTLHours)*time.Hour, req.Uses, false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.db.SetTokenEstate(tok.ID, est.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	cfg := agent.EmbeddedConfig{
		Server:      s.cfg.PublicURL,
		Token:       plain,
		Label:       strings.TrimSpace(req.Label),
		Estate:      est.Name,
		CAPEM:       s.publicCAPEM(),
		Monitor:     req.Monitor,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		GeneratedBy: c.user.Username,
	}
	if cfg.Server == "" {
		writeErr(w, http.StatusNotImplemented,
			"this console has no public URL configured (--public-url); a generated agent would not know where to report")
		return
	}

	var out bytes.Buffer
	if err := agent.Stamp(&out, bin, cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	name := fmt.Sprintf("wordeye-%s-%s", est.Slug, platform)
	if strings.HasPrefix(platform, "windows") {
		name += ".exe"
	}
	s.audit(c, r, "installer.generate", est.Name,
		fmt.Sprintf("platform=%s uses=%d ttl=%dh token=%s", platform, req.Uses, req.TTLHours, tok.Prefix), "ok")

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(out.Len()))
	_, _ = w.Write(out.Bytes())
}

// loadAgentBinary reads a release binary by platform name.
//
// The platform is used to build a filename, so it is validated against a strict
// allowlist pattern rather than sanitised: a request that reaches the
// filesystem with attacker-influenced path components is a traversal waiting to
// happen, and there is no legitimate platform name containing a separator.
func (s *Server) loadAgentBinary(platform string) ([]byte, string, error) {
	if platform == "" {
		platform = "linux-amd64"
	}
	if !validPlatform(platform) {
		return nil, "", fmt.Errorf("unsupported platform %q", platform)
	}
	name := "wordeye-agent-" + platform
	path := filepath.Join(s.cfg.AgentBinaryDir, name)
	if _, err := os.Stat(path); err != nil {
		if _, err2 := os.Stat(path + ".exe"); err2 == nil {
			path += ".exe"
		} else {
			return nil, "", fmt.Errorf("no agent binary for %s in the configured directory", platform)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if fi.Size() > installerMaxBinary {
		return nil, "", fmt.Errorf("agent binary for %s is implausibly large", platform)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return b, platform, nil
}

// validPlatform allows only <os>-<arch> built from a fixed vocabulary.
func validPlatform(p string) bool {
	oses := map[string]bool{"linux": true, "darwin": true, "windows": true, "freebsd": true}
	arches := map[string]bool{"amd64": true, "arm64": true, "386": true, "arm": true}
	parts := strings.Split(p, "-")
	return len(parts) == 2 && oses[parts[0]] && arches[parts[1]]
}

// publicCAPEM returns the console's certificate so a self-signed deployment can
// be verified by pinning rather than by disabling verification. Empty means the
// agent uses the system trust store.
func (s *Server) publicCAPEM() string {
	if s.cfg.TLSCert == "" {
		return ""
	}
	b, err := os.ReadFile(s.cfg.TLSCert)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// estates
// ---------------------------------------------------------------------------

func (s *Server) handleListEstates(w http.ResponseWriter, r *http.Request, c *ctx) {
	all := r.URL.Query().Get("archived") == "1"
	est, err := s.db.ListEstates(all)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nz(est))
}

type estateRequest struct {
	Name  string `json:"name"`
	Notes string `json:"notes"`
}

func (s *Server) handleCreateEstate(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req estateRequest
	if err := readJSON(w, r, 8<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	est, err := s.db.CreateEstate(clamp(req.Name, 120), clamp(req.Notes, 2000), c.user.Username)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "estate.create", est.Name, "", "ok")
	writeJSON(w, http.StatusOK, est)
}

func (s *Server) handleArchiveEstate(w http.ResponseWriter, r *http.Request, c *ctx) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad estate id")
		return
	}
	if err := s.db.ArchiveEstate(id, true); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(c, r, "estate.archive", strconv.FormatInt(id, 10), "", "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type agentEstateRequest struct {
	EstateID int64 `json:"estate_id"`
}

func (s *Server) handleAgentEstate(w http.ResponseWriter, r *http.Request, c *ctx) {
	var req agentEstateRequest
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	id := r.PathValue("id")
	if err := s.db.SetAgentEstate(id, req.EstateID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(c, r, "agent.estate", id, strconv.FormatInt(req.EstateID, 10), "ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

var _ = store.Estate{}
