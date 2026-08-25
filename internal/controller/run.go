package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"wordeye/internal/model"
)

// remoteDir is where the agent and its packs live on each host. Self-contained
// and inside the account's own home, so no privileged path is touched and
// cleanup is a single rm -rf.
const remoteDir = ".wordeye"

type Options struct {
	AgentBinary string
	Packs       []string // local pack files to ship alongside the binary
	Mode        string   // scan|baseline|verify
	Profile     string
	Quick       bool
	Concurrency int
	Timeout     time.Duration
	// ContainDryRun asks each host for its containment plan without executing.
	ContainDryRun bool
	// Contain actually performs containment. Requires explicit opt-in at the
	// CLI, because it is destructive on every host at once.
	Contain bool
	// KeepAgent leaves the binary in place for repeat runs.
	KeepAgent bool
	// Extra flags appended to every remote invocation.
	Extra []string
	// Progress receives human-readable status lines.
	Progress func(string)
}

// Result pairs a host with whatever came back from it.
type Result struct {
	Host     Host            `json:"host"`
	Reports  []*model.Report `json:"reports,omitempty"`
	Err      string          `json:"error,omitempty"`
	Duration time.Duration   `json:"duration_ms"`
	Deployed bool            `json:"deployed"`
}

func (r Result) OK() bool { return r.Err == "" }

// Run fans out across the estate. Hosts are independent, so this is a simple
// bounded-concurrency fan-out: one slow or unreachable host delays only itself.
func Run(ctx context.Context, inv *Inventory, opt Options) []Result {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 8
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Minute
	}
	if opt.Progress == nil {
		opt.Progress = func(string) {}
	}

	binSum, err := fileSHA256(opt.AgentBinary)
	if err != nil {
		// Fail every host with the same error rather than silently deploying
		// nothing.
		out := make([]Result, 0, len(inv.Hosts))
		for _, h := range inv.Hosts {
			out = append(out, Result{Host: h, Err: fmt.Sprintf("agent binary: %v", err)})
		}
		return out
	}

	results := make([]Result, len(inv.Hosts))
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup

	for i, h := range inv.Hosts {
		wg.Add(1)
		go func(i int, h Host) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Host: h, Err: "cancelled before start"}
				return
			}

			hctx, cancel := context.WithTimeout(ctx, opt.Timeout)
			defer cancel()

			start := time.Now()
			res := runHost(hctx, h, opt, binSum)
			res.Duration = time.Since(start)
			results[i] = res

			status := "ok"
			if !res.OK() {
				status = "FAILED: " + res.Err
			} else if v := worstVerdict(res.Reports); v != "clean" {
				status = strings.ToUpper(v)
			}
			opt.Progress(fmt.Sprintf("%-32s %-9s %s", h.Name(), res.Duration.Round(time.Millisecond), status))
		}(i, h)
	}
	wg.Wait()
	return results
}

func runHost(ctx context.Context, h Host, opt Options, binSum string) Result {
	res := Result{Host: h}

	// 1. Make the remote directory and find out what is already there. One
	//    round trip rather than three.
	probe := fmt.Sprintf("mkdir -p ~/%s && (sha256sum ~/%s/wordeye-agent 2>/dev/null || echo none) && uname -m",
		remoteDir, remoteDir)
	out, err := sshRun(ctx, h, probe)
	if err != nil {
		res.Err = "ssh probe failed: " + firstLine(err.Error(), out)
		return res
	}
	lines := strings.Fields(strings.TrimSpace(out))
	remoteSum := ""
	if len(lines) > 0 && lines[0] != "none" {
		remoteSum = lines[0]
	}

	// 2. Deploy only when the binary differs. On a repeat sweep across a large
	//    estate this turns the upload into a no-op.
	if remoteSum != binSum {
		if err := scpTo(ctx, h, opt.AgentBinary, "~/"+remoteDir+"/wordeye-agent.new"); err != nil {
			res.Err = "upload failed: " + err.Error()
			return res
		}
		// Rename into place, so a concurrent run never sees a partial binary.
		mv := fmt.Sprintf("chmod 700 ~/%s/wordeye-agent.new && mv ~/%s/wordeye-agent.new ~/%s/wordeye-agent",
			remoteDir, remoteDir, remoteDir)
		if _, err := sshRun(ctx, h, mv); err != nil {
			res.Err = "install failed: " + err.Error()
			return res
		}
		res.Deployed = true
	}

	// 3. Ship any file-based rule packs.
	var remotePacks []string
	for _, p := range opt.Packs {
		name := filepath.Base(p)
		if err := scpTo(ctx, h, p, "~/"+remoteDir+"/"+name); err != nil {
			res.Err = fmt.Sprintf("pack upload failed (%s): %v", name, err)
			return res
		}
		remotePacks = append(remotePacks, "~/"+remoteDir+"/"+name)
	}

	// 4. Run.
	cmd := buildRemoteCommand(h, opt, remotePacks)
	stdout, runErr := sshRun(ctx, h, cmd)

	reports, perr := parseReports(stdout)
	switch {
	case len(reports) > 0:
		res.Reports = reports
	case runErr != nil:
		res.Err = "agent failed: " + firstLine(runErr.Error(), stdout)
		return res
	case perr != nil:
		res.Err = "unparseable agent output: " + perr.Error()
		return res
	default:
		res.Err = "agent produced no report"
		return res
	}

	// 5. Optionally remove the binary.
	if !opt.KeepAgent {
		_, _ = sshRun(ctx, h, "rm -f ~/"+remoteDir+"/wordeye-agent")
	}
	return res
}

func buildRemoteCommand(h Host, opt Options, remotePacks []string) string {
	args := []string{"~/" + remoteDir + "/wordeye-agent"}
	if opt.Mode != "" && opt.Mode != "scan" {
		args = append(args, opt.Mode)
	}
	args = append(args, "--json", "-", "--quiet")

	packs := h.Packs
	if len(packs) == 0 {
		packs = []string{"core"}
	}
	for _, p := range packs {
		args = append(args, "--pack", shellQuote(p))
	}
	for _, p := range remotePacks {
		args = append(args, "--pack", p)
	}

	if opt.Profile != "" {
		args = append(args, "--profile", opt.Profile)
	}
	if opt.Quick {
		args = append(args, "--quick")
	}
	if h.Webroot != "" {
		args = append(args, "--webroot", shellQuote(h.Webroot))
	}
	if h.AllSites {
		args = append(args, "--all-sites")
	}
	if h.Label != "" {
		args = append(args, "--label", shellQuote(h.Label))
	}
	if opt.ContainDryRun {
		args = append(args, "--contain-dry-run")
	}
	if opt.Contain {
		args = append(args, "--contain")
	}
	args = append(args, opt.Extra...)
	args = append(args, h.Extra...)
	return strings.Join(args, " ")
}

// parseReports handles both a single JSON object and one-report-per-line, which
// is what --all-sites produces.
func parseReports(out string) ([]*model.Report, error) {
	var reports []*model.Report
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var lastErr error
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r model.Report
		if err := json.Unmarshal(line, &r); err != nil {
			lastErr = err
			continue
		}
		if r.Schema == "" {
			continue
		}
		reports = append(reports, &r)
	}
	if err := sc.Err(); err != nil {
		return reports, err
	}
	return reports, lastErr
}

// ---------------------------------------------------------------------------
// ssh / scp
// ---------------------------------------------------------------------------

func sshArgs(h Host) []string {
	args := []string{
		// BatchMode makes a missing key fail fast instead of hanging on a
		// password prompt, which matters when fanning out across an estate.
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=4",
		"-o", "LogLevel=ERROR",
	}
	if h.Port != 0 {
		args = append(args, "-p", strconv.Itoa(h.Port))
	}
	return append(args, h.SSHOpts...)
}

func sshRun(ctx context.Context, h Host, command string) (string, error) {
	args := append(sshArgs(h), h.Target(), command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s", msg)
	}
	return stdout.String(), nil
}

func scpTo(ctx context.Context, h Host, local, remote string) error {
	// scp spells the port flag -P, unlike ssh's -p.
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "LogLevel=ERROR",
		"-q",
	}
	if h.Port != 0 {
		args = append(args, "-P", strconv.Itoa(h.Port))
	}
	args = append(args, h.SSHOpts...)
	args = append(args, local, h.Target()+":"+remote)

	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// shellQuote makes a value safe inside the single remote command string.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' || r == '/' || r == '~' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func firstLine(a, b string) string {
	s := strings.TrimSpace(a)
	if s == "" {
		s = strings.TrimSpace(b)
	}
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func worstVerdict(reports []*model.Report) string {
	worst := "clean"
	for _, r := range reports {
		switch r.Verdict {
		case "dirty":
			return "dirty"
		case "partial":
			worst = "partial"
		}
	}
	return worst
}
