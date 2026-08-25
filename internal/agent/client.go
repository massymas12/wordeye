package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wordeye/internal/govern"
	"wordeye/internal/model"
)

// The managed-agent client: enrollment, heartbeat, and command execution.
//
// All traffic is agent-initiated. The console never connects inbound, so a
// client's production server needs no open port, no firewall exception, and no
// inbound NAT rule — it only has to be able to make outbound HTTPS.

// ClientState is persisted after enrollment. It holds a credential, so it is
// written 0600 and never logged.
type ClientState struct {
	Server     string `json:"server"`
	AgentID    string `json:"agent_id"`
	Credential string `json:"credential"`
	// AllowRemoteContain is recorded from the LOCAL --allow-remote-contain flag
	// at enrollment time. It is deliberately not refreshed from the server: the
	// whole point of the second key is that the console cannot grant itself
	// permission to destroy this host.
	AllowRemoteContain bool      `json:"allow_remote_contain"`
	EnrolledAt         time.Time `json:"enrolled_at"`
}

type ClientConfig struct {
	Server    string
	Token     string
	StateFile string
	Label     string

	// AllowRemoteContain opts this host in to accepting destructive orders.
	AllowRemoteContain bool

	// SigningKey is the PUBLIC half of the estate release key, stamped in at
	// install time. It is the only thing that decides whether a binary served
	// by the console is allowed to replace this one, which is why the console
	// never holds its private counterpart. Empty means this agent cannot verify
	// a release and will refuse to upgrade at all.
	SigningKey string

	// Base is the scan configuration commands are executed with.
	Base Config

	HeartbeatInterval time.Duration
	// Monitor runs inotify detection alongside the heartbeat loop.
	Monitor      bool
	RescanPeriod time.Duration

	// CAPEM pins the console's certificate authority in PEM form, so a
	// self-signed console is VERIFIED rather than trusted blindly. Preferred
	// over Insecure in every case.
	CAPEM string

	// Insecure skips TLS verification. For testing against a self-signed
	// console only; it defeats the protection on the credential in transit.
	Insecure bool
}

type Client struct {
	cfg   ClientConfig
	state ClientState
	http  *http.Client

	mu      sync.Mutex
	pending []model.Finding

	// Flush telemetry. A resident agent that detects but cannot deliver looks
	// identical to one that detects nothing, which is how a field agent ran for
	// half an hour reporting zero while the pipeline worked.
	lastFlush    atomic.Int64
	lastFlushErr atomic.Value

	// shutdown ends the run loop from inside. Used by an authorised uninstall,
	// which has to stop the agent without the process looking as though it was
	// killed.
	shutdown     chan struct{}
	shutdownOnce sync.Once
}

// FlushStats reports how many findings were last handed to the console and the
// error, if any, from that attempt.
func (c *Client) FlushStats() (int64, string) {
	e, _ := c.lastFlushErr.Load().(string)
	return c.lastFlush.Load(), e
}

// DefaultStateFile is where enrollment credentials live.
func DefaultStateFile(home string) string {
	return filepath.Join(home, ".wordeye", "agent.json")
}

// newHTTPClient builds the transport used for every console call.
//
// caPEM pins a specific certificate authority. This exists so that a
// self-signed console can be verified rather than trusted blindly: without it,
// the only way to talk to one is --insecure, which turns off verification
// entirely and exposes the agent credential to anyone on the path. A stamped
// installer carries the console's certificate for exactly this reason.
func newHTTPClient(insecure bool, caPEM string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	if caPEM != "" {
		// Pinning must fail CLOSED.
		//
		// This previously assigned RootCAs only when the PEM parsed, so a DER
		// file passed where PEM was expected — or a truncated certificate
		// stamped into an installer — left RootCAs nil and the client verified
		// against every publicly-trusted CA on earth. That is precisely the
		// blind trust the pin exists to prevent: anyone able to obtain a
		// certificate for the console's name could terminate the agent's TLS
		// and harvest its bearer credential.
		//
		// An unparseable pin therefore yields an EMPTY pool, which trusts
		// nothing. The agent fails to connect with an unknown-authority error
		// instead of connecting to the wrong thing, which is the outcome an
		// operator who supplied a CA actually asked for.
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			pool = x509.NewCertPool() // trusts nothing; every handshake fails
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	if insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}
}

// Enroll exchanges a console-minted token for a durable agent credential.
//
// The token is single- or limited-use and is consumed server-side, so it cannot
// be replayed from this host later to impersonate a different agent.
func Enroll(ctx context.Context, cfg ClientConfig) (*ClientState, error) {
	if cfg.Server == "" || cfg.Token == "" {
		return nil, fmt.Errorf("both --server and --token are required to enroll")
	}
	host, _ := os.Hostname()
	webroot := cfg.Base.Webroot
	if webroot == "" {
		webroot = FindWebroot(cfg.Base.Home)
	}

	body, _ := json.Marshal(map[string]any{
		"token":          cfg.Token,
		"hostname":       host,
		"label":          cfg.Label,
		"site":           siteName(webroot),
		"webroot":        webroot,
		"version":        Version,
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"opt_in_contain": cfg.AllowRemoteContain,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cfg.Server, "/")+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newHTTPClient(cfg.Insecure, cfg.CAPEM).Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting console: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, fmt.Errorf("enrollment refused: %s", e.Error)
	}

	var out struct {
		AgentID            string `json:"agent_id"`
		Credential         string `json:"credential"`
		AllowRemoteContain bool   `json:"allow_remote_contain"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unexpected enrollment response: %w", err)
	}

	st := &ClientState{
		Server:     strings.TrimRight(cfg.Server, "/"),
		AgentID:    out.AgentID,
		Credential: out.Credential,
		// Record OUR opt-in, not the server's opinion of it.
		AllowRemoteContain: cfg.AllowRemoteContain,
		EnrolledAt:         time.Now().UTC(),
	}
	if err := SaveState(cfg.StateFile, st); err != nil {
		return nil, err
	}
	return st, nil
}

func SaveState(path string, st *ClientState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	// 0600: this file contains a credential that authenticates to the console.
	return os.WriteFile(path, b, 0o600)
}

func LoadState(path string) (*ClientState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st ClientState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	if st.AgentID == "" || st.Credential == "" {
		return nil, fmt.Errorf("%s does not contain an enrollment; run `wordeye-agent enroll` first", path)
	}
	return &st, nil
}

func NewClient(cfg ClientConfig, st *ClientState) *Client {
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 60 * time.Second
	}
	return &Client{cfg: cfg, state: *st, http: newHTTPClient(cfg.Insecure, cfg.CAPEM),
		shutdown: make(chan struct{})}
}

func (c *Client) authHeader() string {
	return "Bearer " + c.state.AgentID + "." + c.state.Credential
}

func (c *Client) post(ctx context.Context, path string, payload any, out any) error {
	var body io.Reader
	switch v := payload.(type) {
	case []byte:
		body = bytes.NewReader(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.state.Server+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.authHeader())

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("%s: %s", path, e.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Run is the resident loop: heartbeat, collect commands, execute them, and (if
// enabled) stream real-time detections.
func (c *Client) Run(ctx context.Context, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logf("connected to %s as %s", c.state.Server, c.state.AgentID)
	if c.state.AllowRemoteContain {
		logf("remote containment: PERMITTED by local opt-in")
	} else {
		logf("remote containment: refused locally (enroll with --allow-remote-contain to permit)")
	}

	// Tamper reporting.
	//
	// Nothing running as an unprivileged user can stop an intruder killing it.
	// What it can do is refuse to die quietly: report the signal AND its sender
	// before exiting, and leave evidence behind when the kill is one that cannot
	// be caught.
	started := time.Now().UTC()
	statePath := c.cfg.StateFile
	if statePath != "" {
		// A previous instance that never recorded a clean exit is the trace an
		// uncatchable kill leaves. Report it before doing anything else.
		if f := UncleanShutdownFinding(statePath); f != nil {
			logf("previous instance stopped without a clean exit at %s", f.Meta["last_alive"])
			c.queueFinding(*f)
		}
		_ = MarkAlive(statePath, started)
		defer func() { _ = MarkCleanExit(statePath, started) }()
	}
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go c.watchForTermination(ctx, stopWatch, logf)

	if c.cfg.Monitor {
		go c.runMonitor(ctx, logf)
	}

	t := time.NewTicker(c.cfg.HeartbeatInterval)
	defer t.Stop()

	// Beat immediately so the console shows the agent as online at once.
	c.beat(ctx, logf)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.shutdown:
			// An authorised uninstall. Returning nil matters: the process exits
			// zero, a supervisor sees a deliberate stop, and the clean-exit
			// marker already written means the next start reports nothing.
			return nil
		case <-t.C:
			// last_alive bounds how long ago an unreported death happened.
			if statePath != "" {
				_ = MarkAlive(statePath, started)
			}
			c.beat(ctx, logf)
		}
	}
}

func (c *Client) beat(ctx context.Context, logf func(string, ...any)) {
	c.flushEvents(ctx)

	load, _ := govern.LoadAvg1()
	var resp struct {
		Command *struct {
			ID     string          `json:"id"`
			Kind   string          `json:"kind"`
			Params json.RawMessage `json:"params"`
		} `json:"command"`
	}
	err := c.post(ctx, "/v1/heartbeat", map[string]any{
		"load1":   load,
		"monitor": c.cfg.Monitor,
		"version": Version,
	}, &resp)
	if err != nil {
		// Transient failures are expected; the console will mark us stale and
		// then offline, which is itself the signal.
		logf("heartbeat failed: %v", err)
		return
	}
	if resp.Command == nil {
		return
	}
	cmd := *resp.Command
	logf("received command %s (%s)", cmd.ID, cmd.Kind)
	go c.execute(ctx, cmd.ID, cmd.Kind, logf)
}

// execute runs one command and reports the outcome.
func (c *Client) execute(ctx context.Context, id, kind string, logf func(string, ...any)) {
	_ = c.post(ctx, "/v1/command/result", map[string]any{"id": id, "status": "running"}, nil)

	report, err := c.runCommand(ctx, kind, logf)
	if IsUninstallRequest(err) {
		c.uninstall(ctx, id, logf)
		return
	}
	if IsUpgradeRequest(err) {
		c.upgrade(ctx, id, logf)
		return
	}
	if err != nil {
		logf("command %s failed: %v", id, err)
		_ = c.post(ctx, "/v1/command/result", map[string]any{
			"id": id, "status": "failed", "error": err.Error(),
		}, nil)
		return
	}

	summary := fmt.Sprintf("verdict=%s findings=%d duration=%dms",
		report.Verdict, len(report.Findings), report.DurationMS)
	if len(report.Containment) > 0 {
		done := 0
		for _, a := range report.Containment {
			if a.Executed && a.Success {
				done++
			}
		}
		summary += fmt.Sprintf(" containment=%d/%d actions succeeded", done, len(report.Containment))
	}

	if raw, err := json.Marshal(report); err == nil {
		if err := c.post(ctx, "/v1/report", raw, nil); err != nil {
			logf("uploading report: %v", err)
		}
	}
	_ = c.post(ctx, "/v1/command/result", map[string]any{
		"id": id, "status": "done", "result": summary,
	}, nil)
	logf("command %s complete: %s", id, summary)
}

func (c *Client) runCommand(ctx context.Context, kind string, logf func(string, ...any)) (*model.Report, error) {
	// The command's `params` are deliberately NOT consulted. Everything that
	// determines what gets scanned or quarantined — webroot, rule packs,
	// profile, evidence directory — comes from this host's own configuration.
	//
	// That is a security property, not an oversight: if the console could
	// supply a webroot, a compromised console could aim the agent's quarantine
	// at an arbitrary path on a customer's server. Only the command KIND
	// crosses the trust boundary.
	cfg := c.cfg.Base

	switch kind {
	case "scan":
		cfg.Mode = "scan"
	case "baseline":
		cfg.Mode = "baseline"
	case "verify":
		cfg.Mode = "verify"
	case "contain_dryrun":
		cfg.Mode = "scan"
		cfg.Contain = true
		cfg.ContainDryRun = true
	case "contain":
		// The second key. The console already checked its own grant, but this
		// host decides independently whether it will ever accept destruction.
		// A compromised console cannot flip this: it lives in local state,
		// written at enrollment from an explicit operator flag.
		if !c.state.AllowRemoteContain {
			return nil, fmt.Errorf("refused: this host was not enrolled with --allow-remote-contain")
		}
		cfg.Mode = "scan"
		cfg.Contain = true
		cfg.ContainDryRun = false
	case "uninstall":
		// Handled entirely outside the scanning path: there is nothing to scan.
		return nil, errUninstallRequested
	case "upgrade":
		return nil, errUpgradeRequested
	default:
		return nil, fmt.Errorf("unsupported command %q", kind)
	}

	a, err := New(cfg)
	if err != nil {
		return nil, err
	}
	defer a.Close()
	// Ask the estate what it can vouch for before scanning. Premium and bespoke
	// trees have no publisher manifest, so without this they reach the pattern
	// engines with no authority behind them and report the same benign files on
	// every host in the estate.
	c.withEstateAttestations(ctx, a)
	return a.Run(ctx)
}

// ScanAndReport performs one scan and pushes the result, then returns.
//
// This is what a generated installer does on first run: an administrator who
// executes it should see their host appear in the console with real findings,
// not merely register as present and stay empty until something schedules work.
func (c *Client) ScanAndReport(ctx context.Context) error {
	rep, err := c.runCommand(ctx, "scan", func(string, ...any) {})
	if err != nil {
		return err
	}
	return c.PushReport(ctx, rep)
}

// ---------------------------------------------------------------------------
// real-time detections
// ---------------------------------------------------------------------------

func (c *Client) runMonitor(ctx context.Context, logf func(string, ...any)) {
	cfg := c.cfg.Base
	cfg.Mode = "monitor"
	a, err := New(cfg)
	if err != nil {
		logf("monitor: %v", err)
		return
	}
	defer a.Close()
	c.withEstateAttestations(ctx, a)

	// Detections are queued and shipped on the next heartbeat rather than one
	// request per finding: a noisy event burst must not turn into a request
	// storm against the console.
	a.SetSink(func(f model.Finding) {
		c.mu.Lock()
		if len(c.pending) < maxPendingFindings {
			c.pending = append(c.pending, f)
		}
		c.mu.Unlock()
	})

	period := c.cfg.RescanPeriod
	if period <= 0 {
		period = 6 * time.Hour
	}

	// Report real-time coverage once the watches are up.
	//
	// Connect mode previously said NOTHING about monitoring: an operator saw
	// "connected" and had no way to tell whether the daemon was watching the
	// whole tree, a fraction of it, or nothing at all. A field agent ran for
	// half an hour in exactly that state.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		if s := a.MonitorWatchSummary(); s != "" {
			logf("monitor: %s", s)
		}
	}()

	if err := a.Monitor(ctx, period); err != nil && ctx.Err() == nil {
		logf("monitor stopped: %v", err)
	}
}

func (c *Client) flushEvents(ctx context.Context) {
	c.mu.Lock()
	batch := c.pending
	c.pending = nil
	c.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	// Read the acknowledgement. A 200 is not proof of storage: the console
	// reports how many findings it could not write, and counting those as
	// delivered is how a detection disappears with both ends believing it
	// landed.
	var ack struct {
		Accepted int `json:"accepted"`
		Failed   int `json:"failed"`
	}
	err := c.post(ctx, "/v1/events", map[string]any{"findings": batch}, &ack)
	if err == nil && ack.Failed > 0 {
		err = fmt.Errorf("console stored %d of %d findings", ack.Accepted, len(batch))
	}

	if err != nil {
		c.lastFlushErr.Store(err.Error())
		c.requeue(batch)
		return
	}

	// Telemetry is recorded only on success, and the previous error is cleared.
	//
	// Both directions used to be wrong: the count was stored BEFORE the POST,
	// so a failed attempt reported N findings delivered, and the error was
	// never cleared, so one transient blip made every later flush look broken
	// forever. That defeats the entire purpose of these fields, which exist
	// because an agent that detects but cannot deliver looks identical to one
	// that detects nothing.
	c.lastFlush.Store(int64(len(batch)))
	c.lastFlushErr.Store("")
}

// requeue puts an undelivered batch back, keeping the NEWEST detections.
//
// The truncation used to slice from the front, which keeps the oldest and
// discards whatever arrived during the outage — exactly backwards. During an
// incident the newest events are the ones an analyst needs, and an intruder
// actively writing shells while the console is unreachable is precisely when
// the queue overflows.
func (c *Client) requeue(batch []model.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pending = append(batch, c.pending...)
	if len(c.pending) > maxPendingFindings {
		drop := len(c.pending) - maxPendingFindings
		// Copy into a fresh slice: re-slicing keeps the old backing array
		// alive, so the dropped findings would never actually be released.
		kept := make([]model.Finding, maxPendingFindings)
		copy(kept, c.pending[drop:])
		c.pending = kept
	}
}

// PushReport uploads a one-shot report from an enrolled agent, so a manual
// `wordeye-agent scan` on an enrolled host still lands in the console.
func (c *Client) PushReport(ctx context.Context, rep *model.Report) error {
	raw, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	return c.post(ctx, "/v1/report", raw, nil)
}

// fetchVendorPack retrieves the estate's attestations from the console.
//
// This is the half of cross-site correlation that was missing. Premium and
// bespoke code — Divi, Gravity Forms, a customer's own theme — publishes no
// checksum manifest, so provenance has no authority to compare it against and
// every dangerous-looking primitive inside it reaches the pattern engines
// unexonerated. One agent cannot know whether a file is the publisher's, but
// the console can see the whole estate, and a file byte-identical at the same
// path across many independent sites is vendor code.
//
// A failure here is not fatal. Attestation is an improvement on having no
// authority at all, never a prerequisite for scanning: an agent that cannot
// reach the console must still scan, and simply reports more than it needs to.
func (c *Client) fetchVendorPack(ctx context.Context) *VendorPack {
	var resp struct {
		Name        string        `json:"name"`
		GeneratedAt string        `json:"generated_at"`
		Source      string        `json:"source"`
		MinSites    int           `json:"min_sites"`
		Entries     []VendorEntry `json:"entries"`
	}
	if err := c.getJSON(ctx, "/v1/vendor-pack", &resp); err != nil {
		return nil
	}
	if len(resp.Entries) == 0 {
		return nil
	}
	return VendorPackFrom(resp.Name, resp.Source, time.Now(), resp.Entries)
}

// withEstateAttestations merges the console's pack into a scan configuration.
//
// Locally configured packs still win: an operator who shipped a signed pack to
// a host meant it, and the estate's opinion must not silently displace it.
func (c *Client) withEstateAttestations(ctx context.Context, a *Agent) {
	pack := c.fetchVendorPack(ctx)
	if pack == nil {
		return
	}
	a.MergeVendorPack(pack)
}

// getJSON performs an authenticated GET and decodes the response.
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.state.Server+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Bounded: an estate pack is a list of digests, not a payload channel. A
	// console that has been persuaded to return something enormous must not be
	// able to exhaust an agent's memory on a customer's production host.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// queueFinding pushes a finding onto the pending queue so it ships with the
// next heartbeat.
func (c *Client) queueFinding(f model.Finding) {
	c.mu.Lock()
	if len(c.pending) < maxPendingFindings {
		c.pending = append(c.pending, f)
	}
	c.mu.Unlock()
}

// watchForTermination reports a stop signal, and who sent it, before exiting.
//
// The sender is the valuable part. "SIGTERM from pid 1 (systemd)" is a deploy;
// "SIGTERM from pid 4821, uid 33, /usr/sbin/php-fpm" is code inside the website
// silencing the thing watching it — which means execution has already happened,
// and is one of the most informative events this agent can send.
//
// Delivery is best-effort and deliberately impatient: the process is about to
// end, and a long timeout would simply mean the report never leaves.
func (c *Client) watchForTermination(ctx context.Context, stop <-chan struct{}, logf func(string, ...any)) {
	rep, err := WatchTermination(stop)
	if err != nil || rep == nil {
		return
	}
	sev, conf := model.SevMedium, model.ConfConfirmed
	if rep.Suspicious {
		sev = model.SevCritical
	}
	f := model.Finding{
		RuleID:     "agent.terminated",
		Class:      "OSP",
		Severity:   sev,
		Confidence: conf,
		Title:      "The agent was signalled to stop (" + rep.Signal + ")",
		Detail: fmt.Sprintf("The agent received %s and is exiting. %s. The kernel does not disclose a "+
			"signal sender to this process, so any attribution here is inference rather than proof.",
			rep.Signal, rep.Reason),
		Remediation: "If this stop was not planned, treat the host as blinded from this moment: anything " +
			"written afterwards was not evaluated in real time. Run a full scan when the agent returns.",
		Meta: map[string]any{
			"signal": rep.Signal, "signal_num": rep.SignalNum,
			"suspect": rep.Suspect, "suspect_pid": rep.SuspectPID,
			"suspicious": rep.Suspicious, "attribution": "best-effort",
		},
	}
	logf("stopping: %s (%s)", rep.Signal, rep.Reason)

	// Ship it now rather than waiting for a heartbeat that will never come.
	sendCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.post(sendCtx, "/v1/events", map[string]any{"findings": []model.Finding{f}}, nil); err != nil {
		// Queue it anyway: if this is a restart rather than a kill, the next
		// instance is not the one that saw the signal, but a supervised agent
		// may still get the chance to flush.
		c.queueFinding(f)
	}
}

// uninstall performs an authorised removal and stops the agent.
//
// Order matters here. The console is told BEFORE anything is deleted, because
// once the credential is gone this host can no longer authenticate and would
// have no way to explain its own disappearance. An uninstall that fails to
// report is indistinguishable from a kill, which is the exact ambiguity this
// whole path exists to remove.
func (c *Client) uninstall(ctx context.Context, id string, logf func(string, ...any)) {
	logf("uninstall requested by the console")

	// Do the work FIRST, then report what actually happened.
	//
	// This used to POST an unconditional "done ... credential and state
	// removed" before attempting any deletion, so a permission failure — or a
	// StateFile that was never configured, which skipped the block entirely —
	// was recorded by the console as a clean decommission while a working
	// credential stayed on disk. The UninstallFinding branch that reports
	// failures was unreachable and its removed/failed metadata was always
	// empty.
	//
	// The credential is still valid at this point, which is what makes
	// reporting possible at all: the ordering is deletion, then a report sent
	// with the credential we are about to invalidate.
	res := UninstallResult{}
	status, summary := "done", "agent uninstalled; local credential and state removed"
	if c.cfg.StateFile == "" {
		status = "failed"
		summary = "no state file is configured, so there was no credential to remove"
	} else {
		// Mark a clean exit before removing state: if the process is killed
		// mid-uninstall, the next start must not report tampering for what was
		// an authorised removal.
		_ = MarkCleanExit(c.cfg.StateFile, time.Now())
		res = PerformUninstall(c.cfg.StateFile)
		if len(res.Failed) > 0 {
			status = "failed"
			summary = fmt.Sprintf("uninstall incomplete: %d item(s) could not be removed: %v",
				len(res.Failed), res.Failed)
		}
	}

	f := UninstallFinding(res, "console")
	_ = c.post(ctx, "/v1/events", map[string]any{"findings": []model.Finding{f}}, nil)
	_ = c.post(ctx, "/v1/command/result", map[string]any{
		"id": id, "status": status, "result": summary,
	}, nil)
	for _, p := range res.Removed {
		logf("removed %s", p)
	}
	for _, p := range res.Failed {
		logf("could not remove %s", p)
	}
	logf("uninstalled. Remove the binary and any service unit to finish decommissioning.")

	// Stop the agent. The supervisor, if any, will see a clean exit.
	c.requestShutdown()
}

// requestShutdown ends the run loop.
func (c *Client) requestShutdown() {
	c.shutdownOnce.Do(func() { close(c.shutdown) })
}

// maxPendingFindings bounds the undelivered-detection queue. A resident agent
// must not grow without limit while a console is unreachable, but it must keep
// enough to describe an active incident when the link returns.
const maxPendingFindings = 5000
