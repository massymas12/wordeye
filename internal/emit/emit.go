// Package emit turns detections into output. A one-shot JSON report is one
// sink among several: once findings are a stream of events rather than a
// document, a SIEM can consume them directly and the monitor daemon becomes
// useful without any further plumbing.
package emit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"wordeye/internal/model"
)

// Emitter receives findings as they occur and the report when a run completes.
// Implementations must be safe for concurrent use: the scan worker pool emits
// from several goroutines at once.
type Emitter interface {
	Finding(model.Finding, Context)
	Report(*model.Report) error
	Close() error
}

// Context carries the run-level fields that every event needs stamped onto it.
type Context struct {
	Host    string
	Site    string
	Webroot string
	Label   string
	Version string
}

func ContextFor(r *model.Report) Context {
	return Context{
		Host: r.Host, Site: r.Site, Webroot: r.Webroot,
		Label: r.Label, Version: r.AgentVersion,
	}
}

// ---------------------------------------------------------------------------
// ECS event shape
// ---------------------------------------------------------------------------

// severityNumber maps to the ECS 0-100 scale, which Wazuh and Elastic both
// understand for alert ranking.
func severityNumber(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 99
	case model.SevHigh:
		return 73
	case model.SevMedium:
		return 47
	case model.SevLow:
		return 21
	}
	return 1
}

// syslogSeverity maps to RFC5424 numeric severities.
func syslogSeverity(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 2 // crit
	case model.SevHigh:
		return 3 // err
	case model.SevMedium:
		return 4 // warning
	case model.SevLow:
		return 5 // notice
	}
	return 6 // info
}

// ECSEvent is the wire shape written by the NDJSON, syslog and webhook sinks.
// Field names follow the Elastic Common Schema so that Wazuh's JSON decoder,
// and any Elastic-shaped pipeline, index it without custom mappings.
type ECSEvent struct {
	Timestamp string `json:"@timestamp"`
	Message   string `json:"message"`

	Event struct {
		Kind     string   `json:"kind"`
		Category []string `json:"category"`
		Type     []string `json:"type"`
		Module   string   `json:"module"`
		Dataset  string   `json:"dataset"`
		Provider string   `json:"provider"`
		Severity int      `json:"severity"`
		Action   string   `json:"action,omitempty"`
		Outcome  string   `json:"outcome,omitempty"`
	} `json:"event"`

	Rule struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Ruleset     string `json:"ruleset,omitempty"`
	} `json:"rule"`

	Host struct {
		Hostname string `json:"hostname"`
		Name     string `json:"name,omitempty"`
	} `json:"host"`

	File *ecsFile `json:"file,omitempty"`

	Process *ecsProcess `json:"process,omitempty"`

	Agent struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Version string `json:"version"`
	} `json:"agent"`

	// Vendor namespace for everything ECS has no home for. Keeping it under a
	// single key avoids polluting the top level and keeps index mappings small.
	WordEye map[string]any `json:"wordeye"`
}

type ecsFile struct {
	Path  string         `json:"path"`
	Name  string         `json:"name,omitempty"`
	Size  int64          `json:"size,omitempty"`
	Mtime string         `json:"mtime,omitempty"`
	Ctime string         `json:"ctime,omitempty"`
	Mode  string         `json:"mode,omitempty"`
	Hash  map[string]any `json:"hash,omitempty"`
}

type ecsProcess struct {
	PID         int    `json:"pid,omitempty"`
	Name        string `json:"name,omitempty"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	Parent      *struct {
		PID int `json:"pid,omitempty"`
	} `json:"parent,omitempty"`
}

// ToECS converts a finding into an ECS event.
func ToECS(f model.Finding, c Context) ECSEvent {
	var e ECSEvent
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	e.Message = f.Title
	if f.Detail != "" {
		e.Message = f.Title + " — " + f.Detail
	}

	e.Event.Kind = "alert"
	e.Event.Category = []string{"intrusion_detection", "malware"}
	e.Event.Type = []string{"info"}
	e.Event.Module = "wordeye"
	e.Event.Dataset = "wordeye.finding"
	e.Event.Provider = "wordeye"
	e.Event.Severity = severityNumber(f.Severity)
	e.Event.Action = f.RuleID

	e.Rule.ID = f.RuleID
	e.Rule.Name = f.Title
	e.Rule.Description = f.Detail
	if f.Meta != nil {
		if p, ok := f.Meta["pack"].(string); ok {
			e.Rule.Ruleset = p
		}
	}

	e.Host.Hostname = c.Host
	e.Host.Name = c.Label

	e.Agent.Name = "wordeye-agent"
	e.Agent.Type = "wordeye"
	e.Agent.Version = c.Version

	if f.Path != "" {
		file := &ecsFile{Path: f.Path, Size: f.Size, Mode: f.Mode}
		if i := strings.LastIndexAny(f.Path, "/\\"); i >= 0 {
			file.Name = f.Path[i+1:]
		} else {
			file.Name = f.Path
		}
		if f.SHA256 != "" {
			file.Hash = map[string]any{"sha256": f.SHA256}
		}
		if f.ModTime != nil {
			file.Mtime = f.ModTime.UTC().Format(time.RFC3339)
		}
		if f.CTime != nil {
			file.Ctime = f.CTime.UTC().Format(time.RFC3339)
		}
		e.File = file
	}

	if f.ContainPID > 0 {
		p := &ecsProcess{PID: f.ContainPID}
		if f.Meta != nil {
			p.Name, _ = f.Meta["comm"].(string)
			p.Executable, _ = f.Meta["exe"].(string)
			p.CommandLine, _ = f.Meta["cmdline"].(string)
		}
		e.Process = p
	}

	e.WordEye = map[string]any{
		"class":      f.Class,
		"severity":   string(f.Severity),
		"confidence": string(f.Confidence),
		"actionable": f.Actionable,
		"site":       c.Site,
		"webroot":    c.Webroot,
	}
	if f.Remediation != "" {
		e.WordEye["remediation"] = f.Remediation
	}
	if f.Evidence != "" {
		e.WordEye["evidence"] = f.Evidence
	}
	if f.Line > 0 {
		e.WordEye["line"] = f.Line
	}
	for k, v := range f.Meta {
		if k == "comm" || k == "exe" || k == "cmdline" || k == "pack" {
			continue
		}
		e.WordEye[k] = v
	}
	return e
}

// ---------------------------------------------------------------------------
// JSON report sink
// ---------------------------------------------------------------------------

// JSONReport writes the complete report once, at the end of a run. This is the
// format the controller consumes.
type JSONReport struct {
	W      io.Writer
	Pretty bool
	closer io.Closer
}

func NewJSONReport(w io.Writer, pretty bool) *JSONReport { return &JSONReport{W: w, Pretty: pretty} }

// NewJSONReportFile writes to a path, creating parent directories.
func NewJSONReportFile(path string, pretty bool) (*JSONReport, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &JSONReport{W: f, Pretty: pretty, closer: f}, nil
}

func (j *JSONReport) Finding(model.Finding, Context) {}

func (j *JSONReport) Report(r *model.Report) error {
	enc := json.NewEncoder(j.W)
	if j.Pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(r)
}

func (j *JSONReport) Close() error {
	if j.closer != nil {
		return j.closer.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// NDJSON sink (Wazuh logcollector, Filebeat, Vector, …)
// ---------------------------------------------------------------------------

// NDJSON appends one ECS event per line. This is the format to point Wazuh's
// logcollector at: it tails the file and ships each line as a JSON event, so
// detections reach the SIEM as they happen rather than at the end of a scan.
type NDJSON struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

func NewNDJSON(w io.Writer) *NDJSON { return &NDJSON{w: w} }

// NewNDJSONFile opens the target in append mode so the agent can be run
// repeatedly, or as a daemon, without truncating history.
func NewNDJSONFile(path string) (*NDJSON, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &NDJSON{w: f, closer: f}, nil
}

func (n *NDJSON) Finding(f model.Finding, c Context) {
	b, err := json.Marshal(ToECS(f, c))
	if err != nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, _ = n.w.Write(append(b, '\n'))
}

// Report emits a run-summary event so a SIEM can alert on scans that stopped
// reporting — a silent agent is itself a signal.
func (n *NDJSON) Report(r *model.Report) error {
	var e ECSEvent
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	e.Event.Kind = "event"
	e.Event.Category = []string{"process"}
	e.Event.Type = []string{"end"}
	e.Event.Module = "wordeye"
	e.Event.Dataset = "wordeye.scan"
	e.Event.Provider = "wordeye"
	e.Event.Outcome = r.Verdict
	e.Event.Severity = 1
	e.Rule.ID = "wordeye.scan_complete"
	e.Rule.Name = "WordEye scan complete"
	e.Host.Hostname = r.Host
	e.Host.Name = r.Label
	e.Agent.Name = "wordeye-agent"
	e.Agent.Type = "wordeye"
	e.Agent.Version = r.AgentVersion
	counts := r.Counts()
	e.Message = fmt.Sprintf("scan %s: %d findings (%d critical, %d high) in %dms",
		r.Verdict, len(r.Findings), counts[model.SevCritical], counts[model.SevHigh], r.DurationMS)
	e.WordEye = map[string]any{
		"verdict": r.Verdict, "site": r.Site, "webroot": r.Webroot,
		"duration_ms": r.DurationMS, "mode": r.Mode,
		"findings_total": len(r.Findings),
		"critical":       counts[model.SevCritical],
		"high":           counts[model.SevHigh],
		"medium":         counts[model.SevMedium],
		"files_seen":     r.Stats.FilesSeen,
		"files_read":     r.Stats.FilesRead,
		"errors":         len(r.Errors),
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, err = n.w.Write(append(b, '\n'))
	return err
}

func (n *NDJSON) Close() error {
	if n.closer != nil {
		return n.closer.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// syslog sink
// ---------------------------------------------------------------------------

// Syslog ships RFC5424 messages with a JSON payload over UDP or TCP. Useful
// where the SIEM already collects syslog and adding a file tail is awkward.
type Syslog struct {
	mu       sync.Mutex
	conn     net.Conn
	network  string
	addr     string
	facility int
	hostname string
}

// NewSyslog dials the collector. network is "udp" or "tcp".
func NewSyslog(network, addr string) (*Syslog, error) {
	c, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	h, _ := os.Hostname()
	return &Syslog{conn: c, network: network, addr: addr, facility: 16, hostname: h}, nil
}

func (s *Syslog) write(sev int, payload []byte) {
	pri := s.facility*8 + sev
	msg := fmt.Sprintf("<%d>1 %s %s wordeye-agent %d - - %s\n",
		pri, time.Now().UTC().Format(time.RFC3339), s.hostname, os.Getpid(), payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.conn.Write([]byte(msg))
}

func (s *Syslog) Finding(f model.Finding, c Context) {
	b, err := json.Marshal(ToECS(f, c))
	if err != nil {
		return
	}
	s.write(syslogSeverity(f.Severity), b)
}

func (s *Syslog) Report(r *model.Report) error {
	b, _ := json.Marshal(map[string]any{
		"event": "scan_complete", "verdict": r.Verdict, "host": r.Host,
		"site": r.Site, "findings": len(r.Findings), "duration_ms": r.DurationMS,
	})
	s.write(6, b)
	return nil
}

func (s *Syslog) Close() error { return s.conn.Close() }

// ---------------------------------------------------------------------------
// webhook sink
// ---------------------------------------------------------------------------

// Webhook batches events and POSTs them as NDJSON. Batching keeps a noisy scan
// from turning into thousands of HTTP requests against the collector.
type Webhook struct {
	URL     string
	Headers map[string]string

	mu    sync.Mutex
	buf   []ECSEvent
	limit int
	cl    *http.Client
}

func NewWebhook(url string, headers map[string]string) *Webhook {
	return &Webhook{
		URL: url, Headers: headers, limit: 50,
		cl: &http.Client{Timeout: 15 * time.Second},
	}
}

func (w *Webhook) Finding(f model.Finding, c Context) {
	w.mu.Lock()
	w.buf = append(w.buf, ToECS(f, c))
	full := len(w.buf) >= w.limit
	w.mu.Unlock()
	if full {
		_ = w.flush()
	}
}

func (w *Webhook) Report(*model.Report) error { return w.flush() }

func (w *Webhook) flush() error {
	w.mu.Lock()
	batch := w.buf
	w.buf = nil
	w.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range batch {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}
	resp, err := w.cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func (w *Webhook) Close() error { return w.flush() }

// ---------------------------------------------------------------------------
// fan-out
// ---------------------------------------------------------------------------

// Multi fans every event out to several sinks. A failing sink never blocks the
// others: shipping to a SIEM is best-effort, and losing the collector must not
// cost you the local report.
type Multi struct {
	Sinks []Emitter
	Errs  []error
	mu    sync.Mutex
}

func NewMulti(sinks ...Emitter) *Multi { return &Multi{Sinks: sinks} }

func (m *Multi) Finding(f model.Finding, c Context) {
	for _, s := range m.Sinks {
		s.Finding(f, c)
	}
}

func (m *Multi) Report(r *model.Report) error {
	var first error
	for _, s := range m.Sinks {
		if err := s.Report(r); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (m *Multi) Close() error {
	var first error
	for _, s := range m.Sinks {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
