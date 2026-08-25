package console

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wordeye/internal/emit"
	"wordeye/internal/model"
	"wordeye/internal/store"
)

// SIEM forwarding.
//
// Now that every agent reports to the console, the console is the right place —
// and the only place — to forward from. The alternative, each agent shipping to
// the SIEM directly, means one egress path per client host, one firewall rule
// per client host, and your SIEM's credentials sitting on production servers
// you do not control. A single authenticated hop out of the console is strictly
// better on all three counts.
//
// Transport is RFC 5425: syslog over TLS, octet-counted framing. Plaintext
// transports are refused rather than warned about — an event stream describing
// which of your clients is compromised, and which shells were found where, is
// not something to put on the wire in the clear.
//
// The forwarder never blocks ingest. A slow or dead SIEM must not be able to
// stall agents reporting a live compromise, so the queue is bounded and drops
// the oldest events, counting what it dropped.

const (
	forwardQueueDepth   = 8192
	forwardDialTimeout  = 10 * time.Second
	forwardWriteTimeout = 10 * time.Second
	// RFC 5425 recommends no smaller than 2048 octets; be generous but bounded.
	forwardMaxMessage = 64 << 10
)

type ForwardConfig struct {
	// Target must be tls://host:port. Anything else is refused.
	Target string
	// CAFile pins the collector's certificate authority. Without it the system
	// trust store is used.
	CAFile string
	// ClientCert/ClientKey enable mutual TLS, which most SIEMs prefer for
	// authenticating a syslog source.
	ClientCert string
	ClientKey  string
	// ServerName overrides SNI/verification when the collector is addressed by
	// IP but presents a named certificate.
	ServerName string
	// Facility per RFC 5424. 16 = local0.
	Facility int
	// AppName appears in the syslog header.
	AppName string
}

type Forwarder struct {
	cfg  ForwardConfig
	log  *log.Logger
	host string

	tlsCfg *tls.Config
	addr   string

	queue chan []byte
	done  chan struct{}
	wg    sync.WaitGroup

	mu   sync.Mutex
	conn net.Conn

	sent    atomic.Int64
	dropped atomic.Int64
	errs    atomic.Int64
}

// NewForwarder validates configuration and prepares the TLS context. It does
// not dial: a SIEM that is down at startup must not prevent the console from
// running, since the console is what agents depend on.
func NewForwarder(cfg ForwardConfig, logger *log.Logger) (*Forwarder, error) {
	u, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("syslog target %q is not a URL: %w", cfg.Target, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "tls", "syslog-tls", "tcp+tls":
	case "udp", "tcp":
		return nil, fmt.Errorf(
			"refusing scheme %q: syslog forwarding carries which of your clients is compromised and what was found. Use tls://host:6514", u.Scheme)
	default:
		return nil, fmt.Errorf("unsupported syslog scheme %q (want tls://host:port)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("syslog target %q has no host:port", cfg.Target)
	}

	serverName := cfg.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}
	tc := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading syslog CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CAFile)
		}
		tc.RootCAs = pool
	}
	if (cfg.ClientCert == "") != (cfg.ClientKey == "") {
		return nil, fmt.Errorf("mutual TLS needs both --syslog-cert and --syslog-key")
	}
	if cfg.ClientCert != "" {
		pair, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading syslog client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}

	if cfg.Facility == 0 {
		cfg.Facility = 16 // local0
	}
	if cfg.AppName == "" {
		cfg.AppName = "wordeye"
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}

	return &Forwarder{
		cfg: cfg, log: logger, host: host,
		tlsCfg: tc, addr: u.Host,
		queue: make(chan []byte, forwardQueueDepth),
		done:  make(chan struct{}),
	}, nil
}

func (f *Forwarder) Start() {
	f.wg.Add(1)
	go f.run()
}

func (f *Forwarder) Close() error {
	close(f.done)
	f.wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}

// Stats reports throughput for operator visibility. Silent loss is worse than
// visible loss, so drops are counted and surfaced.
func (f *Forwarder) Stats() (sent, dropped, errs int64) {
	return f.sent.Load(), f.dropped.Load(), f.errs.Load()
}

// enqueue is non-blocking. When the queue is full the OLDEST event is dropped:
// during an incident the newest events are the ones an analyst needs, and a
// blocked enqueue would stall the ingest handler that is receiving them.
func (f *Forwarder) enqueue(msg []byte) {
	if f == nil {
		return
	}
	for {
		select {
		case f.queue <- msg:
			return
		default:
		}
		select {
		case <-f.queue:
			f.dropped.Add(1)
		default:
			return
		}
	}
}

func (f *Forwarder) run() {
	defer f.wg.Done()
	backoff := time.Second

	for {
		select {
		case <-f.done:
			return
		case msg := <-f.queue:
			if err := f.write(msg); err != nil {
				f.errs.Add(1)
				f.dropConn()
				// Put the message back at the front of the queue's effect by
				// retrying once after reconnecting; if that fails it is dropped
				// rather than retried forever.
				select {
				case <-time.After(backoff):
				case <-f.done:
					return
				}
				if err := f.write(msg); err != nil {
					f.dropped.Add(1)
					f.dropConn()
					if backoff < 30*time.Second {
						backoff *= 2
					}
					continue
				}
			}
			backoff = time.Second
			f.sent.Add(1)
		}
	}
}

func (f *Forwarder) dropConn() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn = nil
	}
}

func (f *Forwarder) write(msg []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn == nil {
		d := &net.Dialer{Timeout: forwardDialTimeout}
		c, err := tls.DialWithDialer(d, "tcp", f.addr, f.tlsCfg)
		if err != nil {
			return err
		}
		f.conn = c
	}
	_ = f.conn.SetWriteDeadline(time.Now().Add(forwardWriteTimeout))
	_, err := f.conn.Write(msg)
	return err
}

// ---------------------------------------------------------------------------
// message construction
// ---------------------------------------------------------------------------

// frame applies RFC 5425 octet counting: "<length> <message>". Without it a
// collector cannot tell where one message ends and the next begins on a stream
// transport, and JSON payloads containing newlines would be split.
func frame(msg string) []byte {
	return []byte(fmt.Sprintf("%d %s", len(msg), msg))
}

// syslog5424 builds the header and appends the JSON payload as the message.
func (f *Forwarder) syslog5424(severity int, msgID string, payload []byte) []byte {
	pri := f.cfg.Facility*8 + severity
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if len(payload) > forwardMaxMessage {
		payload = payload[:forwardMaxMessage]
	}
	msg := fmt.Sprintf("<%d>1 %s %s %s %d %s - %s",
		pri, ts, f.host, f.cfg.AppName, os.Getpid(), msgID, payload)
	return frame(msg)
}

func severityForFinding(sev string) int {
	switch sev {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	}
	return 6 // informational
}

// ForwardFinding ships one detection.
func (f *Forwarder) ForwardFinding(agent *store.Agent, in store.FindingInput) {
	if f == nil {
		return
	}
	// Reuse the agent-side ECS mapping so an event forwarded by the console is
	// shaped identically to one an agent emitted directly. A SIEM should not
	// need two parsers for the same detection.
	ev := emit.ToECS(toModelFinding(in), emit.Context{
		Host:    agent.Hostname,
		Site:    agent.Site,
		Webroot: agent.Webroot,
		Label:   agent.Label,
		Version: agent.Version,
	})
	ev.WordEye["agent_id"] = agent.ID
	ev.WordEye["forwarded_by"] = "console"

	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f.enqueue(f.syslog5424(severityForFinding(in.Severity), "detection", b))
}

// ForwardAudit ships an operator action. These matter to a SOC as much as the
// detections do: who approved containment across a client estate, and when.
func (f *Forwarder) ForwardAudit(e store.AuditEntry) {
	if f == nil {
		return
	}
	payload := map[string]any{
		"@timestamp": e.At.Format(time.RFC3339Nano),
		"event": map[string]any{
			"kind": "event", "category": []string{"iam", "configuration"},
			"module": "wordeye", "dataset": "wordeye.audit",
			"action": e.Action, "outcome": e.Result,
		},
		"user":    map[string]any{"name": e.Actor},
		"source":  map[string]any{"ip": e.IP},
		"message": fmt.Sprintf("%s %s %s", e.Actor, e.Action, e.Target),
		"wordeye": map[string]any{"target": e.Target, "detail": e.Detail},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	sev := 6
	if e.Result != "ok" {
		sev = 4
	}
	// Destructive actions are elevated so they stand out in a SIEM.
	if strings.HasPrefix(e.Action, "command.") || strings.Contains(e.Action, "contain") ||
		e.Action == "user.reset_mfa" {
		sev = 3
	}
	f.enqueue(f.syslog5424(sev, "audit", b))
}

// ForwardScan ships a run summary, so a SIEM can alert on an agent that has
// stopped reporting or a scan that could not complete.
func (f *Forwarder) ForwardScan(agent *store.Agent, sum store.ReportSummary) {
	if f == nil {
		return
	}
	payload := map[string]any{
		"@timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"event": map[string]any{
			"kind": "event", "category": []string{"process"}, "type": []string{"end"},
			"module": "wordeye", "dataset": "wordeye.scan", "outcome": sum.Verdict,
		},
		"host":    map[string]any{"hostname": agent.Hostname, "name": agent.Label},
		"message": fmt.Sprintf("scan %s on %s: %d critical, %d high", sum.Verdict, agent.Hostname, sum.NCritical, sum.NHigh),
		"wordeye": map[string]any{
			"agent_id": agent.ID, "site": agent.Site, "mode": sum.Mode,
			"verdict": sum.Verdict, "duration_ms": sum.DurationMS,
			"critical": sum.NCritical, "high": sum.NHigh, "medium": sum.NMedium,
			"files_seen": sum.FilesSeen, "errors": sum.NErrors,
			"forwarded_by": "console",
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	sev := 6
	if sum.Verdict == "dirty" {
		sev = 3
	} else if sum.Verdict == "partial" {
		sev = 4
	}
	f.enqueue(f.syslog5424(sev, "scan", b))
}

// toModelFinding adapts the stored shape to the one the ECS mapper expects.
func toModelFinding(in store.FindingInput) model.Finding {
	return model.Finding{
		RuleID:      in.RuleID,
		Class:       in.Class,
		Severity:    model.Severity(in.Severity),
		Confidence:  model.Confidence(in.Confidence),
		Title:       in.Title,
		Detail:      in.Detail,
		Path:        in.Path,
		SHA256:      in.SHA256,
		Size:        in.Size,
		Line:        in.Line,
		Evidence:    in.Evidence,
		Remediation: in.Remediation,
		Actionable:  in.Actionable,
		ContainPID:  in.ContainPID,
		Meta:        in.Meta,
	}
}
