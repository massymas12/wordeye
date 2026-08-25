// Package console is the WordEye management server: a fleet database, an agent
// ingest API, and an operator web console.
//
// It runs TWO listeners with deliberately different exposure:
//
//   - Ingest. Must be reachable from client hosts, so in practice it faces the
//     internet. It speaks only to agents, authenticates every request with a
//     per-agent credential, validates schemas strictly, and bounds every body.
//     It exposes no operator functionality whatsoever.
//
//   - Console. The operator UI and API, including the button that can order
//     containment across an estate. Binds loopback by default and is never
//     meant to face the internet. Session auth with mandatory MFA.
//
// Splitting them means the internet-facing surface is a narrow, schema-checked
// API, and the dangerous surface is not routable from outside.
package console

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"wordeye/internal/store"
)

type Config struct {
	DBPath string

	// ConsoleAddr serves the operator UI/API. Loopback by default.
	ConsoleAddr string
	// IngestAddr serves agents. Empty disables agent ingest entirely, which is
	// the right setting for a purely sweep-driven deployment.
	IngestAddr string

	// TLS for the ingest listener. Strongly recommended: agent credentials
	// travel over it.
	TLSCert string
	TLSKey  string

	// ConsoleTLS applies the same certificate to the console listener.
	ConsoleTLS bool

	// Issuer name shown in authenticator apps.
	Issuer string

	// PublicURL is the address agents should report to, e.g.
	// https://console.example.com:8444. Generated installers are stamped with
	// it, so without it an installed agent would not know where to call home.
	PublicURL string

	// AgentBinaryDir holds release binaries named wordeye-agent-<os>-<arch>,
	// which the console stamps to produce estate installers. Empty disables
	// installer generation; the console never compiles anything.
	AgentBinaryDir string

	// InsecureAllowPlaintextIngest permits a non-loopback ingest listener
	// without TLS. Only sane when terminating TLS at a reverse proxy.
	InsecureAllowPlaintextIngest bool

	// Forward, when set, streams detections and audit events to a SIEM over
	// TLS. Empty disables forwarding entirely.
	Forward ForwardConfig

	Logger *log.Logger
	// ReleaseSigningPublicKey is stamped into every installer this console
	// generates, so agents can verify future upgrades.
	//
	// The PUBLIC half only. The private key belongs on a build machine and must
	// never reach this process: the whole point of signing releases is that
	// compromising the console — the internet-facing component — does not let
	// an attacker push code to the estate. A console that could sign would
	// simply be the single point of failure the design exists to remove.
	ReleaseSigningPublicKey string

	// TrustedProxies are CIDRs whose X-Forwarded-For header may be believed.
	//
	// Empty by default, which is the safe posture: without it the header is
	// ignored entirely and the peer address is used. Set it only when the
	// console genuinely sits behind a proxy you control, because anything in
	// this list can rewrite the source IP on every audit record.
	TrustedProxies []*net.IPNet
}

type Server struct {
	cfg Config
	db  *store.DB
	log *log.Logger

	loginLimiter  *limiter
	ingestLimiter *limiter
	reportLimiter *limiter

	consoleSrv *http.Server
	ingestSrv  *http.Server

	// silenceSeen rate-limits the watchdog so a host nobody retired does not
	// generate a finding on every tick.
	silenceMu   sync.Mutex
	silenceSeen map[string]time.Time

	// csrfKey signs per-session CSRF tokens. It is PERSISTED, because sessions
	// are: deriving it per process meant a restart invalidated the tokens of
	// sessions that remained valid in the database, so an open tab could still
	// read every page and failed every write with "invalid CSRF token".
	csrfKey []byte

	// fwd is nil when SIEM forwarding is not configured. Every method on
	// Forwarder tolerates a nil receiver, so call sites stay uncluttered.
	fwd *Forwarder
}

func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "WordEye"
	}
	if cfg.ConsoleAddr == "" {
		cfg.ConsoleAddr = "127.0.0.1:8443"
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	key, err := csrfSigningKey(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	var fwd *Forwarder
	if cfg.Forward.Target != "" {
		var err error
		fwd, err = NewForwarder(cfg.Forward, cfg.Logger)
		if err != nil {
			db.Close()
			return nil, err
		}
	}

	s := &Server{
		cfg:           cfg,
		db:            db,
		fwd:           fwd,
		log:           cfg.Logger,
		loginLimiter:  newLimiter(10, time.Minute),
		ingestLimiter: newLimiter(240, time.Minute),
		// Reports are large; a legitimate agent sends one per scan, not per minute.
		reportLimiter: newLimiter(6, time.Minute),
		csrfKey:       key,
	}
	if fwd != nil {
		fwd.Start()
		// Route every audit entry to the SIEM.
		db.OnAudit = fwd.ForwardAudit
		cfg.Logger.Printf("syslog forwarding to %s over TLS", cfg.Forward.Target)
	}
	return s, nil
}

func (s *Server) DB() *store.DB { return s.db }

func (s *Server) Close() error {
	if s.fwd != nil {
		sent, dropped, errs := s.fwd.Stats()
		s.log.Printf("syslog forwarder: %d sent, %d dropped, %d errors", sent, dropped, errs)
		_ = s.fwd.Close()
	}
	return s.db.Close()
}

// Run starts both listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.preflight(); err != nil {
		return err
	}

	errc := make(chan error, 2)

	s.consoleSrv = &http.Server{
		Addr:              s.cfg.ConsoleAddr,
		Handler:           s.consoleHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		scheme := "http"
		var err error
		if s.cfg.ConsoleTLS && s.cfg.TLSCert != "" {
			scheme = "https"
			s.log.Printf("console  listening on %s://%s", scheme, s.cfg.ConsoleAddr)
			err = s.consoleSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			s.log.Printf("console  listening on %s://%s", scheme, s.cfg.ConsoleAddr)
			err = s.consoleSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("console listener: %w", err)
		}
	}()

	if s.cfg.IngestAddr != "" {
		s.ingestSrv = &http.Server{
			Addr:              s.cfg.IngestAddr,
			Handler:           s.ingestHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
		go func() {
			var err error
			if s.cfg.TLSCert != "" {
				s.log.Printf("ingest   listening on https://%s", s.cfg.IngestAddr)
				err = s.ingestSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
			} else {
				s.log.Printf("ingest   listening on http://%s (NO TLS)", s.cfg.IngestAddr)
				err = s.ingestSrv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("ingest listener: %w", err)
			}
		}()
	}

	// Background maintenance.
	go s.janitor(ctx)
	// Scheduled scans. Only scan, baseline and verify are schedulable, so a
	// clock can never trigger what the two-key rule keeps behind a human.
	s.startScheduler(ctx)
	// Silence is the only signal an uncatchable kill leaves, and only the
	// server can see it.
	s.startWatchdog(ctx)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s.consoleSrv != nil {
		_ = s.consoleSrv.Shutdown(shutCtx)
	}
	if s.ingestSrv != nil {
		_ = s.ingestSrv.Shutdown(shutCtx)
	}
	return nil
}

// preflight refuses configurations that would quietly expose credentials or the
// containment API. Better to fail at startup than to run insecurely.
func (s *Server) preflight() error {
	if s.cfg.IngestAddr != "" && s.cfg.TLSCert == "" {
		if !isLoopbackAddr(s.cfg.IngestAddr) && !s.cfg.InsecureAllowPlaintextIngest {
			return fmt.Errorf(
				"refusing to serve ingest on %s without TLS: agent credentials would cross the network in plaintext.\n"+
					"Supply --tls-cert/--tls-key, or pass --insecure-allow-plaintext-ingest if TLS terminates at a proxy in front of this",
				s.cfg.IngestAddr)
		}
	}
	if !isLoopbackAddr(s.cfg.ConsoleAddr) {
		s.log.Printf("WARNING: the console is bound to %s, which is not loopback.", s.cfg.ConsoleAddr)
		s.log.Printf("         The console can order containment across the estate; keep it on a private network.")
		if !s.cfg.ConsoleTLS {
			s.log.Printf("         It is also serving without TLS: session cookies are exposed.")
		}
	}
	return nil
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	// An EMPTY host means ":8444", which binds every interface — the opposite
	// of loopback. Treating it as loopback silently disabled the TLS guard
	// below for the most common way of binding publicly.
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// An unresolvable or named host is not provably loopback; assume public.
		return false
	}
	return ip.IsLoopback()
}

func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.db.PruneSessions()
			_ = s.db.PruneHeartbeats(14 * 24 * time.Hour)
			s.loginLimiter.sweep()
			s.ingestLimiter.sweep()
			s.reportLimiter.sweep()
		}
	}
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// readJSON enforces a body limit and rejects unknown fields. Strict decoding on
// the internet-facing ingest API means a malformed or hostile payload is
// refused rather than partially applied.
func readJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject trailing content: one request, one object.
	if dec.More() {
		return fmt.Errorf("unexpected trailing data in request body")
	}
	return nil
}

// clientIP returns the peer address, and consults X-Forwarded-For only when
// the immediate peer is a configured trusted proxy.
//
// The header used to be trusted unconditionally, which was remotely exploitable
// without credentials. docker-compose publishes the ingest listener directly
// ("8444:8444", no reverse proxy), and ingestSecurity keys the rate limiter on
// this value BEFORE authentication. A client sending a unique X-Forwarded-For
// per request therefore got a fresh limiter window every time — defeating both
// the 240/min ingest cap and the 10/min login cap outright — while inserting a
// new map entry per request that the janitor only prunes every ten minutes.
// With Go's 1MB default header limit that is a memory-exhaustion primitive
// against the console the whole fleet reports to.
//
// It also poisoned evidence: this value becomes the source IP on every audit
// row and every forwarded SIEM event, so attribution in a security product was
// attacker-controlled.
//
// The header is now used only when the connection actually came from a proxy
// the operator listed, which is the only circumstance in which it means
// anything.
func (s *Server) clientIP(r *http.Request) string {
	peer := peerIP(r)
	if len(s.cfg.TrustedProxies) == 0 {
		return peer
	}
	if !isTrustedProxy(peer, s.cfg.TrustedProxies) {
		return peer
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Left-most entry is the original client, per the header's convention.
		if i := strings.IndexByte(xff, ','); i > 0 {
			xff = xff[:i]
		}
		// Bound it: this becomes a map key and an audit field.
		if v := strings.TrimSpace(xff); v != "" && len(v) <= 45 && net.ParseIP(v) != nil {
			return v
		}
	}
	return peer
}

// peerIP is the address of whoever actually opened the connection. It cannot be
// forged by a header.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isTrustedProxy reports whether an address falls inside any configured CIDR.
func isTrustedProxy(ip string, cidrs []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range cidrs {
		if n != nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

// readAllLimited reads a whole body under a hard ceiling.
func readAllLimited(r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, max))
}

// csrfToken derives a per-session token. Bound to the session and to a
// process-lifetime secret, so it cannot be forged or replayed across sessions.
func (s *Server) csrfToken(sessionID string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// rate limiting
// ---------------------------------------------------------------------------

// limiter is a fixed-window counter keyed by an arbitrary string. Sufficient
// for throttling login attempts and agent chatter; not a general-purpose QoS
// mechanism.
type limiter struct {
	mu     sync.Mutex
	counts map[string]*window
	max    int
	period time.Duration
}

type window struct {
	start time.Time
	n     int
}

func newLimiter(max int, period time.Duration) *limiter {
	return &limiter{counts: map[string]*window{}, max: max, period: period}
}

// allow reports whether the key is under its quota, and consumes one unit.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.counts[key]
	nowT := time.Now()
	if !ok || nowT.Sub(w.start) > l.period {
		l.counts[key] = &window{start: nowT, n: 1}
		return true
	}
	if w.n >= l.max {
		return false
	}
	w.n++
	return true
}

func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.counts {
		if time.Since(w.start) > 2*l.period {
			delete(l.counts, k)
		}
	}
}

// csrfSigningKeyName is the settings key holding the CSRF signing secret.
const csrfSigningKeyName = "csrf_signing_key"

// csrfSigningKey loads the persisted CSRF signing key, creating one on first
// run.
//
// It has to outlive the process for the same reason sessions do. A key
// generated per start invalidated every outstanding CSRF token on restart while
// leaving the sessions themselves valid, which presents to a user as an
// intermittent "invalid CSRF token" on an otherwise working console — reads
// succeed, because GET carries no CSRF check, and only writes fail.
//
// Storing it beside the session table costs nothing in security terms: anything
// able to read this table can already read the sessions the key protects.
func csrfSigningKey(db *store.DB) ([]byte, error) {
	if v, err := db.Setting(csrfSigningKeyName); err == nil && v != "" {
		if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := db.SetSetting(csrfSigningKeyName, hex.EncodeToString(key)); err != nil {
		return nil, err
	}
	return key, nil
}
