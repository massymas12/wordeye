package agent

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"wordeye/internal/model"
)

// HTTP probes.
//
// Two distinct jobs share this machinery:
//
//   - The cloak probe asks the site what it serves to a search-engine crawler.
//     Cloaking is the one class of compromise that signature and checksum
//     checks structurally cannot find, because the malicious behaviour may live
//     in the database, in a premium plugin, or in code that only executes for
//     a crawler user-agent. Asking the site to incriminate itself works
//     regardless of where the logic hides.
//
//   - The health probe establishes whether the site is serving at all. The
//     containment engine re-runs it after every destructive step and rolls back
//     if the site stops responding, which is what makes automated remediation
//     safe to run against production.

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

type healthState struct {
	OK      bool
	Status  int
	BodyLen int
	Latency time.Duration
	Err     string
}

func (h healthState) serving() bool {
	// 2xx and 3xx are fine; so is 401/403 on a site behind auth. A 5xx or a
	// transport error means the site is down.
	return h.OK && h.Status > 0 && h.Status < 500
}

func (h healthState) String() string {
	if h.Err != "" {
		return "error: " + h.Err
	}
	return fmt.Sprintf("HTTP %d, %d bytes, %s", h.Status, h.BodyLen, h.Latency.Round(time.Millisecond))
}

// originClient builds an HTTP client that connects to the loopback origin while
// still presenting the real Host/SNI. This bypasses any CDN or edge cache, so
// the probe observes what this specific server generates rather than what a
// cache replayed — essential when only one host in a pool is compromised.
func originClient(host string, viaOrigin bool) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 8 * time.Second,
		// Origin certificates frequently do not validate when addressed over
		// loopback; the probe is about content, not about trust.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viaOrigin, ServerName: host},
	}
	if viaOrigin {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "80"
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		}
	} else {
		tr.DialContext = dialer.DialContext
	}
	return &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Do not follow: an off-site redirect IS the finding.
			return http.ErrUseLastResponse
		},
	}
}

type probeResult struct {
	status   int
	body     string
	location string
	err      error
}

func fetch(ctx context.Context, target, host, ua, referer string, viaOrigin bool) probeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return probeResult{err: err}
	}
	req.Host = host
	req.Header.Set("User-Agent", ua)
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := originClient(host, viaOrigin).Do(req)
	if err != nil {
		return probeResult{err: err}
	}
	defer resp.Body.Close()
	// Cap the read: the probe must never pull a large response into memory on
	// a memory-constrained host.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return probeResult{
		status:   resp.StatusCode,
		body:     string(body),
		location: resp.Header.Get("Location"),
	}
}

// siteURL resolves the site's own address, preferring the database (which is
// what WordPress itself uses to build URLs) over any guess.
func (a *Agent) siteURL(ctx context.Context) string {
	a.urlOnce.Do(func() {
		if a.cfg.HealthURL != "" {
			a.cachedURL = a.cfg.HealthURL
			return
		}
		// wp-config.php may define the URL outright, which is the only source
		// available when the database is skipped or unreachable. A field run
		// with --skip-db reported the cloak probe as unavailable purely because
		// this fallback did not exist.
		if u := siteURLFromConfig(a.cfg.Webroot); u != "" {
			a.cachedURL = u
			return
		}
		cfg, err := a.loadDBConfig()
		if err != nil {
			return
		}
		db, err := sql.Open("mysql", cfg.dsn())
		if err != nil {
			return
		}
		defer db.Close()
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for _, opt := range []string{"home", "siteurl"} {
			var v string
			q := fmt.Sprintf("SELECT option_value FROM %soptions WHERE option_name=? LIMIT 1", cfg.Prefix)
			if err := db.QueryRowContext(qctx, q, opt).Scan(&v); err == nil && v != "" {
				a.cachedURL = v
				return
			}
		}
	})
	return a.cachedURL
}

// probeHealth reports whether the site is currently serving.
func (a *Agent) probeHealth(ctx context.Context) healthState {
	raw := a.siteURL(ctx)
	if raw == "" {
		return healthState{Err: "site URL unknown"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return healthState{Err: err.Error()}
	}
	host := u.Hostname()

	start := time.Now()
	// Prefer the origin so the health signal reflects this server, not a cache.
	target := "http://127.0.0.1/"
	if u.Scheme == "https" {
		target = "https://" + host + "/"
	}
	r := fetch(ctx, target, host, browserUA, "", true)
	if r.err != nil {
		// Fall back to the public address: some hosts do not serve on loopback.
		r = fetch(ctx, raw, host, browserUA, "", false)
	}
	if r.err != nil {
		return healthState{Err: r.err.Error(), Latency: time.Since(start)}
	}
	return healthState{OK: true, Status: r.status, BodyLen: len(r.body), Latency: time.Since(start)}
}

// checkCloak compares the crawler view against the browser view.
//
// Comparing the two is what makes this reliable: a site that legitimately
// mentions a spam keyword shows it to both, whereas a cloak by definition shows
// it only to the crawler. That differential is the detection.
func (a *Agent) checkCloak(ctx context.Context) {
	a.timed("probe.cloak", func() (model.CheckState, string) {
		raw := a.siteURL(ctx)
		if raw == "" {
			return model.CheckUnavailable, "could not determine the site URL"
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return model.CheckUnavailable, "unparseable site URL: " + raw
		}
		host := u.Hostname()
		kw := a.set.IOCs.SpamKeywords

		target := "http://127.0.0.1/"
		if u.Scheme == "https" {
			target = "https://" + host + "/"
		}

		bot := fetch(ctx, target, host, googlebotUA, "https://www.google.com/", true)
		if bot.err != nil {
			bot = fetch(ctx, raw, host, googlebotUA, "https://www.google.com/", false)
		}
		if bot.err != nil {
			return model.CheckError, "crawler probe failed: " + bot.err.Error()
		}
		human := fetch(ctx, target, host, browserUA, "", true)
		if human.err != nil {
			human = fetch(ctx, raw, host, browserUA, "", false)
		}

		botLow := strings.ToLower(bot.body)
		humanLow := strings.ToLower(human.body)

		var onlyBot, both []string
		for _, k := range kw {
			lk := strings.ToLower(k)
			inBot := strings.Contains(botLow, lk)
			if !inBot {
				continue
			}
			if human.err == nil && strings.Contains(humanLow, lk) {
				both = append(both, k)
			} else {
				onlyBot = append(onlyBot, k)
			}
		}

		switch {
		case len(onlyBot) > 0:
			a.emit(model.Finding{
				RuleID:     "probe.cloak_active",
				Class:      "CLOAK",
				Severity:   model.SevCritical,
				Confidence: model.ConfConfirmed,
				Title:      "Server serves spam to crawlers but not to browsers",
				Detail: fmt.Sprintf(
					"Requesting %s as Googlebot returned: %s. The same request as a normal browser did not. This is an active server-side cloak, and it is what damages the domain's search reputation.",
					host, strings.Join(onlyBot, ", ")),
				Remediation: "Hunt the cloak in theme functions.php, the front controller, mu-plugins, autoloaded options, and any premium plugin. Re-run this probe to confirm removal.",
				Meta:        map[string]any{"keywords": onlyBot, "host": host},
			})
		case len(both) > 0:
			a.emit(model.Finding{
				RuleID:      "probe.spam_content_served",
				Class:       "CLOAK",
				Severity:    model.SevHigh,
				Confidence:  model.ConfLikely,
				Title:       "Spam keywords served to all visitors",
				Detail:      "Present in both crawler and browser responses: " + strings.Join(both, ", ") + ". Injected content rather than a cloak.",
				Remediation: "Locate and remove the injected content, then request re-indexing.",
				Meta:        map[string]any{"keywords": both},
			})
		}

		// An off-site redirect shown only to the crawler is a doorway.
		if bot.location != "" && isOffSite(bot.location, host) {
			if human.err != nil || human.location != bot.location {
				a.emit(model.Finding{
					RuleID:      "probe.crawler_redirect",
					Class:       "CLOAK",
					Severity:    model.SevCritical,
					Confidence:  model.ConfConfirmed,
					Title:       "Crawler is redirected off-site",
					Detail:      fmt.Sprintf("Googlebot receives HTTP %d to %s; a browser does not.", bot.status, bot.location),
					Remediation: "Trace the redirect source; treat as an active doorway.",
					Meta:        map[string]any{"location": bot.location, "status": bot.status},
				})
			}
		}
		return model.CheckOK, ""
	})
}

func isOffSite(location, host string) bool {
	u, err := url.Parse(location)
	if err != nil || u.Host == "" {
		return false // relative redirect
	}
	h := strings.ToLower(u.Hostname())
	host = strings.ToLower(host)
	return h != host && !strings.HasSuffix(h, "."+host)
}

// wpConfigURLRe matches a WP_HOME or WP_SITEURL definition in wp-config.php.
var wpConfigURLRe = regexp.MustCompile(`define\s*\(\s*[\x27"](?:WP_HOME|WP_SITEURL)[\x27"]\s*,\s*[\x27"]([^\x27"]+)[\x27"]`)

// siteURLFromConfig recovers the site address without touching the database.
//
// Many installs pin WP_HOME/WP_SITEURL in wp-config.php precisely so the URL
// does not depend on the database, which makes it the right source when the
// database is skipped, unreachable, or has itself been tampered with.
func siteURLFromConfig(webroot string) string {
	p, ok := findWPConfig(webroot)
	if !ok {
		return ""
	}
	b, err := readHead(p, 256<<10)
	if err != nil {
		return ""
	}
	if m := wpConfigURLRe.FindSubmatch(b); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
