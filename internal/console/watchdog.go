package console

import (
	"context"
	"fmt"
	"time"

	"wordeye/internal/store"
)

// The silence watchdog.
//
// SIGKILL is not delivered to userspace, so an agent killed with -9 sends
// nothing and never runs again to notice its own missing clean-exit marker.
// From the host's point of view that death is unreportable. From the CONSOLE's
// point of view it is loud: a machine that was checking in every minute stopped,
// said nothing, and did not come back.
//
// That is the case an actual intruder produces, and until now it was only
// VISIBLE — a row quietly turning stale in a list nobody was watching at 3am —
// rather than reported.
//
// The check depends on there being a blessed way to leave. An agent that is
// uninstalled through the console is retired, and retired agents are not
// watched; an administrator who decommissions a site properly generates
// nothing. Everything else is worth an operator's attention, which is only true
// because the legitimate path exists.
const (
	watchdogTick = 5 * time.Minute
	// silenceThreshold is how long a host may be quiet before it is treated as
	// gone. Generous relative to the one-minute heartbeat: a restart, a deploy
	// or a slow network must not raise an incident.
	silenceThreshold = 15 * time.Minute
	// silenceRepeat bounds how often the same silent host is re-reported, so a
	// permanently decommissioned machine nobody retired does not generate a
	// finding every tick.
	silenceRepeat = 24 * time.Hour
)

func (s *Server) startWatchdog(ctx context.Context) {
	go func() {
		t := time.NewTicker(watchdogTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.checkForSilentAgents(now)
			}
		}
	}()
}

func (s *Server) checkForSilentAgents(now time.Time) {
	agents, err := s.db.ListAgents(false, 0)
	if err != nil {
		s.log.Printf("watchdog: %v", err)
		return
	}
	for _, a := range agents {
		if a.LastSeen.IsZero() {
			// Enrolled but never checked in. That is an installation problem,
			// not a disappearance, and the fleet view already shows it.
			continue
		}
		quiet := now.Sub(a.LastSeen)
		if quiet < silenceThreshold {
			continue
		}
		if !s.shouldReportSilence(a.ID, now) {
			continue
		}
		f := store.FindingInput{
			RuleID:     "agent.went_silent",
			Class:      "OSP",
			Severity:   "high",
			Confidence: "confirmed",
			Title:      "The agent stopped reporting without being uninstalled",
			Detail: fmt.Sprintf(
				"This host last checked in %s ago, at %s, and has not returned. It was not uninstalled "+
					"through the console, and it sent no termination notice — so it was not stopped in any "+
					"way it could report. That is what SIGKILL, a destroyed container or a powered-off host "+
					"look like from here, and it is also what an intruder silencing the agent looks like. "+
					"Nothing written on this host since then has been evaluated in real time.",
				quiet.Round(time.Minute), a.LastSeen.Format(time.RFC3339)),
			Remediation: "Confirm whether this host was decommissioned. If it was, uninstall from the console " +
				"so the record is explicit. If it was not, treat the gap as unmonitored: check web-server and " +
				"auth logs around the last check-in, and run a full scan once the agent is back.",
			Path: a.Hostname,
			Meta: map[string]any{
				"last_seen":     a.LastSeen,
				"quiet_seconds": int64(quiet.Seconds()),
				"hostname":      a.Hostname,
			},
		}
		if err := s.db.UpsertFinding(a.ID, f); err != nil {
			s.log.Printf("watchdog: recording silence for %s: %v", a.ID, err)
			continue
		}
		s.log.Printf("watchdog: %s (%s) silent for %s", a.Hostname, a.ID, quiet.Round(time.Minute))
		_ = s.db.Audit("watchdog", "agent.went_silent", a.ID,
			fmt.Sprintf("no contact for %s", quiet.Round(time.Minute)), "local", "ok")
	}
}

// shouldReportSilence rate-limits per host.
func (s *Server) shouldReportSilence(agentID string, now time.Time) bool {
	s.silenceMu.Lock()
	defer s.silenceMu.Unlock()
	if s.silenceSeen == nil {
		s.silenceSeen = map[string]time.Time{}
	}
	if last, ok := s.silenceSeen[agentID]; ok && now.Sub(last) < silenceRepeat {
		return false
	}
	s.silenceSeen[agentID] = now
	return true
}
