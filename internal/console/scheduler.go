package console

import (
	"context"
	"time"

	"wordeye/internal/store"
)

// The scheduler turns a clock into an operator.
//
// A full sweep is the expensive operation — the EDR split exists precisely so
// that it happens deliberately rather than on a loop — but "deliberately" does
// not have to mean "manually". The right time to sweep a production estate is
// the small hours in its own timezone, and nobody should have to be awake for
// it.
//
// Two properties matter more than the scheduling itself:
//
//   - Nothing destructive is schedulable. Only scan, baseline and verify are
//     allowed, so a clock can never trigger what the two-key rule keeps behind
//     a human decision.
//   - Firings are STAGGERED. Starting a full sweep on 236 hosts at the same
//     instant is a self-inflicted outage on shared infrastructure; this is the
//     same lesson as the agent CPU work, one level up.
const schedulerTick = time.Minute

func (s *Server) startScheduler(ctx context.Context) {
	go func() {
		t := time.NewTicker(schedulerTick)
		defer t.Stop()
		// Run once at startup so a console that was down over a schedule's
		// window catches up rather than silently skipping a night.
		s.runDueSchedules(time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.runDueSchedules(now)
			}
		}
	}()
}

func (s *Server) runDueSchedules(now time.Time) {
	due, err := s.db.DueSchedules(now)
	if err != nil {
		s.log.Printf("scheduler: %v", err)
		return
	}
	for i := range due {
		sch := due[i]
		// Advance FIRST. A console that dies mid-dispatch then re-runs at most
		// one schedule instead of looping on a permanently-due row.
		if err := s.db.MarkScheduleRun(&sch, now); err != nil {
			s.log.Printf("scheduler: advancing %q: %v", sch.Name, err)
			continue
		}
		agents, err := s.db.AgentsForSchedule(sch)
		if err != nil {
			s.log.Printf("scheduler: resolving %q: %v", sch.Name, err)
			continue
		}
		n := s.dispatchSchedule(sch, agents, now)
		s.log.Printf("scheduler: %q dispatched %s to %d host(s); next %s",
			sch.Name, sch.Kind, n, sch.NextRun.Format(time.RFC3339))
		_ = s.db.Audit("scheduler", "schedule.fired", sch.Name,
			schedDetail(sch, n), "local", "ok")
	}
}

// dispatchSchedule queues one command per agent, spread across the jitter
// window. The offset is derived from the agent id, so a host keeps the same
// slot night after night rather than wandering.
func (s *Server) dispatchSchedule(sch store.Schedule, agents []store.Agent, now time.Time) int {
	queued := 0
	for _, a := range agents {
		// A command's TTL covers its own window plus the stagger, so a host
		// that is offline at its slot still picks the work up when it returns —
		// but not days later, when the operator has forgotten it was asked for.
		ttl := 12*time.Hour + sch.AgentOffset(a.ID)
		// The offset is applied to the COMMAND, not written into params.
		//
		// It used to be a params field, which nothing reads — the agent ignores
		// params by design and the dispatch query had no time predicate — so
		// every host picked its command up on the next heartbeat and the whole
		// fleet swept inside one minute. Passing it to the store is what makes
		// the stagger real.
		notBefore := now.Add(sch.AgentOffset(a.ID))
		params := map[string]any{
			"scheduled":   true,
			"schedule":    sch.Name,
			"jitter_mins": sch.Jitter,
		}
		if _, err := s.db.CreateCommandAt(a.ID, sch.Kind, params, "scheduler", ttl, notBefore); err != nil {
			s.log.Printf("scheduler: queueing %s for %s: %v", sch.Kind, a.ID, err)
			continue
		}
		queued++
	}
	return queued
}

func schedDetail(sch store.Schedule, n int) string {
	scope := "all agents"
	switch {
	case sch.AgentID != "":
		scope = "agent " + sch.AgentID
	case sch.EstateID != 0:
		scope = "estate " + itoa(sch.EstateID)
	}
	return sch.Kind + " on " + scope + " (" + itoa(int64(n)) + " host(s))"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
