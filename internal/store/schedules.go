package store

import (
	"database/sql"
	"fmt"
	"hash/fnv"
	"time"
)

// Scheduled scans.
//
// Monitoring evaluates what changes; a full sweep is the expensive operation
// and runs when someone asks. That someone should be able to be a clock: the
// right time to sweep a production estate is the small hours in its own
// timezone, not whenever an analyst is at a keyboard.

// Schedule is a recurring scan across an estate or a single host.
type Schedule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	EstateID    int64     `json:"estate_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	Kind        string    `json:"kind"`
	MinuteOfDay int       `json:"minute_of_day"`
	Weekdays    int       `json:"weekdays"`
	TZ          string    `json:"tz"`
	Enabled     bool      `json:"enabled"`
	Jitter      int       `json:"jitter_minutes"`
	LastRun     time.Time `json:"last_run"`
	NextRun     time.Time `json:"next_run"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// scheduleKinds is the allowlist. Scheduling anything destructive would let a
// clock trigger what the two-key rule exists to keep behind a human.
var scheduleKinds = map[string]bool{"scan": true, "baseline": true, "verify": true}

func (s *Schedule) validate() error {
	if !scheduleKinds[s.Kind] {
		return fmt.Errorf("cannot schedule %q; only scan, baseline and verify may run unattended", s.Kind)
	}
	if s.EstateID != 0 && s.AgentID != "" {
		return fmt.Errorf("a schedule targets an estate or one agent, not both")
	}
	if s.MinuteOfDay < 0 || s.MinuteOfDay > 1439 {
		return fmt.Errorf("time of day out of range")
	}
	if s.Weekdays&0x7F == 0 {
		return fmt.Errorf("a schedule with no weekdays selected would never run")
	}
	if s.Jitter < 0 || s.Jitter > 240 {
		return fmt.Errorf("jitter must be between 0 and 240 minutes")
	}
	if _, err := time.LoadLocation(s.TZ); err != nil {
		return fmt.Errorf("unknown timezone %q", s.TZ)
	}
	return nil
}

// NextRunAfter computes the next firing at or after `from`.
//
// The timezone is honoured rather than approximated: "03:00 local" has to keep
// meaning 03:00 across a daylight-saving boundary, or a quarterly scan silently
// moves into business hours.
func (s *Schedule) NextRunAfter(from time.Time) time.Time {
	loc, err := time.LoadLocation(s.TZ)
	if err != nil {
		loc = time.UTC
	}
	t := from.In(loc)
	for i := 0; i < 8; i++ {
		day := t.AddDate(0, 0, i)
		if s.Weekdays&(1<<uint(day.Weekday())) == 0 {
			continue
		}
		fire := time.Date(day.Year(), day.Month(), day.Day(),
			s.MinuteOfDay/60, s.MinuteOfDay%60, 0, 0, loc)
		if fire.After(from) {
			return fire.UTC()
		}
	}
	return from.Add(24 * time.Hour).UTC()
}

// AgentOffset spreads one schedule's agents across the jitter window.
//
// Firing a full sweep on 236 hosts at the same instant is a self-inflicted
// outage on shared infrastructure — the same lesson as the CPU work, one level
// up. The offset is derived from the agent id so it is stable: a host keeps its
// slot night after night instead of wandering.
func (s *Schedule) AgentOffset(agentID string) time.Duration {
	if s.Jitter <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	// Modulo in uint32 space. Converting to int first is a latent bug on a
	// 32-bit build, where a hash above MaxInt32 becomes negative and yields a
	// negative offset — a scan scheduled before its own window.
	return time.Duration(h.Sum32()%uint32(s.Jitter)) * time.Minute
}

func (db *DB) CreateSchedule(s Schedule) (*Schedule, error) {
	if s.Kind == "" {
		s.Kind = "scan"
	}
	if s.TZ == "" {
		s.TZ = "UTC"
	}
	// Weekdays is deliberately NOT defaulted. Turning "no days selected" into
	// "every day" would mean an operator who unchecked everything got a nightly
	// scan across their estate — the opposite of what they asked for, and the
	// kind of surprise that costs trust in a scheduler. An empty selection is
	// an error with a message that says so.
	if err := s.validate(); err != nil {
		return nil, err
	}
	now := time.Now()
	s.NextRun = s.NextRunAfter(now)
	res, err := db.sql.Exec(
		`INSERT INTO schedules (name, estate_id, agent_id, kind, minute_of_day, weekdays, tz,
		                        enabled, jitter_minutes, next_run, created_at, created_by)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.Name, nullIfZero(s.EstateID), nullIfEmpty(s.AgentID), s.Kind, s.MinuteOfDay,
		s.Weekdays, s.TZ, boolInt(s.Enabled), s.Jitter, s.NextRun.Unix(), now.Unix(), s.CreatedBy)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.ID = id
	s.CreatedAt = now
	return &s, nil
}

func (db *DB) ListSchedules(estateID int64) ([]Schedule, error) {
	q := `SELECT id, name, COALESCE(estate_id,0), COALESCE(agent_id,''), kind, minute_of_day,
	             weekdays, tz, enabled, jitter_minutes, last_run, next_run, created_at, created_by
	        FROM schedules WHERE 1=1`
	var args []any
	if estateID != 0 {
		q += ` AND estate_id = ?`
		args = append(args, estateID)
	}
	q += ` ORDER BY next_run`
	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanSchedule(r rowScanner) (*Schedule, error) {
	var s Schedule
	var enabled int
	var last, next, created int64
	if err := r.Scan(&s.ID, &s.Name, &s.EstateID, &s.AgentID, &s.Kind, &s.MinuteOfDay,
		&s.Weekdays, &s.TZ, &enabled, &s.Jitter, &last, &next, &created, &s.CreatedBy); err != nil {
		return nil, err
	}
	s.Enabled = enabled != 0
	if last > 0 {
		s.LastRun = time.Unix(last, 0).UTC()
	}
	s.NextRun = time.Unix(next, 0).UTC()
	s.CreatedAt = time.Unix(created, 0).UTC()
	return &s, nil
}

// SetScheduleEnabled pauses or resumes a schedule.
//
// Resuming recomputes next_run. Without that, a schedule paused past its firing
// time detonates the moment it is re-enabled: an operator disables the 03:00
// estate-wide scan on Monday for maintenance and re-enables it on Friday
// afternoon, next_run is still Tuesday 03:00, and within one scheduler tick a
// full sweep lands on every host in the estate in the middle of the customer's
// business day. The jitter window only spreads that over a few working hours,
// which is not a mitigation.
func (db *DB) SetScheduleEnabled(id int64, enabled bool) error {
	if !enabled {
		_, err := db.sql.Exec(`UPDATE schedules SET enabled = 0 WHERE id = ?`, id)
		return err
	}
	// QueryRow, not Query: the pool is capped at a single connection, so holding
	// an open *sql.Rows while issuing the UPDATE below deadlocks the whole
	// store waiting for a connection that this call is itself holding.
	sch, err := scanSchedule(db.sql.QueryRow(
		`SELECT id, name, COALESCE(estate_id,0), COALESCE(agent_id,''), kind, minute_of_day,
		        weekdays, tz, enabled, jitter_minutes, last_run, next_run, created_at, created_by
		   FROM schedules WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return fmt.Errorf("no such schedule")
	}
	if err != nil {
		return err
	}
	next := sch.NextRunAfter(time.Now())
	_, err = db.sql.Exec(`UPDATE schedules SET enabled = 1, next_run = ? WHERE id = ?`,
		next.Unix(), id)
	return err
}

func (db *DB) DeleteSchedule(id int64) error {
	_, err := db.sql.Exec(`DELETE FROM schedules WHERE id = ?`, id)
	return err
}

// DueSchedules returns enabled schedules whose firing time has passed.
func (db *DB) DueSchedules(now time.Time) ([]Schedule, error) {
	rows, err := db.sql.Query(
		`SELECT id, name, COALESCE(estate_id,0), COALESCE(agent_id,''), kind, minute_of_day,
		        weekdays, tz, enabled, jitter_minutes, last_run, next_run, created_at, created_by
		   FROM schedules WHERE enabled = 1 AND next_run <= ? ORDER BY next_run`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// MarkScheduleRun records a firing and advances the schedule.
//
// next_run is advanced BEFORE the commands are created by the caller, so a
// console that crashes mid-dispatch re-runs at most one schedule rather than
// looping on it forever.
func (db *DB) MarkScheduleRun(s *Schedule, at time.Time) error {
	next := s.NextRunAfter(at)
	_, err := db.sql.Exec(
		`UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?`,
		at.Unix(), next.Unix(), s.ID)
	s.LastRun, s.NextRun = at.UTC(), next
	return err
}

// AgentsForSchedule resolves a schedule's scope to concrete agents.
func (db *DB) AgentsForSchedule(s Schedule) ([]Agent, error) {
	if s.AgentID != "" {
		a, err := db.GetAgent(s.AgentID)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		if a.Retired {
			return nil, nil
		}
		return []Agent{*a}, nil
	}
	return db.ListAgents(false, s.EstateID)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
