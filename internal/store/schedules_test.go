package store

import (
	"strconv"
	"testing"
	"time"
)

// A full sweep is the expensive operation, which is why it is not on a timer
// inside the agent. Putting it on a timer in the CONSOLE is different: the work
// is attributable, bounded to a window an operator chose, and staggered.

func TestScheduleFiresAtTheChosenLocalTime(t *testing.T) {
	s := Schedule{Kind: "scan", MinuteOfDay: 3 * 60, Weekdays: 0x7F, TZ: "America/New_York"}
	from := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) // 08:00 in New York
	next := s.NextRunAfter(from)

	loc, _ := time.LoadLocation("America/New_York")
	local := next.In(loc)
	if local.Hour() != 3 || local.Minute() != 0 {
		t.Errorf("next run is %s local, want 03:00", local.Format("15:04"))
	}
	if !next.After(from) {
		t.Errorf("next run %s is not after %s", next, from)
	}
}

// "03:00 local" must keep meaning 03:00 across a daylight-saving boundary, or a
// scan quietly migrates into business hours twice a year.
func TestScheduleHoldsLocalTimeAcrossDST(t *testing.T) {
	s := Schedule{Kind: "scan", MinuteOfDay: 3 * 60, Weekdays: 0x7F, TZ: "America/New_York"}
	loc, _ := time.LoadLocation("America/New_York")

	// The night the clocks go forward in 2026.
	before := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	after := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	for _, from := range []time.Time{before, after} {
		local := s.NextRunAfter(from).In(loc)
		if local.Hour() != 3 {
			t.Errorf("from %s: fires at %s local, want 03:00", from.Format("Jan 2"), local.Format("15:04"))
		}
	}
}

func TestScheduleSkipsUnselectedWeekdays(t *testing.T) {
	// Sundays only.
	s := Schedule{Kind: "scan", MinuteOfDay: 60, Weekdays: 1 << uint(time.Sunday), TZ: "UTC"}
	from := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) // a Tuesday
	next := s.NextRunAfter(from)
	if next.Weekday() != time.Sunday {
		t.Errorf("next run falls on %s, want Sunday", next.Weekday())
	}
}

// Starting a full sweep on every host at the same instant is a self-inflicted
// outage on shared hosting — the same lesson as the agent CPU work, one level
// up. Offsets must also be STABLE, so a host keeps its slot night after night.
func TestScheduleStaggersHostsStably(t *testing.T) {
	s := Schedule{Jitter: 30}
	seen := map[time.Duration]int{}
	for _, id := range []string{"ag_a", "ag_b", "ag_c", "ag_d", "ag_e", "ag_f"} {
		off := s.AgentOffset(id)
		if off < 0 || off >= 30*time.Minute {
			t.Errorf("%s offset %s is outside the window", id, off)
		}
		if again := s.AgentOffset(id); again != off {
			t.Errorf("%s offset moved between calls: %s then %s", id, off, again)
		}
		seen[off]++
	}
	if len(seen) < 2 {
		t.Error("every host was given the same slot; the window is not being used")
	}
}

func TestNoJitterMeansNoOffset(t *testing.T) {
	s := Schedule{Jitter: 0}
	if off := s.AgentOffset("ag_a"); off != 0 {
		t.Errorf("offset %s with jitter disabled", off)
	}
}

// A clock must never be able to trigger what the two-key rule keeps behind a
// human decision.
func TestOnlyNonDestructiveWorkIsSchedulable(t *testing.T) {
	db := consensusDB(t)
	for _, kind := range []string{"contain", "contain_dryrun", "quarantine", "delete"} {
		if _, err := db.CreateSchedule(Schedule{Name: "x", Kind: kind, Weekdays: 0x7F, TZ: "UTC"}); err == nil {
			t.Errorf("%q was accepted as a schedulable command", kind)
		}
	}
	for _, kind := range []string{"scan", "baseline", "verify"} {
		if _, err := db.CreateSchedule(Schedule{Name: "x", Kind: kind, Weekdays: 0x7F, TZ: "UTC"}); err != nil {
			t.Errorf("%q was rejected: %v", kind, err)
		}
	}
}

func TestScheduleRejectsNonsense(t *testing.T) {
	db := consensusDB(t)
	cases := []Schedule{
		{Kind: "scan", Weekdays: 0, TZ: "UTC"},                                  // never runs
		{Kind: "scan", Weekdays: 0x7F, TZ: "Mars/Olympus"},                      // unknown tz
		{Kind: "scan", Weekdays: 0x7F, TZ: "UTC", MinuteOfDay: 5000},            // out of range
		{Kind: "scan", Weekdays: 0x7F, TZ: "UTC", EstateID: 1, AgentID: "ag_a"}, // both scopes
		{Kind: "scan", Weekdays: 0x7F, TZ: "UTC", Jitter: 9000},                 // absurd stagger
	}
	for i, c := range cases {
		if _, err := db.CreateSchedule(c); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
}

// A schedule that has fired must advance, or a console restart re-runs it.
func TestDueSchedulesAdvanceAfterFiring(t *testing.T) {
	db := consensusDB(t)
	s, err := db.CreateSchedule(Schedule{Name: "nightly", Kind: "scan", MinuteOfDay: 3 * 60,
		Weekdays: 0x7F, TZ: "UTC", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Pretend its moment has arrived.
	if _, err := db.sql.Exec(`UPDATE schedules SET next_run = ? WHERE id = ?`,
		time.Now().Add(-time.Minute).Unix(), s.ID); err != nil {
		t.Fatal(err)
	}
	due, err := db.DueSchedules(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("got %d due schedules, want 1", len(due))
	}
	if err := db.MarkScheduleRun(&due[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	again, err := db.DueSchedules(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("a fired schedule is still due; it would run every tick")
	}
}

func TestDisabledSchedulesDoNotFire(t *testing.T) {
	db := consensusDB(t)
	s, err := db.CreateSchedule(Schedule{Name: "paused", Kind: "scan", Weekdays: 0x7F, TZ: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetScheduleEnabled(s.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE schedules SET next_run = ? WHERE id = ?`,
		time.Now().Add(-time.Minute).Unix(), s.ID); err != nil {
		t.Fatal(err)
	}
	due, err := db.DueSchedules(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Errorf("a paused schedule fired")
	}
}

// The offset must never be negative. Converting a 32-bit hash to int before the
// modulo is a latent bug on a 32-bit build: a hash above MaxInt32 becomes
// negative, and the host is scheduled before its own window.
func TestScheduleOffsetIsNeverNegative(t *testing.T) {
	s := Schedule{Jitter: 30}
	// Ids chosen to spread across the hash space, including values whose FNV
	// hash has the high bit set.
	for i := 0; i < 2000; i++ {
		id := "ag_" + strconv.Itoa(i*7919)
		off := s.AgentOffset(id)
		if off < 0 {
			t.Fatalf("%s produced a negative offset: %s", id, off)
		}
		if off >= 30*time.Minute {
			t.Fatalf("%s produced %s, outside the window", id, off)
		}
	}
}

// Resuming a schedule whose firing time has passed must not detonate.
//
// next_run was left untouched by enable, so a schedule paused past 03:00 and
// resumed on a Friday afternoon dispatched a fleet-wide sweep within one tick,
// in the middle of the customer's business day.
func TestResumingAStaleScheduleDoesNotFireImmediately(t *testing.T) {
	db := consensusDB(t)
	s, err := db.CreateSchedule(Schedule{Name: "nightly", Kind: "scan", MinuteOfDay: 3 * 60,
		Weekdays: 0x7F, TZ: "UTC", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetScheduleEnabled(s.ID, false); err != nil {
		t.Fatal(err)
	}
	// Time passes; its slot goes by while paused.
	if _, err := db.sql.Exec(`UPDATE schedules SET next_run = ? WHERE id = ?`,
		time.Now().Add(-72*time.Hour).Unix(), s.ID); err != nil {
		t.Fatal(err)
	}

	if err := db.SetScheduleEnabled(s.ID, true); err != nil {
		t.Fatal(err)
	}
	due, err := db.DueSchedules(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Error("resuming a stale schedule fired it immediately across the estate")
	}

	list, err := db.ListSchedules(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !list[0].NextRun.After(time.Now()) {
		t.Errorf("next_run was not moved forward on resume: %v", list)
	}
}
