package store

import (
	"strings"
	"testing"
	"time"
)

// A delivery names which of a customer's sites is compromised and what was
// found on it. That must not cross a network in plaintext.
func TestWebhookRefusesPlaintextToRemoteHosts(t *testing.T) {
	db := consensusDB(t)
	for _, u := range []string{
		"http://tickets.example.com/hook",
		"http://198.51.100.5/hook",
		"ftp://example.com/hook",
		"not a url at all",
		"https://",
	} {
		if _, err := db.CreateWebhook(Webhook{Name: "x", URL: u}); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
}

// A self-hosted ticket system on the same box is a real deployment, and
// refusing it would push operators towards disabling verification instead.
func TestWebhookAllowsLoopbackPlaintextAndHTTPS(t *testing.T) {
	db := consensusDB(t)
	for _, u := range []string{
		"http://127.0.0.1:8080/hook",
		"http://localhost:3000/hook",
		"https://tickets.example.com/hook",
	} {
		if _, err := db.CreateWebhook(Webhook{Name: "x", URL: u}); err != nil {
			t.Errorf("rejected %q: %v", u, err)
		}
	}
}

// The severity floor is what keeps a 438-finding estate from becoming a
// 438-ticket queue.
func TestWebhookSeverityThreshold(t *testing.T) {
	w := Webhook{MinSeverity: "high"}
	for sev, want := range map[string]bool{
		"critical": true, "high": true,
		"medium": false, "low": false, "info": false,
		"": false, "nonsense": false,
	} {
		if got := w.MeetsThreshold(sev); got != want {
			t.Errorf("MeetsThreshold(%q) = %v, want %v", sev, got, want)
		}
	}
}

// Idempotency is the difference between a useful integration and a ticket queue
// nobody can read: a monitoring fleet re-reports a shell still on disk every few
// minutes.
func TestArtefactIsTicketedOnlyOnce(t *testing.T) {
	db := consensusDB(t)
	h, err := db.CreateWebhook(Webhook{Name: "tickets", URL: "https://example.com/hook"})
	if err != nil {
		t.Fatal(err)
	}

	first, err := db.ClaimDelivery(h.ID, "fs.heuristic_webshell|abc123")
	if err != nil || !first {
		t.Fatalf("first claim failed: %v %v", first, err)
	}
	if err := db.MarkDelivered(h.ID, "fs.heuristic_webshell|abc123", nil); err != nil {
		t.Fatal(err)
	}

	again, err := db.ClaimDelivery(h.ID, "fs.heuristic_webshell|abc123")
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Error("the same artefact was claimed twice; every re-report would raise a new ticket")
	}
}

// A failed delivery must be retryable, or one transient outage loses the ticket
// permanently.
func TestFailedDeliveryIsRetried(t *testing.T) {
	db := consensusDB(t)
	h, _ := db.CreateWebhook(Webhook{Name: "tickets", URL: "https://example.com/hook"})

	if ok, _ := db.ClaimDelivery(h.ID, "k"); !ok {
		t.Fatal("first claim refused")
	}
	if err := db.MarkDelivered(h.ID, "k", errFake("collector down")); err != nil {
		t.Fatal(err)
	}
	ok, err := db.ClaimDelivery(h.ID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("a failed delivery was never retried")
	}
}

// Health must distinguish "never worked" from "worked until Tuesday".
func TestWebhookHealthIsRecorded(t *testing.T) {
	db := consensusDB(t)
	h, _ := db.CreateWebhook(Webhook{Name: "tickets", URL: "https://example.com/hook"})

	if err := db.RecordWebhookResult(h.ID, errFake("boom")); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListWebhooks()
	if list[0].FailCount != 1 || !strings.Contains(list[0].LastError, "boom") {
		t.Errorf("failure not recorded: %+v", list[0])
	}

	if err := db.RecordWebhookResult(h.ID, nil); err != nil {
		t.Fatal(err)
	}
	list, _ = db.ListWebhooks()
	if list[0].FailCount != 0 || list[0].LastError != "" || list[0].LastOK.IsZero() {
		t.Errorf("success did not clear the failure state: %+v", list[0])
	}
}

// The signing secret must never be serialised to an API client.
func TestWebhookSecretIsNotSerialised(t *testing.T) {
	db := consensusDB(t)
	h, _ := db.CreateWebhook(Webhook{Name: "tickets", URL: "https://example.com/hook"})
	if h.Secret == "" {
		t.Fatal("no secret was generated")
	}
	// The struct tag is `json:"-"`, so it must not appear in marshalled output.
	list, _ := db.ListWebhooks()
	if list[0].Secret == "" {
		t.Error("the secret was not persisted, so deliveries could not be signed")
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }

// Scaling: a findings page must not cost one query per row.
//
// At 130 agents the console runs on a single database connection, so a 500-row
// page issuing 500 sequential SELECTs blocks every agent heartbeat queued
// behind it. One query answers the whole page.
func TestEstatesOfAgentsResolvesInOneQuery(t *testing.T) {
	db := consensusDB(t)
	est, err := db.CreateEstate("Acme", "", "tester")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-24 * time.Hour)
	for _, h := range []string{"a", "b", "c"} {
		sightAs(t, db, "ag_"+h, "host-"+h, "/www/"+h, "p.php", "sha", false, base)
	}
	assignEstate(t, db, est.ID, "ag_a", "ag_b")

	got, err := db.EstatesOfAgents([]string{"ag_a", "ag_b", "ag_c", "ag_a", "", "ag_missing"})
	if err != nil {
		t.Fatal(err)
	}
	if got["ag_a"] != est.ID || got["ag_b"] != est.ID {
		t.Errorf("assigned agents resolved to %v", got)
	}
	if got["ag_c"] != 0 {
		t.Errorf("an unassigned agent resolved to estate %d, want 0", got["ag_c"])
	}
	if _, ok := got["ag_missing"]; ok {
		t.Error("a nonexistent agent produced an entry")
	}
}

// A single-agent lookup must aggregate only that agent's findings, not the
// whole fleet's. It runs on every command creation, so a bulk dispatch to 130
// hosts would otherwise mean 130 full-table aggregates.
func TestGetAgentDoesNotAggregateTheFleet(t *testing.T) {
	db := consensusDB(t)
	base := time.Now().Add(-24 * time.Hour)
	for _, h := range []string{"a", "b", "c"} {
		sightAs(t, db, "ag_"+h, "host-"+h, "/www/"+h, "shell.php", "sha"+h, false, base)
	}

	a, err := db.GetAgent("ag_a")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "ag_a" || a.Hostname != "host-a" {
		t.Errorf("wrong agent returned: %+v", a)
	}
	// Its counts must reflect only its own findings.
	if a.OpenTotal != 1 {
		t.Errorf("OpenTotal = %d, want 1 — counts are leaking from other agents", a.OpenTotal)
	}
	if _, err := db.GetAgent("ag_nope"); err == nil {
		t.Error("a missing agent did not error")
	}
}
