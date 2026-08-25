package console

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"wordeye/internal/store"
)

// Resource limits on the agent-facing endpoints.
//
// The threat model here is unusual and easy to get wrong: an ENROLLED agent is
// a customer's WordPress host — precisely the kind of machine this product
// exists because it gets compromised. Authentication says the report came from
// that host, not that the host is still trustworthy. So the limits below are
// not anti-abuse niceties, they are the boundary between one compromised
// customer site and an unavailable console for every other customer.

// A body-size limit is not a limit on WORK. A minimal finding is ~44 bytes of
// JSON, so a 12MB report carries roughly 286,000 of them — each an upsert
// against a database deliberately held to a single writer.
func TestReportFindingsAreCapped(t *testing.T) {
	h := newHarness(t)
	ag, code, body := h.enroll(h.mintToken(1, false), false)
	if code != http.StatusOK {
		t.Fatalf("enroll failed: %d %s", code, body)
	}

	over := maxFindingsPerReport + 250
	findings := make([]map[string]any, 0, over)
	for i := 0; i < over; i++ {
		findings = append(findings, map[string]any{
			"rule_id":  "flood.rule",
			"severity": "low",
			// Distinct paths so each is a separate row rather than a dedupe.
			"path": fmt.Sprintf("wp-content/f%d.php", i),
		})
	}

	var out struct {
		OK       bool `json:"ok"`
		Findings int  `json:"findings"`
		Dropped  int  `json:"dropped"`
	}
	code, body = h.postJSON(h.ingest.URL, "/v1/report", ag.auth(),
		map[string]any{"mode": "scan", "findings": findings}, &out)
	if code != http.StatusOK {
		t.Fatalf("report rejected: %d %s", code, body)
	}
	if out.Findings > maxFindingsPerReport {
		t.Errorf("stored %d findings, cap is %d", out.Findings, maxFindingsPerReport)
	}
	if out.Dropped != over-maxFindingsPerReport {
		t.Errorf("dropped = %d, want %d", out.Dropped, over-maxFindingsPerReport)
	}
	// Truncation must be visible in the response, not silent: a scanner that
	// quietly reports less than it found is the failure this codebase exists
	// to avoid.
	if out.Dropped == 0 {
		t.Error("truncation was not disclosed to the agent")
	}
	t.Logf("offered %d, stored %d, dropped %d", over, out.Findings, out.Dropped)
}

// A report under the cap must be stored in full — the limit must not cost
// fidelity in the normal case. A real scan of a 68,000-file site produced 25.
func TestNormalReportIsStoredInFull(t *testing.T) {
	h := newHarness(t)
	ag, code, _ := h.enroll(h.mintToken(1, false), false)
	if code != http.StatusOK {
		t.Fatal("enroll failed")
	}
	findings := make([]map[string]any, 0, 25)
	for i := 0; i < 25; i++ {
		findings = append(findings, map[string]any{
			"rule_id": "fs.heuristic_webshell", "severity": "critical",
			"path": fmt.Sprintf("wp-content/plugins/p/f%d.php", i),
		})
	}
	var out struct {
		Findings int `json:"findings"`
		Dropped  int `json:"dropped"`
	}
	if code, body := h.postJSON(h.ingest.URL, "/v1/report", ag.auth(),
		map[string]any{"mode": "scan", "findings": findings}, &out); code != http.StatusOK {
		t.Fatalf("report rejected: %d %s", code, body)
	}
	if out.Findings != 25 || out.Dropped != 0 {
		t.Errorf("stored %d dropped %d, want 25/0", out.Findings, out.Dropped)
	}
}

// Meta is free-form and reaches the row as marshalled JSON. Every other field
// is clamped; leaving this one open let a single finding carry megabytes.
func TestOversizedFindingMetaIsReplaced(t *testing.T) {
	h := newHarness(t)
	ag, code, _ := h.enroll(h.mintToken(1, false), false)
	if code != http.StatusOK {
		t.Fatal("enroll failed")
	}
	huge := strings.Repeat("A", maxFindingMeta*2)
	if code, body := h.postJSON(h.ingest.URL, "/v1/report", ag.auth(), map[string]any{
		"mode": "scan",
		"findings": []map[string]any{{
			"rule_id": "x.y", "severity": "low", "path": "a.php",
			"meta": map[string]any{"blob": huge},
		}},
	}, nil); code != http.StatusOK {
		t.Fatalf("report rejected: %d %s", code, body)
	}

	found, err := h.srv.DB().ListFindings(store.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 stored finding, got %d", len(found))
	}
	blob, _ := found[0].Meta["blob"].(string)
	if len(blob) > maxFindingMeta {
		t.Errorf("oversized meta was stored verbatim (%d bytes)", len(blob))
	}
	// Replaced wholesale rather than truncated: a clipped JSON fragment would
	// be unparseable, which is a worse outcome than an honest note.
	if _, ok := found[0].Meta["wordeye_note"]; !ok {
		t.Errorf("oversized meta was not replaced with an explanatory note: %v", found[0].Meta)
	}
	t.Logf("meta replaced with: %v", found[0].Meta["wordeye_note"])
}

// A report whose body exceeds the transport limit is refused outright.
func TestOversizedReportBodyRejected(t *testing.T) {
	h := newHarness(t)
	ag, code, _ := h.enroll(h.mintToken(1, false), false)
	if code != http.StatusOK {
		t.Fatal("enroll failed")
	}
	// One finding whose detail alone blows past the body cap.
	code, _ = h.postJSON(h.ingest.URL, "/v1/report", ag.auth(), map[string]any{
		"mode": "scan",
		"findings": []map[string]any{{
			"rule_id": "x.y", "severity": "low",
			"detail": strings.Repeat("B", maxReportBody+1024),
		}},
	}, nil)
	if code == http.StatusOK {
		t.Errorf("a report larger than the %d-byte cap was accepted", maxReportBody)
	}
}
