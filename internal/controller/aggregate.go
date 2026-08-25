package controller

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"wordeye/internal/model"
)

// Estate-level analysis.
//
// This is the capability a per-host tool cannot have. Wordfence sees one site
// and therefore cannot tell "this site has a shell" from "the same shell was
// planted on eleven sites in one afternoon" — but that distinction determines
// whether you are cleaning an incident or hunting a shared credential, a
// compromised deployment pipeline, or a backdoored plugin.

type Aggregate struct {
	GeneratedAt time.Time `json:"generated_at"`
	Mode        string    `json:"mode"`

	Hosts     int `json:"hosts"`
	Reachable int `json:"reachable"`
	Failed    int `json:"failed"`
	Dirty     int `json:"dirty"`
	Partial   int `json:"partial"`
	Clean     int `json:"clean"`

	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`

	TopRules    []RuleCount   `json:"top_rules"`
	Correlated  []Correlation `json:"correlated_artifacts"`
	SharedRules []RuleSpread  `json:"shared_detections"`

	Results []Result `json:"results"`
}

type RuleCount struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
	Hosts    int    `json:"hosts"`
}

// Correlation is one artefact (by content digest) present on several hosts.
type Correlation struct {
	SHA256   string   `json:"sha256"`
	Title    string   `json:"title"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Hosts    []string `json:"hosts"`
	Paths    []string `json:"paths"`
}

// RuleSpread is one detection seen across several hosts, regardless of whether
// the bytes matched — the attacker may repack per host while keeping technique.
type RuleSpread struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Hosts    []string `json:"hosts"`
}

func Aggregated(results []Result, mode string) *Aggregate {
	agg := &Aggregate{
		GeneratedAt: time.Now().UTC(),
		Mode:        mode,
		Hosts:       len(results),
		BySeverity:  map[string]int{},
		Results:     results,
	}

	type ruleAcc struct {
		title, severity string
		count           int
		hosts           map[string]bool
	}
	rules := map[string]*ruleAcc{}

	type hashAcc struct {
		title, ruleID, severity string
		hosts                   map[string]bool
		paths                   map[string]bool
	}
	hashes := map[string]*hashAcc{}

	for _, res := range results {
		if !res.OK() {
			agg.Failed++
			continue
		}
		agg.Reachable++
		switch worstVerdict(res.Reports) {
		case "dirty":
			agg.Dirty++
		case "partial":
			agg.Partial++
		default:
			agg.Clean++
		}

		hostName := res.Host.Name()
		for _, r := range res.Reports {
			for _, f := range r.Findings {
				agg.TotalFindings++
				agg.BySeverity[string(f.Severity)]++

				// Informational findings are inventory, not signal; excluding
				// them keeps the estate view about what actually matters.
				if f.Severity.Rank() < model.SevMedium.Rank() {
					continue
				}

				acc, ok := rules[f.RuleID]
				if !ok {
					acc = &ruleAcc{title: f.Title, severity: string(f.Severity), hosts: map[string]bool{}}
					rules[f.RuleID] = acc
				}
				acc.count++
				acc.hosts[hostName] = true

				if f.SHA256 == "" {
					continue
				}
				h, ok := hashes[f.SHA256]
				if !ok {
					h = &hashAcc{
						title: f.Title, ruleID: f.RuleID, severity: string(f.Severity),
						hosts: map[string]bool{}, paths: map[string]bool{},
					}
					hashes[f.SHA256] = h
				}
				h.hosts[hostName] = true
				h.paths[f.Path] = true
			}
		}
	}

	for id, acc := range rules {
		agg.TopRules = append(agg.TopRules, RuleCount{
			RuleID: id, Title: acc.title, Severity: acc.severity,
			Count: acc.count, Hosts: len(acc.hosts),
		})
		if len(acc.hosts) > 1 {
			agg.SharedRules = append(agg.SharedRules, RuleSpread{
				RuleID: id, Title: acc.title, Severity: acc.severity,
				Hosts: sortedKeys(acc.hosts),
			})
		}
	}
	sort.Slice(agg.TopRules, func(i, j int) bool {
		if agg.TopRules[i].Count != agg.TopRules[j].Count {
			return agg.TopRules[i].Count > agg.TopRules[j].Count
		}
		return agg.TopRules[i].RuleID < agg.TopRules[j].RuleID
	})
	sort.Slice(agg.SharedRules, func(i, j int) bool {
		return len(agg.SharedRules[i].Hosts) > len(agg.SharedRules[j].Hosts)
	})

	// The headline correlation: byte-identical artefacts on multiple hosts.
	for sum, h := range hashes {
		if len(h.hosts) < 2 {
			continue
		}
		agg.Correlated = append(agg.Correlated, Correlation{
			SHA256: sum, Title: h.title, RuleID: h.ruleID, Severity: h.severity,
			Hosts: sortedKeys(h.hosts), Paths: sortedKeys(h.paths),
		})
	}
	sort.Slice(agg.Correlated, func(i, j int) bool {
		return len(agg.Correlated[i].Hosts) > len(agg.Correlated[j].Hosts)
	})
	return agg
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Render writes the operator-facing summary.
func (a *Aggregate) Render(w io.Writer) {
	fmt.Fprintf(w, "\n══ WordEye estate summary ══ %s ══\n\n", a.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "hosts: %d   reachable: %d   unreachable: %d\n", a.Hosts, a.Reachable, a.Failed)
	fmt.Fprintf(w, "verdicts: %d dirty, %d partial, %d clean\n", a.Dirty, a.Partial, a.Clean)
	fmt.Fprintf(w, "findings: %d total — %d critical, %d high, %d medium\n\n",
		a.TotalFindings, a.BySeverity["critical"], a.BySeverity["high"], a.BySeverity["medium"])

	// Per-host table.
	fmt.Fprintln(w, "HOST                              VERDICT   CRIT  HIGH  NOTES")
	fmt.Fprintln(w, strings.Repeat("─", 78))
	for _, res := range a.Results {
		name := truncPad(res.Host.Name(), 33)
		if !res.OK() {
			fmt.Fprintf(w, "%s %-9s %-5s %-5s %s\n", name, "ERROR", "-", "-", trunc(res.Err, 28))
			continue
		}
		crit, high := 0, 0
		notes := []string{}
		for _, r := range res.Reports {
			c := r.Counts()
			crit += c[model.SevCritical]
			high += c[model.SevHigh]
			for _, ch := range r.Checks {
				if ch.State == model.CheckError {
					notes = append(notes, ch.ID+" failed")
				}
			}
		}
		if len(res.Reports) > 1 {
			notes = append([]string{fmt.Sprintf("%d sites", len(res.Reports))}, notes...)
		}
		fmt.Fprintf(w, "%s %-9s %-5d %-5d %s\n",
			name, strings.ToUpper(worstVerdict(res.Reports)), crit, high, trunc(strings.Join(notes, ", "), 28))
	}

	if len(a.Correlated) > 0 {
		fmt.Fprintf(w, "\n── Identical artefacts across hosts ── (same SHA-256 = one campaign, not %d coincidences)\n", len(a.Correlated))
		for i, c := range a.Correlated {
			if i >= 15 {
				fmt.Fprintf(w, "  … and %d more\n", len(a.Correlated)-15)
				break
			}
			fmt.Fprintf(w, "  %s  %s\n", c.SHA256[:16], c.Title)
			fmt.Fprintf(w, "    on %d hosts: %s\n", len(c.Hosts), trunc(strings.Join(c.Hosts, ", "), 120))
			fmt.Fprintf(w, "    paths: %s\n", trunc(strings.Join(c.Paths, ", "), 120))
		}
	}

	if len(a.SharedRules) > 0 {
		fmt.Fprintln(w, "\n── Techniques seen on multiple hosts ── (repacked payloads, shared technique)")
		for i, s := range a.SharedRules {
			if i >= 12 {
				break
			}
			fmt.Fprintf(w, "  [%-8s] %-38s %d hosts\n", strings.ToUpper(s.Severity), trunc(s.RuleID, 38), len(s.Hosts))
		}
	}

	if len(a.TopRules) > 0 {
		fmt.Fprintln(w, "\n── Most frequent detections ──")
		for i, r := range a.TopRules {
			if i >= 12 {
				break
			}
			fmt.Fprintf(w, "  %-40s %4d hits / %d hosts  %s\n",
				trunc(r.RuleID, 40), r.Count, r.Hosts, trunc(r.Title, 50))
		}
	}

	fmt.Fprintln(w)
	switch {
	case a.Failed > 0 && a.Dirty > 0:
		fmt.Fprintf(w, "RESULT: %d host(s) compromised; %d unreachable and therefore UNKNOWN, not clean.\n", a.Dirty, a.Failed)
	case a.Dirty > 0:
		fmt.Fprintf(w, "RESULT: %d of %d hosts have findings requiring action.\n", a.Dirty, a.Reachable)
	case a.Failed > 0:
		fmt.Fprintf(w, "RESULT: no findings on reachable hosts, but %d host(s) could not be checked.\n", a.Failed)
	case a.Partial > 0:
		fmt.Fprintf(w, "RESULT: no findings, but %d host(s) had checks that could not complete.\n", a.Partial)
	default:
		fmt.Fprintln(w, "RESULT: no findings across the estate. Confirm behaviourally before declaring the incident closed.")
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func truncPad(s string, n int) string {
	s = trunc(s, n)
	return s + strings.Repeat(" ", n-len([]rune(s)))
}
