package agent

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"wordeye/internal/model"
)

// World-writable PHP, reported as one fact rather than thousands.
//
// A ten-host deployment produced 4,866 high-severity findings, 3,436 of them
// from a single site: every PHP file in the tree was mode 0666. That is one
// property of how the account is provisioned — an FTP-style deploy, a bad
// umask, a container running the web server as the file owner — and emitting it
// per file is a category error. It buries the estate's real findings under
// thousands of rows that all say the same thing and all have the same fix.
//
// The signal itself is worth keeping, and is genuinely high severity: if any
// process can rewrite any PHP file, then removing a shell accomplishes nothing,
// because whatever put it there can put it back. So the finding stays; only its
// cardinality changes.
//
// A handful of world-writable files is a different claim from a tree full of
// them. One file at 0666 inside an otherwise correct install points AT that
// file — something wrote it, and the permissions are evidence. Below the
// threshold each is therefore still reported individually with its own path.

const (
	// wwIndividualMax is the point at which per-file reporting stops being
	// useful and starts being noise. Below it, each file is named: a few
	// writable files in a correct install is a pointer to specific files.
	wwIndividualMax = 10
	// wwSampleMax bounds how many paths ride along in the aggregate. Enough to
	// see the shape of the problem — which trees, which depths — without
	// carrying a five-thousand-entry array to the console.
	wwSampleMax = 25
)

// wwAccum collects world-writable PHP paths during the concurrent sweep.
type wwAccum struct {
	mu    sync.Mutex
	n     int
	paths []string // capped at wwSampleMax
	trees map[string]int
}

func (w *wwAccum) add(rel string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n++
	if len(w.paths) < wwSampleMax {
		w.paths = append(w.paths, rel)
	}
	if w.trees == nil {
		w.trees = map[string]int{}
	}
	w.trees[wwTreeOf(rel)]++
}

func (w *wwAccum) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n = 0
	w.paths = nil
	w.trees = nil
}

// wwTreeOf groups a path by the unit an administrator would actually chmod: a
// plugin, a theme, or a top-level directory.
func wwTreeOf(rel string) string {
	rel = path.Clean(strings.ReplaceAll(rel, "\\", "/"))
	parts := strings.Split(rel, "/")
	switch {
	case len(parts) >= 3 && parts[0] == "wp-content" &&
		(parts[1] == "plugins" || parts[1] == "themes" || parts[1] == "mu-plugins"):
		return strings.Join(parts[:3], "/")
	case len(parts) >= 2:
		return parts[0]
	default:
		return "."
	}
}

// emitWorldWritable reports what the sweep accumulated, once.
func (a *Agent) emitWorldWritable() {
	a.ww.mu.Lock()
	n := a.ww.n
	paths := append([]string(nil), a.ww.paths...)
	trees := make(map[string]int, len(a.ww.trees))
	for k, v := range a.ww.trees {
		trees[k] = v
	}
	a.ww.mu.Unlock()

	if n == 0 {
		return
	}

	// Few enough to be about specific files: name them.
	if n <= wwIndividualMax {
		for _, rel := range paths {
			a.emit(model.Finding{
				RuleID:     "fs.world_writable_php",
				Class:      "WP",
				Severity:   model.SevHigh,
				Confidence: model.ConfConfirmed,
				Path:       rel,
				Title:      "World-writable PHP file",
				Detail: "Any process on the host can rewrite this file, so removing malicious code from it " +
					"accomplishes nothing until the permissions are fixed.",
				Remediation: "chmod 644 (or 640) and audit how it became writable.",
			})
		}
		return
	}

	// Enough to be about the install: report the property, not the instances.
	ranked := make([]string, 0, len(trees))
	for t := range trees {
		ranked = append(ranked, t)
	}
	sort.Slice(ranked, func(i, j int) bool {
		if trees[ranked[i]] != trees[ranked[j]] {
			return trees[ranked[i]] > trees[ranked[j]]
		}
		return ranked[i] < ranked[j]
	})
	if len(ranked) > wwSampleMax {
		ranked = ranked[:wwSampleMax]
	}
	worst := make([]string, 0, len(ranked))
	for _, t := range ranked {
		worst = append(worst, fmt.Sprintf("%s (%d)", t, trees[t]))
	}

	a.emit(model.Finding{
		RuleID:     "fs.world_writable_php_tree",
		Class:      "WP",
		Severity:   model.SevHigh,
		Confidence: model.ConfConfirmed,
		Title:      fmt.Sprintf("%d PHP files are world-writable", n),
		Detail: fmt.Sprintf(
			"Every one of these can be rewritten by any process on the host, which means removing a web shell "+
				"does not remove the ability to replace it. At this scale the cause is how the account is "+
				"provisioned rather than any individual file — a deploy process running as another user, a "+
				"permissive umask, or ownership that lets the web server write its own code. "+
				"Affected across %d director%s.",
			len(trees), map[bool]string{true: "y", false: "ies"}[len(trees) == 1]),
		Remediation: "Fix the permission model rather than individual files: set files to 644 and directories to " +
			"755 across the webroot, then correct whatever process recreates them writable. Until then, treat " +
			"any cleanup of this site as temporary.",
		Meta: map[string]any{
			"count":           n,
			"directories":     len(trees),
			"worst_offenders": worst,
			"sample_paths":    paths,
		},
	})
}
