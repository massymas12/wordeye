package agent

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wordeye/internal/model"
)

// Baseline and drift verification.
//
// Signatures and heuristics both answer "does this look like malware?". A
// baseline answers a different and often more useful question: "is this the
// same site I left behind?". Taken immediately after remediation it becomes a
// tripwire that catches re-infection regardless of whether the new implant
// resembles anything known — which, for a re-entry through the same unpatched
// hole, it frequently does not.

// BaselinePath returns the default baseline location for a site.
func (a *Agent) BaselinePath() string {
	if a.cfg.BaselinePath != "" {
		return a.cfg.BaselinePath
	}
	name := a.rep.Site
	if name == "" {
		name = "site"
	}
	return filepath.Join(a.cfg.Home, ".wordeye", "baseline_"+sanitize(name)+".txt")
}

type baselineEntry struct {
	sha  string
	size int64
	path string
}

// hashTree walks the webroot and digests every PHP-executable file. Hashing is
// streamed, so memory stays flat regardless of file size, and every read passes
// through the governor.
func (a *Agent) hashTree(ctx context.Context) ([]baselineEntry, error) {
	root := a.cfg.Webroot
	if root == "" {
		return nil, fmt.Errorf("no webroot")
	}

	type job struct {
		abs, rel string
		size     int64
	}
	jobs := make(chan job, 256)

	var (
		mu      sync.Mutex
		entries []baselineEntry
		errs    int64
		wg      sync.WaitGroup
	)
	for i := 0; i < a.gov.Workers(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := a.gov.Gate(ctx, j.size); err != nil {
					return
				}
				sum := hashFile(j.abs)
				if sum == "" {
					atomic.AddInt64(&errs, 1)
					continue
				}
				mu.Lock()
				entries = append(entries, baselineEntry{sha: sum, size: j.size, path: j.rel})
				mu.Unlock()
			}
		}()
	}

	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && a.skipDir(rel, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isPHPPath(rel) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		select {
		case jobs <- job{abs: p, rel: rel, size: info.Size()}:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	close(jobs)
	wg.Wait()

	if errs > 0 {
		a.rep.AddError(fmt.Sprintf("%d file(s) could not be hashed", errs))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries, walkErr
}

func (a *Agent) runBaseline(ctx context.Context) {
	a.timed("baseline.write", func() (model.CheckState, string) {
		entries, err := a.hashTree(ctx)
		if err != nil && ctx.Err() != nil {
			return model.CheckError, "interrupted: " + err.Error()
		}
		out := a.BaselinePath()
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return model.CheckError, err.Error()
		}
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return model.CheckError, err.Error()
		}
		defer f.Close()

		w := bufio.NewWriter(f)
		fmt.Fprintf(w, "# wordeye baseline v1\n# site=%s webroot=%s taken=%s files=%d\n",
			a.rep.Site, a.cfg.Webroot, time.Now().UTC().Format(time.RFC3339), len(entries))
		for _, e := range entries {
			fmt.Fprintf(w, "%s %d %s\n", e.sha, e.size, e.path)
		}
		if err := w.Flush(); err != nil {
			return model.CheckError, err.Error()
		}

		a.rep.Stats.FilesRead = int64(len(entries))
		a.emit(model.Finding{
			RuleID:      "baseline.written",
			Class:       "BASELINE",
			Severity:    model.SevInfo,
			Confidence:  model.ConfConfirmed,
			Title:       fmt.Sprintf("Baseline recorded: %d PHP files", len(entries)),
			Detail:      "Take this only against a state you believe to be clean; a baseline of a compromised site makes the implant look legitimate forever.",
			Path:        out,
			Remediation: "Re-check with: wordeye-agent verify",
		})
		return model.CheckOK, ""
	})
}

func (a *Agent) runVerify(ctx context.Context) {
	a.timed("baseline.verify", func() (model.CheckState, string) {
		base, meta, err := readBaseline(a.BaselinePath())
		if err != nil {
			return model.CheckError, fmt.Sprintf("no usable baseline at %s (%v) — take one on a known-good state first", a.BaselinePath(), err)
		}
		cur, err := a.hashTree(ctx)
		if err != nil && ctx.Err() != nil {
			return model.CheckError, "interrupted: " + err.Error()
		}

		curMap := make(map[string]baselineEntry, len(cur))
		for _, e := range cur {
			curMap[e.path] = e
		}

		var added, changed, removed int
		for _, e := range cur {
			b, ok := base[e.path]
			switch {
			case !ok:
				added++
				a.driftFinding("baseline.new_file", model.SevHigh, "PHP file not present in the baseline", e, "", meta)
			case b.sha != e.sha:
				changed++
				a.driftFinding("baseline.changed_file", model.SevHigh, "PHP file changed since the baseline", e, b.sha, meta)
			}
		}
		for p, b := range base {
			if _, ok := curMap[p]; !ok {
				removed++
				a.driftFinding("baseline.removed_file", model.SevMedium, "PHP file present in the baseline is now missing", baselineEntry{path: p, sha: b.sha}, b.sha, meta)
			}
		}

		a.emit(model.Finding{
			RuleID:     "baseline.summary",
			Class:      "BASELINE",
			Severity:   sevForDrift(added + changed),
			Confidence: model.ConfConfirmed,
			Title: fmt.Sprintf("Drift vs baseline: %d new, %d changed, %d removed",
				added, changed, removed),
			Detail:      "Taken " + meta,
			Remediation: "Investigate NEW and CHANGED first. A legitimate plugin update changes many files at once; an intrusion usually changes very few.",
			Meta:        map[string]any{"new": added, "changed": changed, "removed": removed},
		})
		return model.CheckOK, ""
	})
}

func sevForDrift(n int) model.Severity {
	if n == 0 {
		return model.SevInfo
	}
	return model.SevHigh
}

func (a *Agent) driftFinding(id string, sev model.Severity, title string, e baselineEntry, was, meta string) {
	f := model.Finding{
		RuleID:      id,
		Class:       "BASELINE",
		Severity:    sev,
		Confidence:  model.ConfConfirmed,
		Title:       title,
		Path:        e.path,
		SHA256:      e.sha,
		Size:        e.size,
		Detail:      "Baseline taken " + meta,
		Remediation: "Compare against the vendor package for this plugin/theme/core version.",
	}
	if was != "" && was != e.sha {
		f.Meta = map[string]any{"baseline_sha256": was}
	}
	if abs := filepath.Join(a.cfg.Webroot, filepath.FromSlash(e.path)); e.sha != "" {
		if fi, err := os.Stat(abs); err == nil {
			mt, ct, _ := fileTimes(fi)
			f.ModTime = &mt
			if !ct.IsZero() {
				f.CTime = &ct
			}
		}
	}
	a.emit(f)
}

func readBaseline(p string) (map[string]baselineEntry, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	out := map[string]baselineEntry{}
	meta := "(unknown date)"
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			if i := strings.Index(line, "taken="); i >= 0 {
				meta = strings.Fields(line[i+len("taken="):])[0]
			}
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue
		}
		size, _ := strconv.ParseInt(parts[1], 10, 64)
		out[parts[2]] = baselineEntry{sha: parts[0], size: size, path: parts[2]}
	}
	if err := sc.Err(); err != nil {
		return nil, meta, err
	}
	if len(out) == 0 {
		return nil, meta, fmt.Errorf("baseline is empty")
	}
	return out, meta, nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
