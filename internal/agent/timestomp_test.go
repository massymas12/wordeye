package agent

import (
	"fmt"
	"testing"
	"time"

	"wordeye/internal/govern"
	"wordeye/internal/model"
)

// Timestomping is judged per filesystem OPERATION, not per file.
//
// A field run produced 79 high-severity timestomp findings. Essentially all of
// them were one managed host's mu-plugin deployment: dozens of files sharing a
// single mtime and a single ctime, because extracting an archive stamps ctime
// on everything at once while mtime carries over from the package. That volume
// buries the handful of files that would actually matter.
//
// These tests hold the line in both directions: a deployment must collapse to
// one finding, and a targeted single-file backdate must still be reported.

func tsAgent(t *testing.T) *Agent {
	t.Helper()
	gcfg := govern.ForProfile(govern.ProfileFast)
	gcfg.Deadline = 0
	a, err := New(Config{
		Mode: "scan", Webroot: t.TempDir(), Home: t.TempDir(),
		Packs: []string{"core"}, Gov: gcfg,
		SkipDB: true, SkipOS: true, SkipNet: true, SkipProbe: true,
		SkipProvenance: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func tsFindings(a *Agent, ruleID string) []model.Finding {
	var out []model.Finding
	for _, f := range a.Report().Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// deployMetas reproduces the kinsta-mu-plugins shape: n files, one shared
// mtime from the package, one shared ctime from the extraction.
func deployMetas(n int, dir string) []fileMeta {
	mtime := time.Date(2026, 6, 25, 10, 19, 46, 0, time.UTC)
	ctime := time.Date(2026, 7, 7, 6, 29, 53, 0, time.UTC)
	out := make([]fileMeta, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fileMeta{
			rel:   dir + "/file" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".php",
			mtime: mtime, ctime: ctime, size: 1024,
		})
	}
	return out
}

func TestTimestompDeploymentCollapsesToOneFinding(t *testing.T) {
	a := tsAgent(t)
	a.detectTimestomps(deployMetas(40, "wp-content/mu-plugins/kinsta-mu-plugins/app"))

	if got := tsFindings(a, "fs.timestomp"); len(got) != 0 {
		t.Errorf("%d per-file timestomp findings for a single deployment", len(got))
	}
	bulk := tsFindings(a, "fs.timestomp_bulk")
	if len(bulk) != 1 {
		t.Fatalf("expected 1 bulk finding, got %d", len(bulk))
	}
	if bulk[0].Severity == model.SevHigh || bulk[0].Severity == model.SevCritical {
		t.Errorf("a deployment was reported at %s severity", bulk[0].Severity)
	}
	// Nothing may be hidden: every path must still be listed.
	paths, _ := bulk[0].Meta["paths"].([]string)
	if len(paths) != 40 {
		t.Errorf("bulk finding lists %d of 40 paths — evidence was dropped", len(paths))
	}
	if bulk[0].Path != "wp-content/mu-plugins/kinsta-mu-plugins/app" {
		t.Errorf("bulk finding path = %q, want the shared tree", bulk[0].Path)
	}
	t.Logf("collapsed 40 findings into: %s", bulk[0].Title)
}

// The detection must survive: a lone backdated file is the actual attack shape.
func TestTimestompSingleFileStillReported(t *testing.T) {
	a := tsAgent(t)
	a.detectTimestomps([]fileMeta{{
		rel:   "wp-content/uploads/2026/07/.hidden.php",
		mtime: time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
		ctime: time.Date(2026, 7, 7, 6, 29, 53, 0, time.UTC),
		size:  2048,
	}})

	got := tsFindings(a, "fs.timestomp")
	if len(got) != 1 {
		t.Fatalf("a single backdated file produced %d findings, want 1", len(got))
	}
	if got[0].Severity != model.SevHigh {
		t.Errorf("severity = %s, want high", got[0].Severity)
	}
}

// A handful of files below the cluster threshold stays per-file: an attacker
// dropping three shells must not benefit from being grouped.
func TestTimestompSmallGroupStaysPerFile(t *testing.T) {
	a := tsAgent(t)
	a.detectTimestomps(deployMetas(timestompClusterMin-1, "wp-content/plugins/acme"))

	if got := tsFindings(a, "fs.timestomp"); len(got) != timestompClusterMin-1 {
		t.Errorf("got %d per-file findings, want %d", len(got), timestompClusterMin-1)
	}
	if got := tsFindings(a, "fs.timestomp_bulk"); len(got) != 0 {
		t.Errorf("a sub-threshold group was collapsed: %d bulk findings", len(got))
	}
}

// Two separate operations must not merge into one verdict.
func TestTimestompDistinctOperationsStaySeparate(t *testing.T) {
	a := tsAgent(t)
	metas := deployMetas(10, "wp-content/mu-plugins/vendor-a")
	second := deployMetas(10, "wp-content/mu-plugins/vendor-b")
	later := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for i := range second {
		second[i].ctime = later
	}
	a.detectTimestomps(append(metas, second...))

	if got := tsFindings(a, "fs.timestomp_bulk"); len(got) != 2 {
		t.Errorf("two distinct operations produced %d findings, want 2", len(got))
	}
}

// Normal divergence is not reported at all.
func TestTimestompIgnoresOrdinaryDivergence(t *testing.T) {
	a := tsAgent(t)
	base := time.Date(2026, 7, 7, 6, 0, 0, 0, time.UTC)
	a.detectTimestomps([]fileMeta{
		{rel: "a.php", mtime: base, ctime: base.Add(time.Hour)},
		{rel: "b.php", mtime: base, ctime: base.Add(48 * time.Hour)},
	})
	if got := len(a.Report().Findings); got != 0 {
		t.Errorf("ordinary mtime/ctime skew produced %d findings", got)
	}
}

// Provenance exoneration applies here too: a file identical to its published
// release did not have its timestamps forged.
func TestTimestompExoneratesVerifiedFiles(t *testing.T) {
	a := tsAgent(t)
	metas := []fileMeta{{
		rel:   "wp-content/plugins/wp-crontrol/src/bootstrap.php",
		mtime: time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC),
		ctime: time.Date(2026, 7, 7, 6, 29, 53, 0, time.UTC),
	}}
	a.provVerifiedPaths.Store(metas[0].rel, struct{}{})
	a.detectTimestomps(metas)

	if got := len(a.Report().Findings); got != 0 {
		t.Errorf("a provenance-verified file was reported as timestomped (%d findings)", got)
	}
}

// A restore takes time. Four hyperdb drop-ins landed at 08:38:40 and a related
// drop-in six minutes earlier; bucketing on the exact ctime second split one
// 2021 migration into two separate "attacks", both below the cluster threshold.
func TestTimestompGroupsAcrossAWindow(t *testing.T) {
	a := tsAgent(t)
	mtime := time.Date(2018, 7, 18, 18, 25, 8, 0, time.UTC)
	base := time.Date(2021, 5, 16, 8, 32, 27, 0, time.UTC)
	metas := []fileMeta{
		{rel: "wp-content/db-error.php", mtime: mtime, ctime: base},
	}
	later := base.Add(6*time.Minute + 13*time.Second)
	for _, p := range []string{
		"wp-content/plugins/hyperdb/db.php",
		"wp-content/plugins/hyperdb/db-config.php",
		"wp-content/plugins/hyperdb-1-1/db.php",
		"wp-content/plugins/hyperdb-1-1/db-config.php",
	} {
		metas = append(metas, fileMeta{rel: p, mtime: mtime, ctime: later})
	}
	a.detectTimestomps(metas)

	if got := tsFindings(a, "fs.timestomp"); len(got) != 0 {
		t.Errorf("%d per-file findings: one restore was split by the second boundary", len(got))
	}
	bulk := tsFindings(a, "fs.timestomp_bulk")
	if len(bulk) != 1 {
		t.Fatalf("expected 1 grouped finding, got %d", len(bulk))
	}
	if n, _ := bulk[0].Meta["count"].(int); n != 5 {
		t.Errorf("grouped %v files, want 5", bulk[0].Meta["count"])
	}
}

// Operations genuinely far apart must not be merged by the window.
func TestTimestompWindowDoesNotMergeDistantOperations(t *testing.T) {
	a := tsAgent(t)
	mtime := time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	first := time.Date(2021, 5, 16, 8, 0, 0, 0, time.UTC)
	second := first.Add(3 * time.Hour)
	var metas []fileMeta
	for i := 0; i < 6; i++ {
		metas = append(metas,
			fileMeta{rel: fmt.Sprintf("wp-content/plugins/a/f%d.php", i), mtime: mtime, ctime: first},
			fileMeta{rel: fmt.Sprintf("wp-content/plugins/b/f%d.php", i), mtime: mtime, ctime: second})
	}
	a.detectTimestomps(metas)
	if got := tsFindings(a, "fs.timestomp_bulk"); len(got) != 2 {
		t.Errorf("got %d grouped findings, want 2 — a 3-hour gap is not one operation", len(got))
	}
}

// Application state is rewritten constantly; its timestamps carry no intent.
func TestTimestompIgnoresRuntimeState(t *testing.T) {
	a := tsAgent(t)
	a.detectTimestomps([]fileMeta{{
		rel:   "wp-content/wflogs/config.php",
		mtime: time.Date(2026, 8, 17, 16, 9, 10, 0, time.UTC),
		ctime: time.Date(2026, 8, 24, 17, 40, 34, 0, time.UTC),
	}})
	if got := len(a.Report().Findings); got != 0 {
		t.Errorf("Wordfence's own runtime log config was flagged (%d findings)", got)
	}
}

// But uploads/ must stay in scope: a backdated PHP file there is the classic
// shell drop, and excusing it would blind the check where it matters most.
func TestTimestompStillCoversUploads(t *testing.T) {
	a := tsAgent(t)
	a.detectTimestomps([]fileMeta{{
		rel:   "wp-content/uploads/2026/07/.x.php",
		mtime: time.Date(2019, 3, 3, 0, 0, 0, 0, time.UTC),
		ctime: time.Date(2026, 7, 7, 6, 29, 53, 0, time.UTC),
	}})
	if got := tsFindings(a, "fs.timestomp"); len(got) != 1 {
		t.Errorf("a backdated PHP file in uploads/ produced %d findings, want 1", len(got))
	}
}

func TestCommonDir(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{"same dir", []string{"a/b/x.php", "a/b/y.php"}, "a/b"},
		{"nested", []string{"a/b/c/x.php", "a/b/y.php"}, "a/b"},
		{"disjoint", []string{"a/x.php", "b/y.php"}, ""},
		{"single", []string{"a/b/c/x.php"}, "a/b/c"},
		{"root files", []string{"x.php", "y.php"}, "."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := commonDir(c.paths); got != c.want {
				t.Errorf("commonDir(%v) = %q, want %q", c.paths, got, c.want)
			}
		})
	}
}
