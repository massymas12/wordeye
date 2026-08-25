package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wordeye/internal/model"
)

// The filesystem sweep.
//
// The bash original ran roughly eight independent `grep -r` passes, each of
// which re-read every one of ~16k files. This walks the tree once, reads each
// candidate once, and evaluates the entire rule pack plus every heuristic
// against that single buffer. The result is the same coverage for about an
// eighth of the IO, which is also why it can afford to be polite about it.

// PHP-executable extensions. `inc` and `module` are included because handler
// config can make them execute, and attackers exploit exactly that assumption.
var phpExt = map[string]bool{
	"php": true, "phtml": true, "php3": true, "php4": true, "php5": true,
	"php6": true, "php7": true, "php8": true, "phps": true, "phar": true,
	"pht": true, "inc": true, "module": true,
}

// Text-ish files worth reading in full.
var textExt = map[string]bool{
	"js": true, "mjs": true, "cjs": true, "html": true, "htm": true,
	"xml": true, "json": true, "ini": true, "conf": true, "txt": true,
	"css": true, "svg": true, "md": true, "yml": true, "yaml": true,
	"sh": true, "bash": true, "py": true, "pl": true, "rb": true,
	"twig": true, "tpl": true, "htaccess": true, "user": true, "map": true,
}

// Binary/media formats: header-probed only, unless the probe finds PHP.
var binaryExt = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true, "ico": true,
	"bmp": true, "webp": true, "tiff": true, "woff": true, "woff2": true,
	"ttf": true, "eot": true, "otf": true, "mp3": true, "mp4": true,
	"avi": true, "mov": true, "webm": true, "zip": true, "gz": true,
	"tgz": true, "bz2": true, "xz": true, "7z": true, "rar": true,
	"wpress": true, "pdf": true, "psd": true, "swf": true, "bin": true,
	"dat": true, "sqlite": true, "db": true, "iso": true,
}

// Extensions that must never contain PHP source. A hit here is structural, not
// heuristic — a real PNG does not begin with "<?php".
var neverPHPExt = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true, "ico": true,
	"bmp": true, "webp": true, "svg": true, "css": true, "woff": true,
	"woff2": true, "ttf": true, "eot": true, "otf": true, "map": true,
}

// Directories that are never worth walking.
var alwaysSkipDir = map[string]bool{
	"node_modules": true, ".git": true, ".svn": true, ".hg": true,
	".idea": true, ".vscode": true,
}

// Directories dropped in Quick mode. These are the big, slow, low-yield trees:
// the malware families seen in practice hide in plugins/themes/mu-plugins.
var quickSkipDir = map[string]bool{
	"uploads": true, "cache": true, "ai1wm-backups": true, "updraft": true,
	"backups": true, "backup": true, "wpvividbackups": true, "dup-installer": true,
	// Language packs are thousands of .mo/.po files with no executable content.
	"languages": true, "lang": true,
}

// quickAnalyzable reports whether a file earns full analysis in Quick mode.
//
// Quick used to skip only large DIRECTORIES, which missed the point: a
// WordPress install is mostly non-executable files scattered through the trees
// it does walk — minified JS, CSS, JSON, .map, .po — and every one of them was
// being read in full and put through the lexer, heuristics and YARA. A field
// run walked past 8,000 files on a site with ~7,500 PHP files for exactly that
// reason.
//
// In Quick mode the question is narrowed to: can this file execute, or decide
// what executes? Everything else still gets a 1 KB header probe, so a script
// wearing a .css extension is still caught — that check never needed the whole
// file.
func quickAnalyzable(ext string) bool {
	if phpExt[ext] {
		return true
	}
	switch ext {
	case "htaccess", "user", "ini", "conf", "htpasswd":
		// Handler configuration decides what executes, so it matters as much
		// as code does.
		return true
	case "":
		// No extension at all: a favourite shape for droppers.
		return true
	}
	return false
}

type fileJob struct {
	abs  string
	rel  string
	info fs.FileInfo
}

// fileMeta feeds the post-walk mtime-clustering and runtime-write passes.
type fileMeta struct {
	rel   string
	dir   string
	mtime time.Time
	ctime time.Time
	size  int64
}

func (a *Agent) scanFilesystem(ctx context.Context) {
	a.timed("fs.scan", func() (model.CheckState, string) {
		root := a.cfg.Webroot
		if root == "" {
			return model.CheckUnavailable, "no webroot located"
		}
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			return model.CheckError, fmt.Sprintf("webroot %s unreadable", root)
		}

		var (
			filesSeen, filesRead, bytesRead, dirsSkipped, readErrors int64
			metaMu                                                   sync.Mutex
			metas                                                    []fileMeta
		)

		jobs := make(chan fileJob, 256)
		var wg sync.WaitGroup
		for i := 0; i < a.gov.Workers(); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Per-worker scratch, reused across files so the hot loop does
				// not allocate.
				hit := make([]bool, a.set.NumPatterns())
				buf := make([]byte, 0, 256<<10)
				sc := &heurScratch{}
				for j := range jobs {
					if ctx.Err() != nil {
						return
					}
					n, read, err := a.analyzeFile(ctx, j, hit, &buf, sc)
					if err != nil {
						atomic.AddInt64(&readErrors, 1)
					}
					if read {
						atomic.AddInt64(&filesRead, 1)
						atomic.AddInt64(&bytesRead, n)
						a.filesRead.Add(1)
						a.bytesRead.Add(n)
					}
					if isPHPPath(j.rel) {
						mt, ct, _ := fileTimes(j.info)
						metaMu.Lock()
						metas = append(metas, fileMeta{
							rel: j.rel, dir: path.Dir(j.rel),
							mtime: mt, ctime: ct, size: j.info.Size(),
						})
						metaMu.Unlock()
					}
				}
			}()
		}

		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				// A permission-denied subtree is a partial scan, not a clean
				// one. Record it so the verdict degrades honestly.
				a.rep.AddError(fmt.Sprintf("walk %s: %v", p, err))
				return nil
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			if d.IsDir() {
				if a.skipDir(rel, d.Name()) {
					atomic.AddInt64(&dirsSkipped, 1)
					return filepath.SkipDir
				}
				return nil
			}
			// Regular files only: following symlinks invites loops and lets a
			// link into /etc make the report lie about where a finding lives.
			if !d.Type().IsRegular() {
				return nil
			}
			atomic.AddInt64(&filesSeen, 1)
			a.filesSeen.Add(1)
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			select {
			case jobs <- fileJob{abs: p, rel: rel, info: info}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		close(jobs)
		wg.Wait()

		a.rep.Stats.FilesSeen = filesSeen
		a.rep.Stats.FilesRead = filesRead
		a.rep.Stats.BytesRead = bytesRead
		a.rep.Stats.DirsSkipped = dirsSkipped
		a.rep.Stats.FilesSkippedByType = a.filesSkippedType.Load()
		a.rep.Stats.ReadErrors = readErrors

		a.detectTimestomps(metas)
		a.emitWorldWritable()
		a.detectMtimeOutliers(metas)
		a.detectRuntimeWrites(metas)

		if walkErr != nil && ctx.Err() != nil {
			return model.CheckError, "scan interrupted: " + walkErr.Error()
		}
		return model.CheckOK, ""
	})
}

func (a *Agent) skipDir(rel, name string) bool {
	if alwaysSkipDir[name] {
		return true
	}
	if a.cfg.Quick && quickSkipDir[name] {
		return true
	}
	if a.set.Excluded("/" + rel + "/") {
		return true
	}
	return false
}

// analyzeFile is the per-file pipeline. It returns the number of bytes read and
// whether a read occurred, so the caller can keep statistics without the worker
// touching shared state.
func (a *Agent) analyzeFile(ctx context.Context, j fileJob, hit []bool, buf *[]byte, sc *heurScratch) (int64, bool, error) {
	started := time.Now()
	ext := extOf(j.rel)
	size := j.info.Size()

	// --- Content-free checks first. These cost a stat we already have. ------
	a.checkPathIndicators(j, ext)
	// Timestomping is judged after the sweep, in detectTimestomps: the verdict
	// depends on how many files share a ctime, which is not knowable per file.

	// --- Decide how much to read ------------------------------------------
	readFull := false
	switch {
	case a.cfg.Quick && !quickAnalyzable(ext):
		// Quick mode: non-executable file. A header probe still catches a
		// script wearing an asset extension, which is the only thing worth
		// knowing about a .css or a .map, and costs 1 KB instead of the whole
		// file plus the full analysis stack.
		readFull = false
		a.filesSkippedType.Add(1)
	case phpExt[ext] || textExt[ext]:
		readFull = true
	case binaryExt[ext]:
		readFull = false
	default:
		// Unknown or absent extension. Attackers like extensionless droppers,
		// so read these rather than trusting the name.
		readFull = size <= a.cfg.MaxFileSize
	}

	if !readFull {
		// Header AND tail probe.
		//
		// The head alone answers "is this file secretly a script", but it can
		// never answer "does this real image have a shell appended" — and that
		// is what a polyglot IS. An attacker keeps the media header valid so
		// upload filters that check magic bytes pass it, then appends the PHP
		// after the pixel data. Probing only the first kilobyte made the whole
		// fs.polyglot_file path unreachable for any image larger than 1KB; it
		// looked correct because the test fixtures were ~50-byte GIFs that fit
		// entirely inside the probe window.
		hdr, err := probeHeadAndTail(j.abs, size, 1024, 8<<10)
		if err != nil {
			return 0, false, err
		}
		if !containsPHPOpen(hdr) {
			return int64(len(hdr)), true, nil
		}
		// It is PHP wearing a media extension. Escalate to a full read.
		readFull = true
	}

	limit := size
	truncated := false
	if limit > a.cfg.MaxFileSize {
		limit = a.cfg.MaxFileSize
		truncated = true
	}
	if err := a.gov.Gate(ctx, limit); err != nil {
		return 0, false, err
	}

	content, err := readCapped(j.abs, limit, buf)
	if err != nil {
		return 0, false, err
	}

	// --- Provenance gate ---------------------------------------------------
	// A file byte-identical to its published release cannot be a web shell,
	// whatever primitives it contains. Checking this BEFORE the pattern engines
	// is what stops WordPress core — the densest concentration of
	// dangerous-looking calls on the system — from generating a wall of
	// critical false positives.
	tProv := time.Now()
	verdict := a.provenanceVerdict(j.rel, content, truncated, j.abs)
	a.nsProv.Add(int64(time.Since(tProv)))
	switch verdict {
	case provVerified:
		a.provVerified.Add(1)
		a.provVerifiedPaths.Store(j.rel, struct{}{})
		return int64(len(content)), true, nil
	case provAttested:
		// Estate consensus vouches for these bytes. Exonerate as with a
		// publisher manifest, but count it separately: the report must never
		// present fleet agreement as a publisher's word.
		a.provAttested.Add(1)
		a.vendorAttested.note(j.rel)
		a.provVerifiedPaths.Store(j.rel, struct{}{})
		return int64(len(content)), true, nil
	case provUnexpected:
		a.provUnexpected.Add(1)
		a.emitUnexpected(a.cfg.Webroot, j.rel)
		// Deliberately falls through: an undeployed file is exactly the one
		// worth characterising with every engine available.
	case provModified:
		a.provModified.Add(1)
		a.emitModified(a.cfg.Webroot, j.rel)
	default:
		a.provUncovered.Add(1)
	}

	clear(hit)
	t0 := time.Now()
	a.set.AC.MatchSet(content, hit)
	a.nsLex.Add(int64(time.Since(t0)))

	a.checkPolyglot(j, ext, content)

	// Point the shared lexer at this file. Nothing is lexed until an engine
	// actually asks for the code view.
	sc.beginFile(content, phpExt[ext])

	t0 = time.Now()
	a.evalRules(j, ext, size, content, hit, truncated, sc)
	a.evalIOCStrings(j, content, hit)
	a.nsRules.Add(int64(time.Since(t0)))

	// Budget check. Rules are cheap and bounded; the heuristic and YARA engines
	// are where a pathological file can run away, so the cut is made here.
	if time.Since(started) > perFileBudget {
		a.slowFiles.Add(1)
		return int64(len(content)), true, nil
	}

	t0 = time.Now()
	a.evalHeuristics(j, size, content, hit, sc)
	a.nsHeur.Add(int64(time.Since(t0)))

	if time.Since(started) > perFileBudget {
		a.slowFiles.Add(1)
		return int64(len(content)), true, nil
	}

	t0 = time.Now()
	// YARA sees the file with comments blanked. Its rules reason about PHP
	// behaviour, and a docblock naming a technique is not a use of it. String
	// literals are kept: shell banners and stored hashes are real evidence.
	a.evalYara(j, sc.lens.uncommented(), content, hit)
	a.nsYara.Add(int64(time.Since(t0)))

	return int64(len(content)), true, nil
}

// ---------------------------------------------------------------------------
// rule + heuristic evaluation
// ---------------------------------------------------------------------------

func (a *Agent) evalRules(j fileJob, ext string, size int64, content []byte, hit []bool, truncated bool, sc *heurScratch) {
	for _, r := range a.set.Rules {
		if !r.PathEligible(j.rel, ext, size) {
			continue
		}
		if !r.GatesFired(hit) {
			continue
		}
		// A rule that describes code is matched against the lexed view, so it
		// cannot fire on a comment or a translation string. Offsets are
		// preserved by blanking, so evidence still cites the real line. The lex
		// is deferred until a rule actually asks for it.
		var code []byte
		if r.NeedsCode() {
			code = sc.lens.subject()
		}
		ok, off := r.MatchContent(content, code)
		if !ok {
			continue
		}
		line, ev := snippet(content, off)
		f := a.fileFinding(j, content, truncated)
		f.RuleID = r.ID
		f.Class = r.Class
		f.Severity = model.Severity(r.Severity)
		f.Confidence = model.Confidence(r.Confidence)
		f.Title = r.Title
		f.Detail = r.Detail
		f.Remediation = r.Remediation
		f.Actionable = r.Actionable
		f.Line = line
		f.Evidence = ev
		if f.Meta == nil {
			f.Meta = map[string]any{}
		}
		f.Meta["pack"] = r.Pack()
		a.emit(f)
	}
}

func (a *Agent) evalHeuristics(j fileJob, size int64, content []byte, hit []bool, sc *heurScratch) {
	h := a.analyzeHeuristic(content, hit, size, j.rel, sc)
	if h == nil {
		return
	}
	f := a.fileFinding(j, content, false)
	f.RuleID = "fs.heuristic_webshell"
	f.Class = "SHELL"
	f.Severity = h.Severity
	// Heuristics never claim "confirmed" — that status gates automated action,
	// and no score should be able to authorise deleting a customer's file.
	f.Confidence = model.ConfLikely
	if h.Severity == model.SevMedium {
		f.Confidence = model.ConfReview
	}
	f.Title = fmt.Sprintf("Web-shell structure detected (score %d)", h.Score)
	f.Detail = "Structural indicators: " + strings.Join(h.Reasons, "; ")
	f.Remediation = "Read the file. Signature scanners miss repacked shells; this fired on structure, not on a known signature."
	f.Meta = map[string]any{
		"score":       h.Score,
		"reasons":     h.Reasons,
		"entropy":     h.Entropy,
		"encoded_run": h.B64Run,
		"tainted":     h.Tainted,
	}
	if len(h.Layers) > 0 {
		f.Meta["decoded_layers"] = len(h.Layers)
		f.Meta["decode_chain"] = summarizeLayers(h.Layers)
		// A decoded excerpt is worth more to an analyst than any score. Bounded
		// and inert: it is rendered as text, never executed or re-emitted.
		deepest := h.Layers[0]
		for _, x := range h.Layers {
			if x.Depth > deepest.Depth {
				deepest = x
			}
		}
		f.Meta["decoded_excerpt"] = truncate(string(deepest.Data), 600)
		f.Remediation = "The packed payload has been decoded; read decoded_excerpt in this finding's metadata rather than the file on disk."
	}
	a.emit(f)
}

func (a *Agent) evalIOCStrings(j fileJob, content []byte, hit []bool) {
	hits := a.set.IOCHits(hit)
	if len(hits) == 0 {
		return
	}
	f := a.fileFinding(j, content, false)
	f.RuleID = "fs.ioc_string"
	f.Class = "IOC"
	f.Severity = model.SevHigh
	f.Confidence = model.ConfLikely
	f.Title = "Incident IOC string present in file"
	f.Detail = "Matched indicators: " + strings.Join(hits, ", ")
	f.Remediation = "Correlate against the incident pack; confirm whether this file is attacker-authored or merely references the indicator."
	f.Meta = map[string]any{"iocs": hits}
	a.emit(f)
}

// ---------------------------------------------------------------------------
// content-free and structural checks
// ---------------------------------------------------------------------------

func (a *Agent) checkPathIndicators(j fileJob, ext string) {
	base := path.Base(j.rel)

	for _, name := range a.set.IOCs.Filenames {
		if strings.EqualFold(base, name) {
			f := a.fileFinding(j, nil, false)
			f.RuleID = "fs.ioc_filename"
			f.Class = "IOC"
			f.Severity = model.SevCritical
			f.Confidence = model.ConfConfirmed
			f.Actionable = true
			f.Title = "File matches a known attacker filename"
			f.Remediation = "Preserve as evidence, then quarantine."
			a.emit(f)
		}
	}
	for _, g := range a.set.IOCs.PathGlobs {
		if ok, _ := path.Match(g, j.rel); ok {
			f := a.fileFinding(j, nil, false)
			f.RuleID = "fs.ioc_path"
			f.Class = "IOC"
			f.Severity = model.SevCritical
			f.Confidence = model.ConfConfirmed
			f.Actionable = true
			f.Title = "File matches a known attacker drop path"
			f.Meta = map[string]any{"glob": g}
			a.emit(f)
		}
	}

	// Double extensions: image.php.jpg relies on a permissive handler to run a
	// file that does not look executable.
	//
	// The deception only exists when PHP is NOT the final extension. A file
	// ending .php is served as PHP because it IS PHP — nothing is concealed.
	// Without that condition this fired on scoper.inc.php and every other
	// name.inc.php in the ecosystem, since "inc" is itself a PHP extension.
	if parts := strings.Split(base, "."); len(parts) > 2 && !phpExt[ext] {
		for _, p := range parts[1 : len(parts)-1] {
			if !phpExt[strings.ToLower(p)] {
				continue
			}
			// The name alone is not evidence. This rule asserts the file WOULD
			// execute as PHP, and a file containing no PHP open tag cannot,
			// whatever the handler does with its extension.
			//
			// Without that check it fired on permalink-manager-setup-wizard.php.js,
			// a build artefact in a premium plugin — a naming convention common
			// enough that reporting it at high severity teaches an analyst to
			// skip the rule, which is worse than not having it.
			//
			// A header read is affordable here: only names with three or more
			// dot-separated parts reach this point.
			if !fileStartsWithPHP(j.abs) {
				break
			}
			f := a.fileFinding(j, nil, false)
			f.RuleID = "fs.double_extension"
			f.Class = "WP"
			f.Severity = model.SevHigh
			f.Confidence = model.ConfLikely
			f.Title = "PHP extension hidden mid-filename"
			f.Detail = "Filenames such as x.php.jpg execute as PHP under a misconfigured handler, " +
				"and this file contains PHP despite its non-executable extension."
			f.Remediation = "Inspect content and handler configuration for this directory."
			a.emit(f)
			break
		}
	}

	mode := j.info.Mode()
	// Permission-based checks are only meaningful where the OS reports real
	// POSIX bits. Elsewhere they are synthesized and would fire on everything.
	if permsMeaningful && phpExt[ext] && mode.Perm()&0o002 != 0 {
		// Accumulated, not emitted. See emitWorldWritable.
		a.ww.add(j.rel)
	}
	if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		f := a.fileFinding(j, nil, false)
		f.RuleID = "fs.setuid_binary"
		f.Class = "OSP"
		f.Severity = model.SevCritical
		f.Confidence = model.ConfLikely
		f.Title = "setuid/setgid file inside the webroot"
		f.Detail = "A privilege-escalation primitive has no legitimate reason to exist under a document root."
		a.emit(f)
	}
}

// timestompClusterMin is how many files must share one ctime second before the
// divergence is read as a single filesystem operation rather than as per-file
// forgery.
const timestompClusterMin = 5

// timestompClusterWindow is how far apart two ctimes may be and still count as
// one operation. Extracting an archive or restoring a backup takes time: a
// field run put four hyperdb drop-ins at 08:38:40 and a fifth related drop-in
// at 08:32:27, six minutes earlier in the same 2021 migration. Bucketing on the
// exact second split one restore into two "attacks".
const timestompClusterWindow = 15 * time.Minute

// detectTimestomps reports mtime/ctime divergence, but judges it per OPERATION
// rather than per file.
//
// The signal is real: mtime is forgeable from userspace, ctime is not, so a
// file whose mtime is much older than its ctime was written recently and made
// to look old. The mistake is treating each file as independent evidence.
//
// Extracting an archive, restoring a backup, or running chown -R over a tree
// sets ctime on every file at once while mtime keeps whatever the package
// carried. The result is dozens of files sharing ONE mtime and ONE ctime — the
// signature of a deployment, not of an attacker. A field run produced 79
// high-severity findings this way, essentially all of them one managed host's
// mu-plugin deploy, and that volume buries the handful of files that matter.
//
// Timestomping as an attack is targeted: an operator backdates the file they
// dropped so it blends into a directory listing. That is a small number of
// files, not a whole tree moving in lockstep.
//
// So clusters are collapsed into one finding that still names every path —
// suppressing nothing, while refusing to call a deployment an intrusion.
func (a *Agent) detectTimestomps(metas []fileMeta) {
	type candidate struct {
		rel          string
		mtime, ctime time.Time
	}
	var cands []candidate
	for _, m := range metas {
		if m.ctime.IsZero() || m.mtime.IsZero() {
			continue
		}
		// Ordinary operations (package installs, rsync, editors) leave ctime at
		// or just after mtime. A week of divergence is not explained by normal
		// use.
		if m.ctime.Sub(m.mtime) < 7*24*time.Hour {
			continue
		}
		// A file identical to its published release was not timestomped,
		// whatever its timestamps say.
		if _, ok := a.provVerifiedPaths.Load(m.rel); ok {
			continue
		}
		// Application state directories rewrite their own PHP data files as the
		// site runs, so timestamps there carry no intent — Wordfence's wflogs
		// config was reported as backdated on every scan for this reason.
		//
		// Deliberately NOT writableAtRuntime(): that list includes uploads/,
		// and a backdated PHP file under uploads is the classic shell drop.
		// Excusing the one tree where this signal matters most would be a
		// blind spot, not a fix.
		if runtimeStatePath(m.rel) {
			continue
		}
		cands = append(cands, candidate{m.rel, m.mtime, m.ctime})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ctime.Before(cands[j].ctime) })

	// Walk the sorted candidates, opening a new group whenever the next ctime
	// falls outside the current operation's window.
	var groups [][]candidate
	for i := 0; i < len(cands); {
		j := i + 1
		for j < len(cands) && cands[j].ctime.Sub(cands[i].ctime) <= timestompClusterWindow {
			j++
		}
		groups = append(groups, cands[i:j])
		i = j
	}

	for _, group := range groups {
		key := group[0].ctime.Unix()
		sort.Slice(group, func(i, j int) bool { return group[i].rel < group[j].rel })

		if len(group) < timestompClusterMin {
			for _, c := range group {
				a.emit(model.Finding{
					RuleID:     "fs.timestomp",
					Class:      "SHELL",
					Severity:   model.SevHigh,
					Confidence: model.ConfLikely,
					Title:      "Backdated modification time (timestomping)",
					Path:       c.rel,
					Detail: fmt.Sprintf(
						"mtime %s is %s older than ctime %s. mtime is forgeable from userspace, ctime is not — the file was written recently and deliberately made to look old.",
						c.mtime.UTC().Format(time.RFC3339),
						c.ctime.Sub(c.mtime).Round(time.Hour),
						c.ctime.UTC().Format(time.RFC3339)),
					Remediation: "Treat ctime as the true write time and pivot: what else was written in that window?",
				})
			}
			continue
		}

		// A cluster. Report it once, at a severity that reflects what it
		// almost certainly is, while still listing every path so nothing is
		// hidden from an analyst who wants to look.
		paths := make([]string, 0, len(group))
		for _, c := range group {
			paths = append(paths, c.rel)
		}
		root := commonDir(paths)
		if root == "" {
			root = "(multiple trees)"
		}
		a.emit(model.Finding{
			RuleID:     "fs.timestomp_bulk",
			Class:      "SHELL",
			Severity:   model.SevLow,
			Confidence: model.ConfReview,
			Title: fmt.Sprintf("%d files share one changed-time: a bulk filesystem operation",
				len(group)),
			Path: root,
			Detail: fmt.Sprintf(
				"%d files under %s have an mtime older than their ctime, but all share the ctime %s. "+
					"One inode-change timestamp across a whole tree is an archive extraction, a backup restore, "+
					"or a recursive chown — not per-file forgery, which is targeted by nature. "+
					"Reported once rather than %d times so it cannot bury a genuine single-file backdate.",
				len(group), root, time.Unix(key, 0).UTC().Format(time.RFC3339), len(group)),
			Remediation: "Confirm a deploy or restore happened at that time. If none did, treat the whole tree as written then and pivot on it.",
			Meta: map[string]any{
				"count": len(group),
				"ctime": time.Unix(key, 0).UTC().Format(time.RFC3339),
				"paths": paths,
			},
		})
	}
}

// commonDir returns the deepest directory prefix shared by every path.
func commonDir(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	parts := strings.Split(path.Dir(paths[0]), "/")
	for _, p := range paths[1:] {
		other := strings.Split(path.Dir(p), "/")
		n := len(parts)
		if len(other) < n {
			n = len(other)
		}
		i := 0
		for i < n && parts[i] == other[i] {
			i++
		}
		parts = parts[:i]
		if len(parts) == 0 {
			return ""
		}
	}
	return strings.Join(parts, "/")
}

// checkPolyglot separates "asset extension that is actually a script" from
// "real media file with PHP appended", because the two imply different attacker
// capabilities.
func (a *Agent) checkPolyglot(j fileJob, ext string, content []byte) {
	if !neverPHPExt[ext] {
		return
	}
	// What KIND of opening tag, and is anything behind it?
	//
	// This used to accept any of <?php, <?PHP or <?= as proof. The short-echo
	// tag is three bytes — 0x3C 0x3F 0x3D — and that sequence occurs by chance
	// in compressed binary often enough to matter: a field estate found it in
	// 102 of 15,274 genuine images, roughly 0.7%, and every one was reported as
	// a confirmed critical polyglot. In each case the bytes after the tag were
	// LZW pixel data, with no statements, no calls and no closing tag.
	//
	// So the tag alone is not evidence. What follows it must actually look like
	// source, and a five-byte <?php is treated as far stronger than a
	// three-byte <?= because the longer sequence is vanishingly unlikely to
	// arise by coincidence.
	kind, off := findPHPTag(content)
	if kind == phpTagNone {
		return
	}
	realPayload := phpPayloadIsReal(content, off)
	if kind == phpTagShort && !realPayload {
		// Three bytes of binary coincidence. Reporting this trains an analyst
		// to disbelieve the rule, which costs more than the rule catches.
		return
	}
	// Trim leading whitespace and a UTF-8 BOM: droppers are frequently saved by
	// an editor that prepends one, and it must not hide the opening tag.
	head := bytes.TrimLeft(content[:minInt(64, len(content))], " \t\r\n\uFEFF")
	startsPHP := bytes.HasPrefix(head, []byte("<?"))
	validMagic := hasValidMagic(ext, content)

	f := a.fileFinding(j, content, false)
	f.Class = "SHELL"
	switch {
	case startsPHP && !validMagic:
		f.RuleID = "fs.fake_extension_shell"
		f.Severity = model.SevCritical
		f.Confidence = model.ConfConfirmed
		f.Title = "Script disguised with an asset extension"
		f.Detail = "File carries a media/asset extension but its content is PHP source with no valid file-format header."
		f.Remediation = "Quarantine. Then find the upload path or handler that let it be written."
		// Deliberately not auto-actionable on its own: some legitimate
		// recovery tools ship a .txt containing PHP to be renamed by hand.
		// Escalated below only when malware markers are also present.
		f.Actionable = false
	case validMagic:
		f.RuleID = "fs.polyglot_file"
		f.Title = "Polyglot: valid media header with embedded PHP"
		f.Detail = "The file passes image-type validation yet contains PHP source, which is how upload filters that check magic bytes get bypassed."
		f.Remediation = "Quarantine and deny PHP execution for this directory."

		// Confidence tracks exploitability, not just presence.
		//
		// A .gif is not executed by the web server without an AddHandler
		// directive or a local-file-include reaching it, so even a genuine
		// embedded tag here is inert on its own. Calling that "confirmed
		// critical" overstates what is known and buries findings that are
		// directly reachable.
		switch {
		case kind == phpTagFull && hasMalwareMarker(content):
			// A full tag AND malware vocabulary: this was put there on purpose.
			f.Severity = model.SevCritical
			f.Confidence = model.ConfConfirmed
			f.Actionable = true
		case kind == phpTagFull:
			f.Severity = model.SevHigh
			f.Confidence = model.ConfLikely
			f.Actionable = false
			f.Detail += " The embedded code is inert unless this directory executes PHP, so check the handler configuration before treating it as live."
		default:
			// Short tag with a payload that at least parses like source.
			// Possible, but weak enough that it must not lead the queue.
			f.Severity = model.SevMedium
			f.Confidence = model.ConfReview
			f.Actionable = false
			f.Detail += " Evidence is a short-echo tag (<?=), a three-byte sequence that also occurs by chance in compressed media; confirm by reading the file before acting."
		}
	default:
		f.RuleID = "fs.asset_contains_php"
		f.Severity = model.SevHigh
		f.Confidence = model.ConfLikely
		f.Title = "Asset file contains PHP source"
	}

	// Escalate to actionable only when the disguise is paired with malware
	// vocabulary, which is what distinguishes a shell from a rename-to-run
	// recovery file shipped by a legitimate plugin.
	if f.RuleID == "fs.fake_extension_shell" && hasMalwareMarker(content) {
		f.Actionable = true
		f.Detail += " Obfuscation/execution markers present."
	}
	a.emit(f)
}

// detectMtimeOutliers finds files written long after their neighbours.
//
// Plugin and theme directories are installed as a unit, so their files share an
// mtime cluster. A single PHP file months newer than its ~50 siblings is a
// dropper. Crucially this fires on files with no malicious content at all —
// loaders, stagers, and files whose payload is fetched at runtime.
func (a *Agent) detectMtimeOutliers(metas []fileMeta) {
	byDir := map[string][]fileMeta{}
	for _, m := range metas {
		// Only vendored trees have a meaningful install-time cluster.
		if !strings.Contains(m.dir, "wp-content/plugins/") &&
			!strings.Contains(m.dir, "wp-content/themes/") &&
			!strings.Contains(m.dir, "wp-includes") &&
			!strings.Contains(m.dir, "wp-admin") {
			continue
		}
		byDir[m.dir] = append(byDir[m.dir], m)
	}

	const minSiblings = 6
	const gap = 30 * 24 * time.Hour

	for dir, files := range byDir {
		if len(files) < minSiblings {
			continue
		}
		times := make([]time.Time, len(files))
		for i, f := range files {
			times[i] = f.mtime
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		median := times[len(times)/2]

		var outliers []fileMeta
		for _, f := range files {
			if f.mtime.Sub(median) > gap {
				outliers = append(outliers, f)
			}
		}
		// A genuine plugin update rewrites most of the directory. Only a small
		// minority standing apart looks like an intrusion.
		if len(outliers) == 0 || len(outliers) > len(files)/3 {
			continue
		}
		for _, o := range outliers {
			fi, err := os.Stat(filepath.Join(a.cfg.Webroot, filepath.FromSlash(o.rel)))
			if err != nil {
				continue
			}
			f := a.fileFinding(fileJob{
				abs: filepath.Join(a.cfg.Webroot, filepath.FromSlash(o.rel)), rel: o.rel, info: fi,
			}, nil, false)
			f.RuleID = "fs.mtime_outlier"
			f.Class = "SHELL"
			f.Severity = model.SevMedium
			f.Confidence = model.ConfReview
			f.Title = "File written long after the rest of its directory"
			f.Detail = fmt.Sprintf(
				"Modified %s, but the other %d PHP files in %s cluster around %s. Package installs share an mtime; a lone newer file is often a dropper.",
				o.mtime.UTC().Format("2006-01-02"), len(files)-len(outliers), dir, median.UTC().Format("2006-01-02"))
			f.Remediation = "Compare against the official plugin/theme package for this version."
			f.Meta = map[string]any{"dir_median_mtime": median.UTC(), "siblings": len(files)}
			a.emit(f)
		}
	}
}

// ---------------------------------------------------------------------------
// IO helpers
// ---------------------------------------------------------------------------

func readHead(p string, n int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	r, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:r], nil
}

// readCapped reads up to limit bytes into the worker's reusable buffer.
func readCapped(p string, limit int64, buf *[]byte) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if int64(cap(*buf)) < limit {
		*buf = make([]byte, limit)
	}
	b := (*buf)[:limit]
	n, err := io.ReadFull(f, b)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return b[:n], nil
}

func hashFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fileFinding pre-populates the file metadata common to every path-based
// finding. When the full content is already in hand and untruncated, the digest
// is taken from it rather than re-reading the file.
func (a *Agent) fileFinding(j fileJob, content []byte, truncated bool) model.Finding {
	mtime, ctime, _ := fileTimes(j.info)
	f := model.Finding{
		Path:    j.rel,
		Size:    j.info.Size(),
		Mode:    j.info.Mode().String(),
		ModTime: &mtime,
	}
	if !ctime.IsZero() {
		f.CTime = &ctime
	}
	if content != nil && !truncated && int64(len(content)) == j.info.Size() {
		sum := sha256.Sum256(content)
		f.SHA256 = hex.EncodeToString(sum[:])
	} else {
		f.SHA256 = hashFile(j.abs)
	}
	return f
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func extOf(p string) string {
	base := path.Base(p)
	// Dotfiles such as .htaccess and .user.ini have no conventional extension;
	// treat the name itself as the extension so rules can target them.
	if strings.HasPrefix(base, ".") && strings.Count(base, ".") == 1 {
		return strings.ToLower(base[1:])
	}
	e := path.Ext(base)
	return strings.ToLower(strings.TrimPrefix(e, "."))
}

func isPHPPath(rel string) bool { return phpExt[extOf(rel)] }

func containsPHPOpen(b []byte) bool {
	return bytes.Contains(b, []byte("<?php")) || bytes.Contains(b, []byte("<?=")) ||
		bytes.Contains(b, []byte("<?PHP"))
}

func hasMalwareMarker(b []byte) bool {
	lower := bytes.ToLower(b)
	for _, m := range [][]byte{
		[]byte("eval"), []byte("base64_decode"), []byte("gzinflate"),
		[]byte("str_rot13"), []byte("shell_exec"), []byte("passthru"),
		[]byte("proc_open"), []byte("system("), []byte("assert("),
		[]byte("create_function"), []byte("move_uploaded_file"),
	} {
		if bytes.Contains(lower, m) {
			return true
		}
	}
	return false
}

// hasValidMagic reports whether the bytes actually begin with the file format
// the extension advertises.
func hasValidMagic(ext string, b []byte) bool {
	if len(b) < 8 {
		return false
	}
	switch ext {
	case "png":
		return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n"))
	case "jpg", "jpeg":
		return bytes.HasPrefix(b, []byte("\xff\xd8\xff"))
	case "gif":
		return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
	case "bmp":
		return bytes.HasPrefix(b, []byte("BM"))
	case "ico":
		return bytes.HasPrefix(b, []byte("\x00\x00\x01\x00"))
	case "webp":
		return bytes.HasPrefix(b, []byte("RIFF")) && len(b) > 12 && bytes.Equal(b[8:12], []byte("WEBP"))
	case "woff":
		return bytes.HasPrefix(b, []byte("wOFF"))
	case "woff2":
		return bytes.HasPrefix(b, []byte("wOF2"))
	case "ttf", "otf":
		return bytes.HasPrefix(b, []byte("\x00\x01\x00\x00")) ||
			bytes.HasPrefix(b, []byte("OTTO")) || bytes.HasPrefix(b, []byte("true"))
	}
	return false
}

// snippet renders a one-line, length-bounded evidence excerpt around an offset.
// Long encoded blobs are elided so a report never carries a live payload.
func snippet(content []byte, off int) (int, string) {
	if off < 0 || off >= len(content) {
		return 0, ""
	}
	line := 1 + bytes.Count(content[:off], []byte{'\n'})

	start := bytes.LastIndexByte(content[:off], '\n') + 1
	end := off
	if i := bytes.IndexByte(content[off:], '\n'); i >= 0 {
		end = off + i
	} else {
		end = len(content)
	}
	if end-start > 400 {
		// Centre the window on the match rather than truncating from the left.
		s := off - 120
		if s < start {
			s = start
		}
		e := s + 400
		if e > end {
			e = end
		}
		start, end = s, e
	}
	text := strings.TrimSpace(string(content[start:end]))

	// Elide any long encoded run so the evidence field stays inert and short.
	if o, l := longestEncodedRun([]byte(text)); l > 80 {
		text = text[:o] + fmt.Sprintf("<%d bytes elided>", l) + text[minInt(o+l, len(text)):]
	}
	if len(text) > 400 {
		text = text[:400] + "…"
	}
	return line, text
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// evalYara runs the YARA ruleset against the same buffer every other engine
// already examined.
//
// The gate closure answers "does any of this rule's literal strings appear in
// the file?" from the prefilter automaton results, at no extra IO or scanning
// cost. Rules the engine judged non-prefilterable (hex patterns, regex strings,
// negated conditions) bypass the gate and are always evaluated, so gating can
// never cause a rule to silently miss.
// subject is what the rules are matched against (comments blanked for PHP);
// content is the original file, used for evidence and hashing.
func (a *Agent) evalYara(j fileJob, subject, content []byte, hit []bool) {
	if a.yara == nil {
		return
	}
	gate := func(literals []string) bool {
		for _, l := range literals {
			if id, ok := a.yaraLit[l]; ok && id >= 0 && id < len(hit) && hit[id] {
				return true
			}
		}
		return false
	}

	for _, m := range a.yara.Scan(subject, j.info.Size(), gate) {
		f := a.fileFinding(j, content, false)
		f.RuleID = "yara." + m.Rule.Name
		f.Class = "YARA"
		f.Severity = model.Severity(m.Rule.Severity())
		// YARA matches are pattern matches, not proofs. They inform an analyst
		// and are never eligible for automated quarantine.
		f.Confidence = model.ConfLikely

		// A plugin's own test suite is the single largest source of
		// authentication false positives, and for a structural reason: test
		// fixtures exist to simulate privileged states, so they legitimately
		// call wp_set_auth_cookie and wp_set_current_user beside request
		// superglobals. An 18-host estate reported 31 criticals from this, 30
		// of them five files in one plugin's tests/ directory.
		//
		// They are downgraded rather than suppressed. A shell dropped into a
		// tests/ directory is still served over HTTP and still executes, so
		// silence would be wrong; but a fixture that has never been reachable
		// from a route does not warrant the same severity as a backdoor in a
		// loaded file, and burying five real criticals under thirty fixtures
		// costs more than it catches.
		if isTestFixture(j.rel) {
			f.Severity = downgrade(f.Severity)
			f.Confidence = model.ConfReview
			f.Detail += " — this file is part of a test suite, which routinely " +
				"simulates privileged state; verify it is the vendor's own fixture and is not web-reachable."
		}
		f.Title = "YARA: " + m.Rule.Name
		f.Detail = m.Rule.Description()
		if f.Detail == "" {
			f.Detail = "Matched YARA rule " + m.Rule.Name
		}
		if len(m.Strings) > 0 {
			f.Detail += " (matched " + strings.Join(m.Strings, ", ") + ")"
		}
		f.Remediation = "Review the file. Correlate with the heuristic score and the file's location before acting."
		f.Meta = map[string]any{
			"yara_rule": m.Rule.Name,
			"ruleset":   m.Rule.Origin,
			"tags":      m.Rule.Tags,
			"strings":   m.Strings,
		}
		a.emit(f)
	}
}

// Directories where writes at runtime are entirely normal, so a recent write
// there proves nothing.
// runtimeStatePath reports whether a path is application STATE that the site
// rewrites as it runs — caches, logs, config a plugin persists as PHP.
//
// It is deliberately narrower than writableAtRuntime: uploads/ and backups/ are
// absent, because those are where dropped code lands. The distinction matters
// for timestomping, where the question is whether the file's timestamps were
// written by the application or forged by someone.
func runtimeStatePath(rel string) bool {
	for _, d := range []string{
		"wp-content/wflogs/", "wp-content/cache/", "wp-content/et-cache/",
		"wp-content/w3tc-config/", "wp-content/upgrade/",
	} {
		if strings.Contains(rel, d) {
			return true
		}
	}
	return false
}

func writableAtRuntime(rel string) bool {
	for _, d := range []string{
		"wp-content/uploads/", "wp-content/cache/", "wp-content/upgrade/",
		"wp-content/backups/", "wp-content/ai1wm-backups/", "wp-content/w3tc-config/",
		"wp-content/et-cache/", "wp-content/wflogs/", "wp-content/debug.log",
	} {
		if strings.Contains(rel, d) {
			return true
		}
	}
	return false
}

// detectRuntimeWrites finds code written AFTER this container started.
//
// This is the one detection that works BETTER in a container than on a VPS. A
// container is built from an image: every file in it has a build-time
// timestamp, and the namespace's PID 1 start time is effectively the deploy
// time. Executable code whose inode changed after that point was therefore not
// deployed — it was written while the site was running.
//
// It needs no privilege, no baseline, and no signature, which makes it the
// strongest tool available in exactly the environment where the OS-level checks
// are weakest.
//
// Two honest caveats, both stated in the finding: sites that update plugins
// through wp-admin write code at runtime legitimately, and hosts that mount
// wp-content from a persistent volume keep timestamps across restarts. So this
// is review-grade evidence, weighted by how MANY files moved — a lone new file
// in an otherwise static tree is interesting; four hundred is a plugin update.
func (a *Agent) detectRuntimeWrites(metas []fileMeta) {
	if a.env == nil || !a.env.Contained || a.env.StartedAt.IsZero() {
		return
	}
	// Allow for entrypoint scripts and the first moments of boot.
	cutoff := a.env.StartedAt.Add(90 * time.Second)

	var late []fileMeta
	for _, m := range metas {
		if writableAtRuntime(m.rel) {
			continue
		}
		// ctime is the inode change time and cannot be forged from userspace;
		// fall back to mtime only where ctime is unavailable.
		ref := m.ctime
		if ref.IsZero() {
			ref = m.mtime
		}
		if ref.After(cutoff) {
			late = append(late, m)
		}
	}
	if len(late) == 0 {
		return
	}

	// A bulk rewrite is a deploy or an update, not an intrusion. Report it once
	// rather than emitting hundreds of findings that bury everything else.
	if len(late) > 50 {
		a.emit(model.Finding{
			RuleID:     "fs.bulk_runtime_write",
			Class:      "WP",
			Severity:   model.SevLow,
			Confidence: model.ConfReview,
			Title:      fmt.Sprintf("%d code files written after this container started", len(late)),
			Detail: fmt.Sprintf(
				"Container started %s; these files changed afterwards. At this volume the usual cause is a "+
					"plugin/theme update or an in-place deploy rather than an intrusion.",
				a.env.StartedAt.UTC().Format(time.RFC3339)),
			Remediation: "Confirm an update or deploy happened in this window. If none did, treat every file as suspect.",
			Meta:        map[string]any{"count": len(late), "container_started": a.env.StartedAt.UTC()},
		})
		return
	}

	for _, m := range late {
		abs := filepath.Join(a.cfg.Webroot, filepath.FromSlash(m.rel))
		fi, err := os.Stat(abs)
		if err != nil {
			continue
		}
		f := a.fileFinding(fileJob{abs: abs, rel: m.rel, info: fi}, nil, false)
		f.RuleID = "fs.written_after_deploy"
		f.Class = "WP"
		f.Severity = model.SevMedium
		f.Confidence = model.ConfReview
		f.Title = "Executable code written after the container started"
		f.Detail = fmt.Sprintf(
			"Container started %s; this file's inode changed %s, so it was not part of the deployed image. "+
				"In an immutable deployment nothing under plugins/themes/core should change at runtime.",
			a.env.StartedAt.UTC().Format(time.RFC3339), m.ctime.UTC().Format(time.RFC3339))
		f.Remediation = "Compare against the vendor package. Legitimate causes are a wp-admin plugin update or a persistent volume; " +
			"neither applies to WordPress core files."
		f.Meta = map[string]any{
			"container_started": a.env.StartedAt.UTC(),
			"peers_also_late":   len(late),
		}
		a.emit(f)
	}
}

// fileStartsWithPHP reports whether a file's opening bytes contain a PHP open
// tag. Used to require evidence before claiming a filename conceals executable
// code; a bounded header read, never the whole file.
func fileStartsWithPHP(abs string) bool {
	f, err := os.Open(abs)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [512]byte
	n, _ := io.ReadFull(f, hdr[:])
	if n <= 0 {
		return false
	}
	return containsPHPOpen(hdr[:n])
}

// isTestFixture reports whether a path is part of a package's own test suite.
//
// Matching is deliberately conservative: the directory must be a recognised
// test root, or the filename must follow a test-class convention. "test" as a
// substring is not enough — wp-content/plugins/latest-posts/ is not a test.
func isTestFixture(rel string) bool {
	rel = strings.ToLower(filepath.ToSlash(rel))
	for _, d := range []string{"/tests/", "/test/", "/phpunit/", "/spec/", "/__tests__/", "/testing/"} {
		if strings.Contains(rel, d) {
			return true
		}
	}
	base := path.Base(rel)
	switch {
	case strings.HasPrefix(base, "class-tests-"), strings.HasPrefix(base, "test-"),
		strings.HasSuffix(base, "-test.php"), strings.HasSuffix(base, "_test.php"):
		return true
	}
	// A bare "ends with test.php" case used to live here. It matched
	// latest.php, greatest.php and protest.php — ordinary names, and worse,
	// attacker-chosen ones: naming a shell wp-content/uploads/latest.php earned
	// it an automatic severity downgrade and the misleading detail "this file is
	// part of a test suite". A separator before "test" is what makes it a test.
	return false
}

// downgrade lowers a severity by one step. Used where context weakens a finding
// without invalidating it.
func downgrade(s model.Severity) model.Severity {
	switch s {
	case model.SevCritical:
		return model.SevHigh
	case model.SevHigh:
		return model.SevMedium
	case model.SevMedium:
		return model.SevLow
	default:
		return s
	}
}

// PHP opening tags, graded by how much evidence they actually constitute.
type phpTagKind int

const (
	phpTagNone  phpTagKind = iota
	phpTagShort            // <?= — three bytes, occurs by chance in binary
	phpTagFull             // <?php — five bytes, effectively never by chance
)

// findPHPTag returns the strongest opening tag in b and where it starts.
//
// Strength matters because the two tags are not equally informative. <?php is
// five bytes and its appearance in compressed image data is vanishingly
// unlikely; <?= is three bytes (0x3C 0x3F 0x3D) and appeared in 102 of 15,274
// genuine images on one field host — about 0.7%, exactly the rate a random
// three-byte sequence predicts.
func findPHPTag(b []byte) (phpTagKind, int) {
	if i := bytes.Index(b, []byte("<?php")); i >= 0 {
		return phpTagFull, i + len("<?php")
	}
	if i := bytes.Index(b, []byte("<?PHP")); i >= 0 {
		return phpTagFull, i + len("<?PHP")
	}
	if i := bytes.Index(b, []byte("<?=")); i >= 0 {
		return phpTagShort, i + len("<?=")
	}
	return phpTagNone, 0
}

// phpPayloadIsReal reports whether the bytes after an opening tag look like
// source rather than the binary that happened to precede them.
//
// Two conditions, both cheap. The window must be overwhelmingly printable —
// LZW output is not — and it must contain something PHP actually does: a
// variable, a call, or a statement terminator. A tag followed by pixel data
// satisfies neither.
func phpPayloadIsReal(b []byte, off int) bool {
	if off >= len(b) {
		return false
	}
	win := b[off:]
	if len(win) > 512 {
		win = win[:512]
	}
	// A close tag bounds the payload; its presence is itself corroboration.
	closed := false
	if i := bytes.Index(win, []byte("?>")); i >= 0 {
		win, closed = win[:i], true
	}
	if len(win) < 3 {
		return closed // "<?= ?>" is degenerate but syntactically real
	}

	printable := 0
	for _, c := range win {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	if float64(printable)/float64(len(win)) < 0.90 {
		return false
	}
	// Printable noise is still noise. Require a construct.
	for _, tok := range [][]byte{
		[]byte("$"), []byte(";"), []byte("("),
		[]byte("echo"), []byte("print"), []byte("return"),
		[]byte("if"), []byte("function"), []byte("include"), []byte("require"),
	} {
		if bytes.Contains(win, tok) {
			return true
		}
	}
	return false
}

// probeHeadAndTail reads the first head bytes and the last tail bytes of a
// file, concatenated.
//
// Reading only the head is what made polyglot detection unreachable: a real
// image with a shell appended keeps a valid header for the whole probe window,
// so the scan concluded "ordinary media" and returned before any engine ran.
// Appending is how polyglots are built, so the tail is where the evidence is.
//
// The two windows are returned joined rather than separately because every
// caller asks the same question of them — does a PHP open tag appear anywhere
// in what we looked at — and a seam between two reads cannot split a five-byte
// tag when each window is kilobytes wide.
func probeHeadAndTail(path string, size int64, head, tail int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if size <= head+tail {
		// Small enough to read whole; no seam, no double-counting.
		b := make([]byte, size)
		n, err := io.ReadFull(f, b)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return b[:n], nil
	}

	out := make([]byte, 0, head+tail)
	hb := make([]byte, head)
	n, err := io.ReadFull(f, hb)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	out = append(out, hb[:n]...)

	if _, err := f.Seek(size-tail, io.SeekStart); err != nil {
		return out, nil // head alone is still worth something
	}
	tb := make([]byte, tail)
	n, err = io.ReadFull(f, tb)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return out, nil
	}
	return append(out, tb[:n]...), nil
}
