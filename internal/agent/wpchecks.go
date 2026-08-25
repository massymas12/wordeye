package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wordeye/internal/model"
)

// WordPress-structure checks.
//
// These target the places where WordPress's own loading order works against
// the defender. A security plugin is just a plugin: it initialises late, so
// anything that loads earlier is invisible to it. That ordering is why the
// drop-in surface below is the single most valuable non-signature check in this
// file, and why Wordfence structurally cannot cover it.

// dropIn describes a WordPress drop-in and when it loads.
type dropIn struct {
	name     string
	loadedAt string
	severity model.Severity
}

// Ordered roughly by how early they load — earlier means more dangerous.
var dropIns = []dropIn{
	{"db.php", "before WordPress initialises anything else, including every plugin", model.SevHigh},
	{"object-cache.php", "during bootstrap, ahead of all plugins", model.SevHigh},
	{"advanced-cache.php", "during bootstrap when WP_CACHE is set, ahead of all plugins", model.SevHigh},
	{"sunrise.php", "during multisite bootstrap, ahead of all plugins", model.SevHigh},
	{"maintenance.php", "when the site is in maintenance mode", model.SevMedium},
	{"install.php", "during installation", model.SevMedium},
	{"db-error.php", "on a database error", model.SevMedium},
	{"php-error.php", "on a fatal PHP error", model.SevMedium},
	{"fatal-error-handler.php", "on a fatal error, before recovery mode", model.SevMedium},
	{"blog-deleted.php", "when a multisite blog is deleted", model.SevLow},
}

func (a *Agent) checkWordPress(ctx context.Context) {
	root := a.cfg.Webroot
	if root == "" {
		a.rep.AddCheck(model.CheckStatus{ID: "wp.structure", State: model.CheckUnavailable, Reason: "no webroot"})
		return
	}

	a.timed("wp.dropins", func() (model.CheckState, string) {
		a.checkDropIns(root)
		return model.CheckOK, ""
	})
	a.timed("wp.muplugins", func() (model.CheckState, string) {
		return a.checkMuPlugins(root)
	})
	a.timed("wp.config", func() (model.CheckState, string) {
		return a.checkWPConfig(root)
	})
	a.timed("wp.index", func() (model.CheckState, string) {
		return a.checkIndexPHP(root)
	})
	a.timed("wp.uploads_exec", func() (model.CheckState, string) {
		a.checkUploadsHardening(root)
		return model.CheckOK, ""
	})
}

// checkDropIns inventories wp-content drop-ins. Presence alone is reported at
// info level because several are legitimate (Redis object caches, W3TC), but
// the report always names them: an operator who does not recognise a drop-in on
// their own site has found something.
func (a *Agent) checkDropIns(root string) {
	for _, d := range dropIns {
		p := filepath.Join(root, "wp-content", d.name)
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		rel := "wp-content/" + d.name
		j := fileJob{abs: p, rel: rel, info: fi}

		content, rerr := readHead(p, 512<<10)
		malicious := rerr == nil && hasMalwareMarker(content) && looksLikeCodeExec(content)

		f := a.fileFinding(j, nil, false)
		f.Class = "WP"
		f.Meta = map[string]any{"loads_at": d.loadedAt}
		if malicious {
			f.RuleID = "wp.dropin_trojanized"
			f.Severity = model.SevCritical
			f.Confidence = model.ConfLikely
			f.Title = fmt.Sprintf("Drop-in %s contains code-execution markers", d.name)
			f.Detail = fmt.Sprintf(
				"%s loads %s. Malicious code here runs ahead of every security plugin, so it can disable or hide from them.",
				d.name, d.loadedAt)
			f.Remediation = "Compare against the drop-in shipped by whichever caching/database plugin claims it. If no plugin claims it, quarantine."
		} else {
			f.RuleID = "wp.dropin_present"
			f.Severity = model.SevInfo
			f.Confidence = model.ConfReview
			f.Title = fmt.Sprintf("Drop-in present: %s", d.name)
			f.Detail = fmt.Sprintf("Loads %s. Legitimate when installed by a caching or database plugin.", d.loadedAt)
			f.Remediation = "Confirm a known plugin owns this file. An unclaimed drop-in is a backdoor with a very good hiding place."
		}
		a.emit(f)
	}
}

// checkMuPlugins inventories must-use plugins. Every PHP file directly inside
// mu-plugins/ is loaded automatically, cannot be deactivated from the admin UI,
// and is not listed on the normal Plugins screen.
func (a *Agent) checkMuPlugins(root string) (model.CheckState, string) {
	dir := filepath.Join(root, "wp-content", "mu-plugins")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return model.CheckOK, "no mu-plugins directory"
		}
		return model.CheckError, err.Error()
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".php") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(dir, e.Name())
		rel := "wp-content/mu-plugins/" + e.Name()
		content, _ := readHead(p, 512<<10)

		f := a.fileFinding(fileJob{abs: p, rel: rel, info: fi}, nil, false)
		f.Class = "WP"
		f.Meta = map[string]any{"autoloaded": true}
		if hasMalwareMarker(content) && looksLikeCodeExec(content) {
			f.RuleID = "wp.muplugin_suspicious"
			f.Severity = model.SevCritical
			f.Confidence = model.ConfLikely
			f.Title = "Must-use plugin contains code-execution markers"
			f.Detail = "Files in mu-plugins load on every request, cannot be deactivated from the admin UI, and do not appear on the Plugins screen."
			f.Remediation = "Identify which plugin installed it. Unclaimed mu-plugins should be quarantined."
		} else {
			f.RuleID = "wp.muplugin_present"
			f.Severity = model.SevInfo
			f.Confidence = model.ConfReview
			f.Title = "Must-use plugin: " + e.Name()
			f.Detail = "Auto-loaded on every request and hidden from the Plugins screen."
			f.Remediation = "Confirm this is expected on this site."
		}
		a.emit(f)
	}
	return model.CheckOK, ""
}

// checkWPConfig looks for code appended to wp-config.php. Because wp-config is
// included before the rest of WordPress and is edited by hand during normal
// operations, it is an attractive and easily overlooked persistence point.
func (a *Agent) checkWPConfig(root string) (model.CheckState, string) {
	p, ok := findWPConfig(root)
	if !ok {
		return model.CheckUnavailable, "wp-config.php not found"
	}
	fi, err := os.Stat(p)
	if err != nil {
		return model.CheckError, err.Error()
	}
	content, err := readHead(p, 1<<20)
	if err != nil {
		return model.CheckError, err.Error()
	}

	rel, _ := filepath.Rel(root, p)
	rel = filepath.ToSlash(rel)
	j := fileJob{abs: p, rel: rel, info: fi}

	// Anything after the wp-settings.php require is appended code. WordPress
	// itself puts nothing there.
	if idx := bytes.Index(content, []byte("wp-settings.php")); idx >= 0 {
		tail := content[idx:]
		if nl := bytes.IndexByte(tail, '\n'); nl >= 0 {
			tail = tail[nl+1:]
		}
		if trimmed := bytes.TrimSpace(stripPHPClose(tail)); len(trimmed) > 0 && hasMalwareMarker(trimmed) {
			line, ev := snippet(content, idx)
			f := a.fileFinding(j, nil, false)
			f.RuleID = "wp.config_appended_code"
			f.Class = "WP"
			f.Severity = model.SevCritical
			f.Confidence = model.ConfLikely
			f.Title = "Code appended after the wp-settings.php require in wp-config.php"
			f.Detail = "Stock WordPress ends wp-config.php at that require. Content after it executes on every request."
			f.Remediation = "Excise the appended block by hand; do not delete wp-config.php."
			f.Line = line
			f.Evidence = ev
			a.emit(f)
		}
	}

	// auto_prepend_file set from inside wp-config is a fileless-ish loader.
	if bytes.Contains(bytes.ToLower(content), []byte("auto_prepend_file")) {
		f := a.fileFinding(j, nil, false)
		f.RuleID = "wp.config_auto_prepend"
		f.Class = "WP"
		f.Severity = model.SevCritical
		f.Confidence = model.ConfLikely
		f.Title = "wp-config.php sets auto_prepend_file"
		f.Detail = "Injects an arbitrary file into every PHP request on the site."
		a.emit(f)
	}

	if fi.Mode().Perm()&0o044 != 0 {
		f := a.fileFinding(j, nil, false)
		f.RuleID = "wp.config_world_readable"
		f.Class = "WP"
		f.Severity = model.SevMedium
		f.Confidence = model.ConfConfirmed
		f.Title = "wp-config.php is group/world readable"
		f.Detail = "Database credentials are readable by other accounts on this host — relevant on shared hosting."
		f.Remediation = "chmod 600 wp-config.php."
		a.emit(f)
	}
	return model.CheckOK, ""
}

func findWPConfig(root string) (string, bool) {
	for _, c := range []string{
		filepath.Join(root, "wp-config.php"),
		filepath.Join(filepath.Dir(root), "wp-config.php"),
	} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, true
		}
	}
	return "", false
}

// checkIndexPHP validates the front controller generically. The canonical stub
// is ~405 bytes and does exactly two things; anything else warrants a look,
// whether or not it matches a known injection signature.
func (a *Agent) checkIndexPHP(root string) (model.CheckState, string) {
	p := filepath.Join(root, "index.php")
	fi, err := os.Stat(p)
	if err != nil {
		return model.CheckNotApplicable, "no index.php at webroot"
	}
	content, err := readHead(p, 256<<10)
	if err != nil {
		return model.CheckError, err.Error()
	}
	j := fileJob{abs: p, rel: "index.php", info: fi}

	hasRequire := bytes.Contains(content, []byte("wp-blog-header.php"))
	switch {
	case !hasRequire:
		f := a.fileFinding(j, content, false)
		f.RuleID = "wp.index_not_canonical"
		f.Class = "CLOAK"
		f.Severity = model.SevCritical
		f.Confidence = model.ConfLikely
		f.Title = "Webroot index.php does not load wp-blog-header.php"
		f.Detail = fmt.Sprintf("The canonical front controller is ~405 bytes and requires wp-blog-header.php. This file is %d bytes and does not.", fi.Size())
		f.Remediation = "Restore the canonical index.php, then flush OPcache — the compiled bytecode outlives the file."
		a.emit(f)
	case fi.Size() > 600:
		f := a.fileFinding(j, content, false)
		f.RuleID = "wp.index_oversized"
		f.Class = "CLOAK"
		f.Severity = model.SevMedium
		f.Confidence = model.ConfReview
		f.Title = fmt.Sprintf("Webroot index.php is %d bytes (canonical is ~405)", fi.Size())
		f.Detail = "Larger than stock but still loads wp-blog-header.php — could be a host customisation or an injection appended around the require."
		f.Remediation = "Diff against the canonical stub by hand."
		a.emit(f)
	}
	return model.CheckOK, ""
}

// checkUploadsHardening reports the absence of an execution guard on the
// uploads tree. This is a preventive finding, not a compromise indicator: it is
// the control that turns a future arbitrary-upload bug into a non-event.
func (a *Agent) checkUploadsHardening(root string) {
	up := filepath.Join(root, "wp-content", "uploads")
	if fi, err := os.Stat(up); err != nil || !fi.IsDir() {
		return
	}
	ht := filepath.Join(up, ".htaccess")
	b, err := os.ReadFile(ht)
	guarded := err == nil && bytes.Contains(bytes.ToLower(b), []byte("php"))
	if guarded {
		return
	}
	f := model.Finding{
		RuleID:      "wp.uploads_not_hardened",
		Class:       "WP",
		Severity:    model.SevLow,
		Confidence:  model.ConfConfirmed,
		Title:       "Uploads directory has no PHP-execution guard",
		Detail:      "Nothing prevents a PHP file written into uploads/ from executing. This is the difference between an upload bug and a shell.",
		Remediation: "Deny PHP execution under wp-content/uploads at the web-server level (or via .htaccess on Apache).",
		Path:        "wp-content/uploads",
	}
	a.emit(f)
}

// looksLikeCodeExec distinguishes a file that merely mentions a dangerous
// function from one that appears to call it with dynamic input.
func looksLikeCodeExec(b []byte) bool {
	lower := bytes.ToLower(b)
	hasInput := bytes.Contains(lower, []byte("$_get")) || bytes.Contains(lower, []byte("$_post")) ||
		bytes.Contains(lower, []byte("$_request")) || bytes.Contains(lower, []byte("$_cookie")) ||
		bytes.Contains(lower, []byte("php://input"))
	hasExec := bytes.Contains(lower, []byte("eval(")) || bytes.Contains(lower, []byte("assert(")) ||
		bytes.Contains(lower, []byte("shell_exec")) || bytes.Contains(lower, []byte("passthru")) ||
		bytes.Contains(lower, []byte("proc_open")) || bytes.Contains(lower, []byte("system("))
	hasObf := bytes.Contains(lower, []byte("base64_decode")) || bytes.Contains(lower, []byte("gzinflate")) ||
		bytes.Contains(lower, []byte("str_rot13"))
	return hasExec && (hasInput || hasObf)
}

func stripPHPClose(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("?>"), nil)
}
