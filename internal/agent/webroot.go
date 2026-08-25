package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Webroot discovery.
//
// The bash original hardcoded ~/public and /www/*/public, which is a Kinsta
// layout. Estate-independence means probing the layouts every mainstream host
// actually uses, and confirming each candidate is really WordPress rather than
// trusting the directory name.

var webrootCandidates = []string{
	"~/public",
	"~/public_html",
	"~/www",
	"~/htdocs",
	"~/web",
	"~/app",
	"/www/*/public",
	"/www/*/public_html",
	"/var/www/html",
	"/var/www/*/public_html",
	"/var/www/*/htdocs",
	"/var/www/*/html",
	"/var/www/vhosts/*/httpdocs",
	"/home/*/public_html",
	"/home/*/www",
	"/srv/www/*",
	"/srv/http",
	"/usr/share/nginx/html",
	"/app/public",
	"/bitnami/wordpress",
}

// IsWordPress confirms a directory is a WordPress document root. Checking for
// wp-includes/version.php rather than wp-config.php matters: hardened installs
// move wp-config.php one level above the webroot.
func IsWordPress(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "wp-includes", "version.php")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "wp-load.php")); err == nil {
		return true
	}
	_, a := os.Stat(filepath.Join(dir, "wp-config.php"))
	_, b := os.Stat(filepath.Join(dir, "wp-content"))
	return a == nil && b == nil
}

// FindWebroot returns the single best webroot, preferring the current directory
// (or an ancestor) so that running the agent from inside a site does the
// obvious thing.
func FindWebroot(home string) string {
	if cwd, err := os.Getwd(); err == nil {
		for d := cwd; ; {
			if IsWordPress(d) {
				return d
			}
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}
	if all := DiscoverWebroots(home, 1); len(all) > 0 {
		return all[0]
	}
	return ""
}

// DiscoverWebroots enumerates every WordPress install reachable from the
// standard layouts. A limit of zero means unlimited. This is what lets one
// agent invocation cover a multi-site host.
func DiscoverWebroots(home string, limit int) []string {
	seen := map[string]bool{}
	var out []string

	add := func(d string) bool {
		abs, err := filepath.Abs(d)
		if err != nil || seen[abs] {
			return false
		}
		if !IsWordPress(abs) {
			return false
		}
		seen[abs] = true
		out = append(out, abs)
		return limit > 0 && len(out) >= limit
	}

	for _, pat := range webrootCandidates {
		if strings.HasPrefix(pat, "~/") {
			if home == "" {
				continue
			}
			pat = filepath.Join(home, pat[2:])
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err != nil || !fi.IsDir() {
				continue
			}
			if add(m) {
				return out
			}
		}
	}
	sort.Strings(out)
	return out
}

var wpVersionRe = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)

// WordPressVersion reads the declared core version, for reporting and for
// deciding whether an integrity check is meaningful.
func WordPressVersion(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		return ""
	}
	if m := wpVersionRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}
