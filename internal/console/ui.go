package console

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// The console UI ships inside the binary. No build step, no npm, no CDN — which
// is what lets the strict Content-Security-Policy in consoleSecurity hold: every
// script and stylesheet is same-origin and static.
//
//go:embed web
var webFS embed.FS

func (s *Server) uiHandler() http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return http.NotFoundHandler()
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never let an unknown path fall through to the API surface.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusNotFound, "no such endpoint")
			return
		}
		// Single-page app: unknown routes render the shell and the client
		// resolves them, so a deep link such as /agents/ag_x works on reload.
		if r.URL.Path != "/" && !hasAsset(sub, strings.TrimPrefix(r.URL.Path, "/")) {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}

func hasAsset(fsys fs.FS, name string) bool {
	if name == "" {
		return false
	}
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
