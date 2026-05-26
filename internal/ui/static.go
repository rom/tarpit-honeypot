package ui

import (
	"embed"
	"net/http"
)

// staticFS holds the UI's packaged client assets (JS, etc.), compiled into
// the binary so the sensor host never fetches anything from a CDN — assets
// load same-origin under the CSP's script-src 'self'. To add a vendored
// framework, drop its file into static/ and reference it from the head
// template; no other change is needed.
//
//go:embed static
var staticFS embed.FS

// handleStatic serves the embedded assets under /static/. http.FileServer
// resolves the request path against the embed FS (which already carries the
// "static/" prefix), sets a correct JS MIME type (required since we send
// X-Content-Type-Options: nosniff), and 404s anything missing.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Don't cache: the asset is embedded and changes with the binary, so a
	// stale cached copy after an upgrade would silently run old JS. (It's a
	// few KB on a localhost ops UI — caching buys nothing here.)
	w.Header().Set("Cache-Control", "no-store")
	http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
}

// handleFavicon serves /favicon.ico (the browser default request path) from
// the same embedded static FS, so old / non-SVG browsers find an icon without
// the page having to advertise it.
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}
