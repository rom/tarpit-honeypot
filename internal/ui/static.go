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
	w.Header().Set("Cache-Control", "max-age=3600")
	http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
}
