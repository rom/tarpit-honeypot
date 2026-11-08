package ui

import (
	"log/slog"
	"net/http"

	"github.com/rom/tarpit-honeypot/internal/correlate"
)

// playbooksView drives the /playbooks reference page: every named attack pattern
// the storyline correlator recognizes, with its full description. Focus is an
// optional ?name= that highlights one entry (the playbook tags link here with a
// #<name> anchor).
type playbooksView struct {
	Playbooks []correlate.Playbook
	Focus     string
}

// handlePlaybooks renders the playbook reference. Always available (reached from
// the playbook tags on the attack / correlation / profile views), not nav-gated.
func (s *Server) handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	v := playbooksView{Playbooks: correlate.AllPlaybooks(), Focus: r.URL.Query().Get("name")}
	if err := s.tmpl.ExecuteTemplate(w, "playbooks", v); err != nil {
		slog.Warn("ui: render playbooks", "err", err)
	}
}
