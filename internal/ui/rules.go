package ui

import (
	"net/http"
)

// DetectRuleStat is one operator detection rule + its lifetime match count, as
// surfaced on the /rules page. Mirrors detect.RuleStat without importing
// internal/detect into the ui package (run.go bridges the two).
type DetectRuleStat struct {
	ID         string
	Title      string
	Severity   string
	Tags       []string
	Conditions int
	Hits       uint64
}

// RulesProvider returns a snapshot of the loaded operator detection rules with
// their match counts. nil = the detection-rule engine isn't wired (page hidden).
type RulesProvider func() []DetectRuleStat

// SetRulesProvider wires the operator detection-rule engine so the /rules page
// can list the loaded rules + how often each has fired.
func (s *Server) SetRulesProvider(p RulesProvider) { s.rules = p }

type rulesView struct {
	RangeLabel string
	Rules      []DetectRuleStat
	TotalHits  uint64
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		http.NotFound(w, r)
		return
	}
	v := rulesView{RangeLabel: "live"}
	v.Rules = s.rules()
	for _, rr := range v.Rules {
		v.TotalHits += rr.Hits
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "rules", v); err != nil {
		serverError(w, r.URL.Path, err)
	}
}
