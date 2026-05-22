package ui

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Advanced search. Structured fields that map to store columns (source /
// rule / severity / since / full-text) are pushed into the SQL query; the
// "behavioral" fields (ATT&CK tactic, geo country, tool, has-payload,
// has-session, handler, dest port) are post-filters over the captured meta,
// since they aren't indexed columns. Natural-language search is intentionally
// out of scope (it would require an LLM the sensor doesn't ship).

const searchResultCap = 500
const searchScanMax = 20000

type searchQuery struct {
	SourceIP   string
	RuleID     string
	Severity   string
	Handler    string
	Port       string
	Since      string
	Tactic     string
	Country    string
	Tool       string
	Text       string
	HasPayload bool
	HasSession bool
}

func (q searchQuery) empty() bool {
	return q == searchQuery{}
}

type searchView struct {
	Q        searchQuery
	Searched bool
	Matched  int
	Capped   bool
	Results  []*event.Event
}

func parseSearchQuery(r *http.Request) searchQuery {
	g := func(k string) string { return strings.TrimSpace(r.URL.Query().Get(k)) }
	return searchQuery{
		SourceIP:   g("source"),
		RuleID:     g("rule"),
		Severity:   g("severity"),
		Handler:    g("handler"),
		Port:       g("port"),
		Since:      g("since"),
		Tactic:     g("tactic"),
		Country:    g("country"),
		Tool:       g("tool"),
		Text:       g("q"),
		HasPayload: g("has_payload") == "1",
		HasSession: g("has_session") == "1",
	}
}

func runSearch(ctx context.Context, st *store.Store, q searchQuery) ([]*event.Event, bool, error) {
	since := time.Now().Add(-24 * time.Hour)
	if q.Since != "" {
		if d, err := time.ParseDuration(q.Since); err == nil && d > 0 {
			since = time.Now().Add(-d)
		}
	}
	f := store.Filter{Since: since, SourceIP: q.SourceIP, RuleID: q.RuleID, Text: q.Text, Limit: searchScanMax}
	if q.Severity != "" {
		if sv, err := event.ParseSeverity(q.Severity); err == nil {
			f.MinSeverity = sv
		}
	}
	evs, err := st.Query(ctx, f)
	if err != nil {
		return nil, false, err
	}
	port, _ := strconv.Atoi(q.Port)
	out := make([]*event.Event, 0, len(evs))
	for _, ev := range evs {
		if q.Handler != "" && !strings.EqualFold(ev.Handler, q.Handler) {
			continue
		}
		if port > 0 && ev.Dest.Port != port {
			continue
		}
		if q.Tactic != "" && !containsFold(eventTag(ev).Tactics, q.Tactic) {
			continue
		}
		if q.Country != "" {
			c, _ := ev.Meta["geo_country"].(string)
			if !strings.EqualFold(c, q.Country) {
				continue
			}
		}
		if q.Tool != "" && !containsSubstrFold(metaStrings(ev.Meta, "tools"), q.Tool) {
			continue
		}
		if q.HasPayload && ev.PayloadLen == 0 && len(metaStrings(ev.Meta, "payload_artifacts")) == 0 {
			continue
		}
		if q.HasSession {
			if _, ok := ev.Meta["session_cast"]; !ok {
				continue
			}
		}
		out = append(out, ev)
	}
	capped := false
	if len(out) > searchResultCap {
		out = out[:searchResultCap]
		capped = true
	}
	return out, capped, nil
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func containsSubstrFold(xs []string, v string) bool {
	v = strings.ToLower(v)
	for _, x := range xs {
		if strings.Contains(strings.ToLower(x), v) {
			return true
		}
	}
	return false
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := parseSearchQuery(r)
	view := searchView{Q: q}
	if !q.empty() {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		results, capped, err := runSearch(ctx, s.store, q)
		if err != nil {
			serverError(w, r.URL.Path, err)
			return
		}
		view.Searched = true
		view.Results = results
		view.Matched = len(results)
		view.Capped = capped
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "search", view); err != nil {
		slog.Warn("ui: render search", "err", err)
	}
}
