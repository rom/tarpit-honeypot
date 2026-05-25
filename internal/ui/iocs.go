package ui

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// iocDisplay is one IOC row with a precomputed drill-down link.
type iocDisplay struct {
	Type       string
	Value      string
	Count      int
	Severity   event.Severity
	FirstSeen  time.Time
	LastSeen   time.Time
	LastRule   string
	LastSource string
	Link       string // to the filtered event log
}

type iocsPage struct {
	Counts     []barRow // per-type breakdown (bars; each links to that type)
	IOCs       []iocDisplay
	Total      int
	TypeFilter string
	SinceStr   string
}

// handleIOCs renders the indicator-of-compromise panel: a per-type breakdown
// and the de-duplicated indicators (value, count, first/last seen, severity),
// each linking to the events that exhibited it.
func (s *Server) handleIOCs(w http.ResponseWriter, r *http.Request) {
	since := iocSince(r)
	typ := r.URL.Query().Get("type")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cutoff := time.Now().Add(-since)
	sum, err := s.store.IOCSummary(ctx, cutoff)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	rows, err := s.store.QueryIOCs(ctx, store.IOCFilter{Type: typ, Since: cutoff, Text: r.URL.Query().Get("q"), Limit: 1000})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "iocs", iocsPage{
		Counts:     iocTypeBars(sum),
		IOCs:       iocDisplays(rows),
		Total:      len(rows),
		TypeFilter: typ,
		SinceStr:   r.URL.Query().Get("since"),
	}); err != nil {
		slog.Warn("ui: render iocs", "err", err)
	}
}

// handleAPIIOCs returns the IOC rows as JSON.
func (s *Server) handleAPIIOCs(w http.ResponseWriter, r *http.Request) {
	since := iocSince(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.store.QueryIOCs(ctx, store.IOCFilter{
		Type: r.URL.Query().Get("type"), Since: time.Now().Add(-since),
		Text: r.URL.Query().Get("q"), Limit: 5000,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rows)
}

func iocSince(r *http.Request) time.Duration {
	since := 7 * 24 * time.Hour
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = d
		}
	}
	return since
}

func iocTypeBars(sum map[string]int) []barRow {
	max := 0
	for _, v := range sum {
		if v > max {
			max = v
		}
	}
	rows := make([]barRow, 0, len(sum))
	for typ, c := range sum {
		pct := 0
		if max > 0 {
			pct = c * 100 / max
		}
		rows = append(rows, barRow{Label: typ, Count: c, Pct: pct, Href: "/iocs?type=" + url.QueryEscape(typ)})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Label < rows[j].Label
	})
	return rows
}

func iocDisplays(rows []store.IOCRow) []iocDisplay {
	out := make([]iocDisplay, 0, len(rows))
	for _, r := range rows {
		out = append(out, iocDisplay{
			Type: r.Type, Value: r.Value, Count: r.Count, Severity: r.Severity,
			FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, LastRule: r.LastRule, LastSource: r.LastSource,
			Link: iocLink(r),
		})
	}
	return out
}

// iocLink points at the events that exhibited an indicator: by source IP for the
// ip type, else a text search over the event meta.
func iocLink(r store.IOCRow) string {
	if r.Type == "ip" {
		return "/events?source=" + url.QueryEscape(r.Value)
	}
	return "/events?q=" + url.QueryEscape(r.Value)
}
