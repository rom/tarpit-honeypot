package ui

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Interactions view: everything the decoys captured of an attacker's actual
// WORK — the commands typed into the emulated SSH/Telnet shells, exec requests,
// fake-web-shell commands, keystrokes, and any recorded session casts. This is
// the "what did they DO once 'in'" view, distinct from the recon/attack tables.

const interactionsWindow = 30 * 24 * time.Hour

type interactionsView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Total      int
	Sources    int
	Commands   int
	Figs       []chartFig
	TopCmds    []countRow
	Rows       []interactionRow
	Empty      bool
}

type interactionRow struct {
	Time     string
	Source   string
	Service  string
	Kind     string // shell | exec | webshell | keystrokes | command
	Commands []string
	More     int    // commands beyond the shown cap
	Cast     string // recorded session cast filename (download), if any
}

func (s *Server) handleInteractions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	win := summaryRange(r.URL.Query().Get("range"))
	since := time.Now().Add(-win.dur)
	if win.dur == 0 {
		since = time.Now().Add(-interactionsWindow)
	}
	// Meta-only scan (commands live in meta, never the payload blob).
	evs, err := s.query(ctx, store.Filter{Since: since, Limit: 50000, NoPayload: true})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildInteractions(evs)
	v.RangeLabel = win.label
	v.RangeLinks = rangeLinksFor("/interactions", win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "interactions", v); err != nil {
		slog.Warn("ui: render interactions", "err", err)
	}
}

// capturedWork extracts the attacker's captured work from an event, or ok=false.
func capturedWork(ev *event.Event) (kind string, items []string, cast string, ok bool) {
	cast = metaStr(ev, "session_cast")
	if c := metaStrings(ev.Meta, "shell_commands"); len(c) > 0 {
		return "shell", c, cast, true
	}
	if c := metaStr(ev, "exec_command"); c != "" {
		return "exec", []string{c}, cast, true
	}
	if c := metaStr(ev, "webshell_cmd"); c != "" {
		return "webshell", []string{c}, "", true
	}
	if k := metaStr(ev, "keystrokes"); k != "" {
		return "keystrokes", []string{k}, cast, true
	}
	// Generic "commands" (redis/other decoys that record what the attacker ran).
	if c := metaStrings(ev.Meta, "commands"); len(c) > 0 {
		return "command", c, cast, true
	}
	return "", nil, "", false
}

func buildInteractions(evs []*event.Event) interactionsView {
	v := interactionsView{}
	srcSet := map[string]bool{}
	byService := map[string]int{}
	cmdCount := map[string]int{}

	sorted := append([]*event.Event(nil), evs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Time.After(sorted[j].Time) })
	for _, ev := range sorted {
		kind, items, cast, ok := capturedWork(ev)
		if !ok {
			continue
		}
		v.Total++
		v.Commands += len(items)
		if ev.Source.IP != "" {
			srcSet[ev.Source.IP] = true
		}
		if ev.Handler != "" {
			byService[ev.Handler]++
		}
		for _, c := range items {
			cmdCount[c]++
		}
		if len(v.Rows) >= 300 {
			continue
		}
		row := interactionRow{
			Time:    ev.Time.UTC().Format(time.RFC3339),
			Source:  ev.Source.IP,
			Service: ev.Handler,
			Kind:    kind,
			Cast:    cast,
		}
		const cap = 60
		if len(items) > cap {
			row.Commands = items[:cap]
			row.More = len(items) - cap
		} else {
			row.Commands = items
		}
		v.Rows = append(v.Rows, row)
	}
	if v.Total == 0 {
		v.Empty = true
		return v
	}
	v.Sources = len(srcSet)

	if len(byService) > 0 {
		v.Figs = append(v.Figs, chartFigure("pie", "Interactions by service", map[string]any{"slices": slicesFromMap(byService), "donut": true}))
	}
	if len(cmdCount) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top commands captured", map[string]any{"series": topBarsFromMap(cmdCount, 25)}))
	}
	for _, k := range topKeys(cmdCount, 50) {
		v.TopCmds = append(v.TopCmds, countRow{Label: k, Count: cmdCount[k], Href: "/search?q=" + url.QueryEscape(k)})
	}
	return v
}
