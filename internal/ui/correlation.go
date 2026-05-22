package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Correlation view: per-source pivot chains linking the entities a single
// actor touches — IP → network fingerprints → User-Agents → ASN/country →
// domains → tools → captured credentials → malware artifacts → sessions.
// The strict no-JS CSP rules out a force-directed graph, so this renders the
// chain as linked chips (each pivots to the relevant view), which is the
// useful part of "IP→JA4→UA→Payload→Domain→ASN" without client-side script.

const corrWindow = 24 * time.Hour
const corrScanMax = 20000
const corrMaxSources = 30
const corrMaxPerList = 12

type correlationView struct {
	Since   time.Time
	Total   int
	Sources []corrSource
}

type fpChip struct {
	Kind  string
	Value string
}

type corrSource struct {
	IP        string
	Count     int
	MaxSev    string
	FPs       []fpChip
	UAs       []string
	ASN       string
	Countries []string
	Domains   []string
	Tools     []string
	Creds     []string
	Malware   []string
	Sessions  int
	Tactics   []string
}

func buildCorrelationView(since time.Time, evs []*event.Event) correlationView {
	v := correlationView{Since: since, Total: len(evs)}
	type acc struct {
		s       corrSource
		fps     map[string]bool
		uas     map[string]bool
		country map[string]bool
		dom     map[string]bool
		tool    map[string]bool
		cred    map[string]bool
		mal     map[string]bool
		tactic  map[string]bool
	}
	by := map[string]*acc{}
	order := []string{}

	for _, ev := range evs {
		ip := ev.Source.IP
		if ip == "" {
			continue
		}
		a := by[ip]
		if a == nil {
			a = &acc{
				s:   corrSource{IP: ip},
				fps: map[string]bool{}, uas: map[string]bool{}, country: map[string]bool{},
				dom: map[string]bool{}, tool: map[string]bool{}, cred: map[string]bool{},
				mal: map[string]bool{}, tactic: map[string]bool{},
			}
			by[ip] = a
			order = append(order, ip)
		}
		a.s.Count++
		if sevRank(ev.Severity.String()) > sevRank(a.s.MaxSev) {
			a.s.MaxSev = ev.Severity.String()
		}
		for _, k := range []string{"ja4", "ja4h", "ja3", "ja3s", "hassh", "hassh_server"} {
			if val, ok := ev.Meta[k].(string); ok && val != "" {
				if key := k + "/" + val; !a.fps[key] {
					a.fps[key] = true
					if len(a.s.FPs) < corrMaxPerList {
						a.s.FPs = append(a.s.FPs, fpChip{Kind: k, Value: val})
					}
				}
			}
		}
		if ua, ok := ev.Meta["user_agent"].(string); ok && ua != "" {
			addCapped(&a.s.UAs, a.uas, ua, corrMaxPerList)
		}
		if a.s.ASN == "" {
			a.s.ASN = asnLabel(ev.Meta)
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			addCapped(&a.s.Countries, a.country, c, corrMaxPerList)
		}
		if d, _ := ev.Meta["qname"].(string); d != "" {
			addCapped(&a.s.Domains, a.dom, d, corrMaxPerList)
		}
		for _, t := range metaStrings(ev.Meta, "tools") {
			addCapped(&a.s.Tools, a.tool, t, corrMaxPerList)
		}
		for _, c := range extractCreds(ev.Meta) {
			label := c.User
			if c.Pass != "" {
				label += " : " + c.Pass
			}
			if label != "" && label != " : " {
				addCapped(&a.s.Creds, a.cred, label, corrMaxPerList)
			}
		}
		for _, m := range malwareKinds(ev) {
			addCapped(&a.s.Malware, a.mal, m, corrMaxPerList)
		}
		for _, t := range eventTag(ev).Tactics {
			a.tactic[t] = true
		}
		if _, ok := ev.Meta["session_cast"]; ok {
			a.s.Sessions++
		}
	}

	for _, ip := range order {
		a := by[ip]
		a.s.Tactics = orderTactics(a.tactic)
		v.Sources = append(v.Sources, a.s)
	}
	sort.Slice(v.Sources, func(i, j int) bool {
		if v.Sources[i].Count != v.Sources[j].Count {
			return v.Sources[i].Count > v.Sources[j].Count
		}
		return v.Sources[i].IP < v.Sources[j].IP
	})
	if len(v.Sources) > corrMaxSources {
		v.Sources = v.Sources[:corrMaxSources]
	}
	return v
}

// addCapped appends v to *list (deduped via seen) up to max entries.
func addCapped(list *[]string, seen map[string]bool, v string, max int) {
	if seen[v] || len(*list) >= max {
		return
	}
	seen[v] = true
	*list = append(*list, v)
}

func (s *Server) handleCorrelation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-corrWindow)
	evs, err := s.store.Query(ctx, store.Filter{Since: since, Limit: corrScanMax})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "correlation", buildCorrelationView(since, evs)); err != nil {
		slog.Warn("ui: render correlation", "err", err)
	}
}
