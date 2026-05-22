package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
// Rendered both as linked chips (the no-JS fallback, each pivoting to the
// relevant view) and as a base64-embedded node-link graph that the packaged
// app.js draws as interactive SVG ("IP→JA4→UA→Payload→Domain→ASN").

const corrWindow = 24 * time.Hour
const corrScanMax = 20000
const corrMaxSources = 30
const corrMaxPerList = 12

type correlationView struct {
	Since   time.Time
	Total   int
	Sources []corrSource
	// GraphB64 is a base64-encoded JSON {nodes,edges} the client renders as an
	// interactive SVG node-link graph (app.js). Base64 keeps it free of
	// HTML-special characters so it embeds cleanly in a data attribute.
	GraphB64 string
}

type graphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"`
}
type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// buildCorrGraph turns the top correlated sources into a layered node-link
// graph (IP → fingerprint / ASN / tool / domain), capped so the SVG stays
// legible.
func buildCorrGraph(sources []corrSource) string {
	const maxSources = 8
	var nodes []graphNode
	var edges []graphEdge
	seen := map[string]bool{}
	add := func(id, label, group string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		nodes = append(nodes, graphNode{ID: id, Label: label, Group: group})
	}
	link := func(from, to string) {
		if from != "" && to != "" {
			edges = append(edges, graphEdge{From: from, To: to})
		}
	}
	n := len(sources)
	if n > maxSources {
		n = maxSources
	}
	for _, s := range sources[:n] {
		ipID := "ip:" + s.IP
		add(ipID, s.IP, "ip")
		for _, fp := range s.FPs {
			id := "fp:" + fp.Kind + ":" + fp.Value
			add(id, fp.Kind+":"+short(fp.Value), "fp")
			link(ipID, id)
		}
		if s.ASN != "" {
			id := "asn:" + s.ASN
			add(id, short(s.ASN), "asn")
			link(ipID, id)
		}
		for _, t := range s.Tools {
			add("tool:"+t, t, "tool")
			link(ipID, "tool:"+t)
		}
		for _, d := range s.Domains {
			add("dom:"+d, short(d), "domain")
			link(ipID, "dom:"+d)
		}
	}
	if len(nodes) == 0 {
		return ""
	}
	b, err := json.Marshal(struct {
		Nodes []graphNode `json:"nodes"`
		Edges []graphEdge `json:"edges"`
	}{nodes, edges})
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func short(s string) string {
	if len(s) > 22 {
		return s[:21] + "…"
	}
	return s
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
	v.GraphB64 = buildCorrGraph(v.Sources)
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
