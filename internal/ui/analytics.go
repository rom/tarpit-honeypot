package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/analytics"
	"github.com/rom/tarpit-honeypot/internal/event"
)

const analyticsScanMax = 20000

// Mining / graph tunables (kept modest so a page render stays fast).
const (
	anMaxItemsPerSource = 48   // cap distinct items per transaction
	anMinRuleCount      = 3    // a rule must hold on at least this many sources
	anMinRuleLift       = 1.1  // and be at least mildly positively associated
	anMaxRules          = 40   // rows shown
	anMaxPairs          = 25   // co-occurrence rows shown
	anGraphBetweenCap   = 1500 // skip Brandes above this many nodes
	anGraphDrawNodes    = 140  // nodes drawn in the force figure
	anTopCentrality     = 25   // rows in the centrality table
	anTopActors         = 25   // rows in the diversity table
)

type ruleRow struct {
	Antecedent string
	Consequent string
	Count      int
	SupportPct float64
	ConfPct    float64
	Lift       float64
}

type pairRow struct {
	A, B    string
	Count   int
	Lift    float64
	Jaccard float64
}

type centRow struct {
	Label       string
	Kind        string
	Degree      int
	Betweenness float64
}

type actorDiv struct {
	IP         string
	Events     int
	Services   int
	Evenness   float64
	Gini       float64
	Focus      string // "focused" | "mixed" | "spray"
	TopService string
}

type analyticsView struct {
	Sources      int
	Transactions int
	Rules        []ruleRow
	Pairs        []pairRow
	GraphB64     string
	GraphNodes   int
	GraphEdges   int
	GraphBetween bool // false => betweenness skipped (graph too big)
	TopNodes     []centRow
	Actors       []actorDiv
	Note         string

	RangeKey, RangeLabel string
	RangeLinks           []rangeLink
	Uptime               string
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	dur, rkey, rlabel, rlinks := pageRange(r, "/analytics")
	evs, err := s.windowEvents(ctx, dur, s.scanCap(analyticsScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	view := buildAnalyticsView(evs)
	view.RangeKey, view.RangeLabel, view.RangeLinks = rkey, rlabel, rlinks
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "analytics", view); err != nil {
		slog.Warn("ui: render analytics", "err", err)
	}
}

// buildAnalyticsView computes the association rules, pivot-graph centrality and
// per-actor diversity for the window. Pure given the events (no store/clock).
func buildAnalyticsView(evs []*event.Event) analyticsView {
	txns, graph, actors := analyticsExtract(evs)

	v := analyticsView{Sources: len(actors), Transactions: len(txns)}

	// --- Association-rule / co-occurrence mining ---------------------------
	minSupport := 0.01
	if n := len(txns); n > 0 {
		if f := float64(anMinRuleCount) / float64(n); f > minSupport {
			minSupport = f // never ask for fewer than anMinRuleCount sources
		}
	}
	for _, rl := range analytics.AssociationRules(txns, minSupport, 0.3, anMaxRules*3) {
		if rl.Count < anMinRuleCount || rl.Lift < anMinRuleLift {
			continue
		}
		v.Rules = append(v.Rules, ruleRow{
			Antecedent: strings.Join(rl.Antecedent, " + "),
			Consequent: rl.Consequent,
			Count:      rl.Count,
			SupportPct: rl.Support * 100,
			ConfPct:    rl.Confidence * 100,
			Lift:       rl.Lift,
		})
		if len(v.Rules) >= anMaxRules {
			break
		}
	}
	for _, p := range analytics.CoOccurrence(txns, anMinRuleCount, anMaxPairs) {
		v.Pairs = append(v.Pairs, pairRow{A: p.A, B: p.B, Count: p.Count, Lift: p.Lift, Jaccard: p.Jaccard})
	}

	// --- Infrastructure pivot graph + centrality ---------------------------
	// Keep the connective core: an entity must be shared by ≥2 sources (degree
	// ≥2); a source IP is kept as long as it still touches a surviving entity.
	graph.PruneFunc(func(n analytics.Node, deg int) bool {
		if n.Kind == "source" {
			return deg >= 1
		}
		return deg >= 2
	})
	v.GraphBetween = graph.Compute(anGraphBetweenCap)
	v.GraphNodes = graph.NodeCount()
	nodes := graph.Nodes(0)
	for i, n := range nodes {
		if i >= anTopCentrality {
			break
		}
		if n.Kind == "source" { // IPs are the substrate, not "infrastructure"
			continue
		}
		v.TopNodes = append(v.TopNodes, centRow{Label: n.Label, Kind: n.Kind, Degree: n.Degree, Betweenness: n.Betweenness})
	}
	v.GraphB64, v.GraphEdges = encodePivotGraph(graph, v.GraphBetween)

	// --- Per-actor targeting diversity -------------------------------------
	sort.Slice(actors, func(i, j int) bool {
		if actors[i].events != actors[j].events {
			return actors[i].events > actors[j].events
		}
		return actors[i].ip < actors[j].ip
	})
	for i, a := range actors {
		if i >= anTopActors {
			break
		}
		even := analytics.ShannonEvenness(a.svc)
		gini := analytics.Gini(a.svc)
		focus := "mixed"
		switch {
		case len(a.svc) <= 1 || even < 0.34:
			focus = "focused"
		case even > 0.7:
			focus = "spray"
		}
		top, topN := "", 0
		for svc, c := range a.svc {
			if c > topN {
				top, topN = svc, c
			}
		}
		v.Actors = append(v.Actors, actorDiv{
			IP: a.ip, Events: a.events, Services: len(a.svc),
			Evenness: even, Gini: gini, Focus: focus, TopService: top,
		})
	}

	if v.Sources == 0 {
		v.Note = "No source activity in this window yet."
	}
	return v
}

// actorAccum accumulates one source's transaction items + service-targeting
// distribution while the events are scanned once.
type actorAccum struct {
	ip     string
	events int
	items  map[string]bool
	svc    map[string]int // handler -> event count, for targeting diversity
}

// analyticsExtract does the single pass over events, producing the mining
// transactions (one itemset per source), the pivot graph (source IP ↔ shared
// identity entities), and the per-actor targeting distributions.
func analyticsExtract(evs []*event.Event) (txns [][]string, graph *analytics.Graph, actors []*actorAccum) {
	graph = analytics.NewGraph()
	by := map[string]*actorAccum{}
	seenEdge := map[string]bool{} // src|entity dedupe

	for _, ev := range evs {
		ip := ev.Source.IP
		if ip == "" {
			continue
		}
		a := by[ip]
		if a == nil {
			a = &actorAccum{ip: ip, items: map[string]bool{}, svc: map[string]int{}}
			by[ip] = a
			actors = append(actors, a)
		}
		a.events++

		// Transaction items (capped).
		addItem := func(it string) {
			if it != "" && len(a.items) < anMaxItemsPerSource {
				a.items[it] = true
			}
		}
		if ev.Handler != "" {
			addItem("svc:" + ev.Handler)
			a.svc[ev.Handler]++
		}
		if ev.Dest.Port > 0 {
			addItem("port:" + strconv.Itoa(ev.Dest.Port))
		}
		for _, cve := range eventCVEs(ev) {
			addItem("cve:" + cve)
		}
		for _, t := range metaStrings(ev.Meta, "tools") {
			addItem("tool:" + strings.ToLower(t))
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			addItem("cc:" + c)
		}
		for _, tac := range eventTag(ev).Tactics {
			addItem("tactic:" + tac)
		}
		for _, l := range metaStrings(ev.Meta, "labels") {
			addItem("label:" + strings.TrimPrefix(l, "meta:"))
		}
		if n := metaInt(ev.Meta, "asn"); n > 0 {
			addItem("asn:" + strconv.Itoa(n))
		}

		// Pivot-graph edges: source IP ↔ each strong identity entity it exhibits.
		graph.AddNode(ip, ip, "source")
		linkEntity := func(id, label, kind string) {
			if id == "" {
				return
			}
			ek := ip + "\x00" + id
			if seenEdge[ek] {
				return
			}
			seenEdge[ek] = true
			graph.AddNode(id, label, kind)
			graph.AddEdge(ip, id)
		}
		for _, k := range []string{"ja4", "ja4h", "ja3", "ja3s", "hassh", "hassh_server"} {
			if val, _ := ev.Meta[k].(string); val != "" {
				linkEntity("fp:"+k+"/"+val, k+":"+shortLabel(val, 20), "fp")
			}
		}
		for _, pk := range metaStrings(ev.Meta, "ssh_pubkey_fps") {
			linkEntity("pubkey:"+pk, "pubkey:"+shortLabel(pk, 16), "pubkey")
		}
		for _, c := range extractCreds(ev) {
			if lbl := credLabel(c); lbl != "" {
				linkEntity("cred:"+lbl, lbl, "cred")
			}
		}
		if d, _ := ev.Meta["qname"].(string); d != "" {
			linkEntity("dom:"+strings.ToLower(d), shortLabel(d, 28), "domain")
		}
		for _, d := range metaStrings(ev.Meta, "contacted_domains") {
			linkEntity("dom:"+strings.ToLower(d), shortLabel(d, 28), "domain")
		}
		for _, h := range malwareKinds(ev) {
			linkEntity("mal:"+h, shortLabel(h, 16), "malware")
		}
	}

	txns = make([][]string, 0, len(actors))
	for _, a := range actors {
		if len(a.items) == 0 {
			continue
		}
		items := make([]string, 0, len(a.items))
		for it := range a.items {
			items = append(items, it)
		}
		txns = append(txns, items)
	}
	return txns, graph, actors
}

func credLabel(c credPair) string {
	if c.User == "" && c.Pass == "" {
		return ""
	}
	if c.Pass == "" {
		return c.User
	}
	return c.User + ":" + c.Pass
}

// encodePivotGraph serializes the top-centrality subgraph for charts.js's force
// renderer (base64 JSON {nodes:[{id,label,group,kind,size}], edges:[{from,to}]}),
// returning the encoding and the drawn edge count. Node size scales with
// betweenness (or degree when betweenness was skipped).
func encodePivotGraph(g *analytics.Graph, haveBetween bool) (string, int) {
	top := g.Nodes(anGraphDrawNodes)
	if len(top) == 0 {
		return "", 0
	}
	keep := make(map[string]bool, len(top))
	maxMetric := 0.0
	for _, n := range top {
		keep[n.ID] = true
		m := n.Betweenness
		if !haveBetween {
			m = float64(n.Degree)
		}
		if m > maxMetric {
			maxMetric = m
		}
	}
	type gnode struct {
		ID    string  `json:"id"`
		Label string  `json:"label,omitempty"`
		Group string  `json:"group,omitempty"`
		Kind  string  `json:"kind,omitempty"`
		Size  float64 `json:"size,omitempty"`
	}
	type gedge struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	nodes := make([]gnode, 0, len(top))
	for _, n := range top {
		metric := n.Betweenness
		if !haveBetween {
			metric = float64(n.Degree)
		}
		size := 4.0
		if maxMetric > 0 {
			size = 4 + 16*math.Sqrt(metric/maxMetric)
		}
		label := n.Label
		if n.Kind == "source" {
			label = "" // don't clutter the canvas with every IP label
		}
		nodes = append(nodes, gnode{ID: n.ID, Label: label, Group: n.Kind, Kind: n.Kind, Size: size})
	}
	var edges []gedge
	for _, e := range g.Edges() {
		if keep[e.From] && keep[e.To] {
			edges = append(edges, gedge{From: e.From, To: e.To})
		}
	}
	b, err := json.Marshal(map[string]any{"nodes": nodes, "edges": edges})
	if err != nil {
		return "", 0
	}
	return base64.StdEncoding.EncodeToString(b), len(edges)
}
