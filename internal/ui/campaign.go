package ui

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// encodeB64JSON marshals v and base64-encodes it for embedding in a chart
// data attribute (keeping the JSON clear of HTML-special characters). Returns
// "" on marshal failure so callers can treat it as "no graph".
func encodeB64JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Campaign / attacker-journey view. Two complementary lenses on the same
// window of events:
//
//   - The kill-chain journey: for each source we recover the chronological
//     sequence of ATT&CK tactics it moved through and tally the tactic→tactic
//     transitions across all sources. Rendered as a sankey, this is the
//     aggregate "journey" — how attackers progress from reconnaissance toward
//     impact against this sensor.
//   - Campaign clusters: source IPs are linked into campaigns when they share
//     a strong network fingerprint (JA3/JA4/JA4H/JA3S/HASSH). A shared TLS or
//     SSH fingerprint across distinct IPs is a high-confidence signal of one
//     toolset/operator behind multiple hosts, so each connected component is
//     treated as one campaign and summarised (members, the linking
//     fingerprints, kill-chain reached, techniques, handlers, harvested creds).
//
// Everything is recomputed from the stored events the same way the live router
// tags them (eventTag), so the view never drifts from the persisted columns.

const campaignWindow = 24 * time.Hour
const campaignScanMax = 20000
const campaignMaxClusters = 40

// linkFPKinds are the fingerprint kinds strong enough to link two distinct
// source IPs into one campaign. Each identifies a client toolset/stack, so a
// shared value across IPs is a high-confidence "same operator" signal. (HTTP
// User-Agent is deliberately excluded — it is trivially spoofed and shared by
// unrelated scanners.)
var linkFPKinds = []string{"ja4", "ja3", "ja4h", "ja3s", "hassh", "hassh_server"}

type campaignView struct {
	Since      time.Time
	Total      int // events scanned
	Sources    int // distinct source IPs
	Clusters   []campaignCluster
	Linked     int    // sources that fell into a multi-IP campaign
	JourneyB64 string // sankey: tactic→tactic transitions (the journey graph)
	GraphB64   string // network: campaign ↔ fingerprint ↔ handler linkage
}

type campaignCluster struct {
	ID         string
	Links      []fpChip // the shared fingerprint(s) that bind the members
	Sources    []string
	Multi      bool // more than one source IP (a real cross-host campaign)
	Events     int
	First      time.Time
	Last       time.Time
	MaxSev     string
	Tactics    []string // kill-chain ordered (the journey this campaign reached)
	Techniques []barRow
	Handlers   []barRow
	ASNs       []string
	Countries  []string
	Creds      int
}

// dsu is a tiny union-find over source-IP indices, used to group IPs that
// share a linking fingerprint into connected components (campaigns).
type dsu struct{ parent []int }

func newDSU(n int) *dsu {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &dsu{parent: p}
}

func (d *dsu) find(x int) int {
	for d.parent[x] != x {
		d.parent[x] = d.parent[d.parent[x]]
		x = d.parent[x]
	}
	return x
}

func (d *dsu) union(a, b int) {
	ra, rb := d.find(a), d.find(b)
	if ra != rb {
		d.parent[ra] = rb
	}
}

// srcAgg accumulates the per-source facts the campaign view needs.
type srcAgg struct {
	ip       string
	events   int
	first    time.Time
	last     time.Time
	maxSev   string
	fps      map[string]string // "kind/value" -> value (the linking keys)
	fpChips  []fpChip
	tactics  map[string]bool
	tech     map[string]int
	handlers map[string]int
	asns     map[string]bool
	country  map[string]bool
	creds    int
	// seq is the chronological tactic sequence (consecutive dups collapsed),
	// used to build the journey transition graph.
	seq []string
}

func buildCampaignView(since time.Time, evs []*event.Event) campaignView {
	v := campaignView{Since: since, Total: len(evs)}

	by := map[string]*srcAgg{}
	order := []string{}
	// Events come back time-DESC from the store; walk oldest-first so each
	// source's tactic sequence is in kill-chain order.
	for i := len(evs) - 1; i >= 0; i-- {
		ev := evs[i]
		ip := ev.Source.IP
		if ip == "" {
			continue
		}
		a := by[ip]
		if a == nil {
			a = &srcAgg{
				ip: ip, first: ev.Time,
				fps: map[string]string{}, tactics: map[string]bool{},
				tech: map[string]int{}, handlers: map[string]int{},
				asns: map[string]bool{}, country: map[string]bool{},
			}
			by[ip] = a
			order = append(order, ip)
		}
		a.events++
		a.last = ev.Time
		if sevRank(ev.Severity.String()) > sevRank(a.maxSev) {
			a.maxSev = ev.Severity.String()
		}
		for _, k := range linkFPKinds {
			if val, ok := ev.Meta[k].(string); ok && val != "" {
				key := k + "/" + val
				if _, seen := a.fps[key]; !seen {
					a.fps[key] = val
					a.fpChips = append(a.fpChips, fpChip{Kind: k, Value: val})
				}
			}
		}
		if ev.Handler != "" {
			a.handlers[ev.Handler]++
		}
		if asn := asnLabel(ev.Meta); asn != "" {
			a.asns[asn] = true
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			a.country[c] = true
		}
		a.creds += len(extractCreds(ev))
		tag := eventTag(ev)
		for _, t := range tag.Tactics {
			a.tactics[t] = true
			if n := len(a.seq); n == 0 || a.seq[n-1] != t {
				a.seq = append(a.seq, t)
			}
		}
		for _, t := range tag.Techniques {
			a.tech[t]++
		}
	}

	v.Sources = len(order)

	// Link sources sharing any fingerprint value into campaigns (union-find).
	idx := map[string]int{}
	for i, ip := range order {
		idx[ip] = i
	}
	d := newDSU(len(order))
	fpFirst := map[string]int{} // "kind/value" -> first source index
	for i, ip := range order {
		for key := range by[ip].fps {
			if j, ok := fpFirst[key]; ok {
				d.union(i, j)
			} else {
				fpFirst[key] = i
			}
		}
	}

	// Gather connected components into clusters.
	comp := map[int][]string{}
	for i, ip := range order {
		root := d.find(i)
		comp[root] = append(comp[root], ip)
	}

	for _, members := range comp {
		c := campaignCluster{Sources: members, Multi: len(members) > 1}
		techCount := map[string]int{}
		handlerCount := map[string]int{}
		tacSet := map[string]bool{}
		linkSet := map[string]fpChip{}
		asnSet := map[string]bool{}
		countrySet := map[string]bool{}
		linkCount := map[string]int{} // count members sharing each fp
		for _, ip := range members {
			a := by[ip]
			c.Events += a.events
			c.Creds += a.creds
			if c.First.IsZero() || a.first.Before(c.First) {
				c.First = a.first
			}
			if a.last.After(c.Last) {
				c.Last = a.last
			}
			if sevRank(a.maxSev) > sevRank(c.MaxSev) {
				c.MaxSev = a.maxSev
			}
			for t, n := range a.tech {
				techCount[t] += n
			}
			for h, n := range a.handlers {
				handlerCount[h] += n
			}
			for t := range a.tactics {
				tacSet[t] = true
			}
			for as := range a.asns {
				asnSet[as] = true
			}
			for co := range a.country {
				countrySet[co] = true
			}
			for _, fp := range a.fpChips {
				key := fp.Kind + "/" + fp.Value
				linkSet[key] = fp
				linkCount[key]++
			}
		}
		// Only fingerprints shared by 2+ members are the actual linking
		// evidence; for a single-IP campaign show its fingerprints as-is.
		for key, fp := range linkSet {
			if c.Multi && linkCount[key] < 2 {
				continue
			}
			c.Links = append(c.Links, fp)
		}
		sort.Slice(c.Links, func(i, j int) bool {
			if c.Links[i].Kind != c.Links[j].Kind {
				return c.Links[i].Kind < c.Links[j].Kind
			}
			return c.Links[i].Value < c.Links[j].Value
		})
		if len(c.Links) > 8 {
			c.Links = c.Links[:8]
		}
		c.Tactics = orderTactics(tacSet)
		c.Techniques = topBars(techCount, 10, "/attack/technique?id=")
		c.Handlers = topBars(handlerCount, 10, "")
		c.ASNs = sortedKeys(asnSet, 6)
		c.Countries = sortedKeys(countrySet, 8)
		sort.Strings(c.Sources)
		c.ID = clusterID(c.Sources)
		if c.Multi {
			v.Linked += len(members)
		}
		v.Clusters = append(v.Clusters, c)
	}

	// Most active / most dangerous campaigns first; multi-IP campaigns float
	// to the top since a linked cross-host campaign is the headline finding.
	sort.Slice(v.Clusters, func(i, j int) bool {
		a, b := v.Clusters[i], v.Clusters[j]
		if a.Multi != b.Multi {
			return a.Multi
		}
		if sevRank(a.MaxSev) != sevRank(b.MaxSev) {
			return sevRank(a.MaxSev) > sevRank(b.MaxSev)
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.ID < b.ID
	})
	if len(v.Clusters) > campaignMaxClusters {
		v.Clusters = v.Clusters[:campaignMaxClusters]
	}

	v.JourneyB64 = buildJourneySankey(by, order)
	v.GraphB64 = buildCampaignGraph(v.Clusters)
	return v
}

// buildJourneySankey tallies tactic→tactic transitions across every source's
// chronological tactic sequence and emits a sankey {nodes,links} the packaged
// charts.js renders. This is the aggregate attacker journey through the kill
// chain.
func buildJourneySankey(by map[string]*srcAgg, order []string) string {
	type tkey struct{ from, to string }
	trans := map[tkey]int{}
	nodeSet := map[string]bool{}
	for _, ip := range order {
		seq := by[ip].seq
		for i := 0; i+1 < len(seq); i++ {
			if seq[i] == seq[i+1] {
				continue
			}
			trans[tkey{seq[i], seq[i+1]}]++
			nodeSet[seq[i]] = true
			nodeSet[seq[i+1]] = true
		}
	}
	if len(trans) == 0 {
		return ""
	}
	type snode struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		// Layer pins the node to its kill-chain stage column. Without it the
		// renderer infers columns from link direction, which collapses into an
		// unreadable overlap once an attacker's path loops back (recon→exec→
		// recon), so we assign the canonical order here.
		Layer int `json:"layer"`
	}
	type slink struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Value  int    `json:"value"`
	}
	var nodes []snode
	// Emit nodes in kill-chain order so the sankey reads left→right, one column
	// per stage, with the column index pinned in Layer.
	for i, t := range orderTactics(nodeSet) {
		nodes = append(nodes, snode{ID: t, Label: t, Layer: i})
	}
	var links []slink
	for k, n := range trans {
		links = append(links, slink{Source: k.from, Target: k.to, Value: n})
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Value > links[j].Value })
	return encodeB64JSON(struct {
		Nodes []snode `json:"nodes"`
		Links []slink `json:"links"`
	}{nodes, links})
}

// buildCampaignGraph renders the multi-IP campaigns as a node-link graph:
// campaign ↔ its linking fingerprints ↔ the handlers it touched. Single-IP
// campaigns are omitted to keep the graph about cross-host linkage.
func buildCampaignGraph(clusters []campaignCluster) string {
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
	n := 0
	for _, c := range clusters {
		if !c.Multi {
			continue
		}
		if n++; n > 12 {
			break
		}
		cid := "camp:" + c.ID
		add(cid, "campaign "+c.ID+" ("+itoa(len(c.Sources))+" hosts)", "campaign")
		for _, fp := range c.Links {
			id := "fp:" + fp.Kind + ":" + fp.Value
			add(id, fp.Kind+":"+short(fp.Value), "fp")
			edges = append(edges, graphEdge{From: cid, To: id})
		}
		for _, h := range c.Handlers {
			id := "h:" + h.Label
			add(id, h.Label, "handler")
			edges = append(edges, graphEdge{From: cid, To: id})
		}
	}
	if len(nodes) == 0 {
		return ""
	}
	return encodeB64JSON(struct {
		Nodes []graphNode `json:"nodes"`
		Edges []graphEdge `json:"edges"`
	}{nodes, edges})
}

// clusterID is a short stable id for a campaign, derived from its sorted
// member IPs so the same set of hosts always renders the same label.
func clusterID(sources []string) string {
	h := sha1.New()
	for _, s := range sources {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

func sortedKeys(set map[string]bool, max int) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func (s *Server) handleCampaign(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-campaignWindow)
	evs, err := s.windowEvents(ctx, campaignWindow, campaignScanMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	cv := buildCampaignView(since, evs)
	for i := range cv.Clusters { // out-link technique bars to attack.mitre.org if enabled
		cv.Clusters[i].Techniques = s.linkTechBars(cv.Clusters[i].Techniques)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "campaign", cv); err != nil {
		slog.Warn("ui: render campaign", "err", err)
	}
}

func (s *Server) handleAPICampaign(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-campaignWindow)
	evs, err := s.windowEvents(ctx, campaignWindow, campaignScanMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	writeJSON(w, buildCampaignView(since, evs))
}
