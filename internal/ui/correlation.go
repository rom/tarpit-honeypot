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
)

// Correlation view: per-source pivot chains linking the entities a single
// actor touches — IP → network fingerprints → User-Agents → ASN/country →
// domains → tools → captured credentials → malware artifacts → sessions.
// Rendered both as linked chips (the no-JS fallback, each pivoting to the
// relevant view) and as a base64-embedded node-link graph that the packaged
// app.js draws as interactive SVG ("IP→JA4→UA→Payload→Domain→ASN").

const corrScanMax = 20000
const corrMaxSources = 30
const corrMaxPerList = 12

type correlationView struct {
	Since      time.Time
	RangeKey   string
	RangeLabel string
	RangeLinks []rangeLink
	Total      int
	Sources    []corrSource
	// Clusters are groups of source IPs tied together by shared infrastructure
	// (a fingerprint / pubkey / credential / domain / malware used by two or
	// more of them) — the actual correlation finding, ranked strongest first.
	Clusters []corrCluster
	// SharedCount is how many distinct shared pivots were found in the window.
	SharedCount int
	// GraphB64 is a base64-encoded JSON {sources,hubs,edges} the packaged
	// charts.js renders as a bipartite "shared-infrastructure" graph: source
	// IPs on the left, the entities they share on the right. Base64 keeps it
	// free of HTML-special characters so it embeds cleanly in a data attribute.
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

// sharedNode is one node in the bipartite shared-infrastructure graph.
type sharedNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind,omitempty"`
	Sev   string `json:"sev,omitempty"`
	Count int    `json:"count,omitempty"`
}

// sharedPivot is one entity (and the kind of entity) that two or more source
// IPs have in common — the evidence that links them.
type sharedPivot struct {
	Kind  string // fp | pubkey | cred | domain | malware
	Label string // display text (and the thing clicked to pivot)
	Href  string // where the chip links, if anywhere
	IPs   int    // how many distinct source IPs share it
}

// corrCluster is a connected component of source IPs joined by shared pivots.
type corrCluster struct {
	ID      string
	Members []string
	Events  int
	MaxSev  string
	Shared  []sharedPivot
}

// linkPivotKinds are the entity kinds strong enough to correlate two distinct
// source IPs. Deliberately high-signal: a shared TLS/SSH fingerprint, reused
// SSH pubkey, identical credential, C2/ingress domain or malware artifact each
// points at one operator/toolset. ASN / User-Agent / generic tool name are
// excluded — they're broad or trivially shared, so they'd link unrelated hosts.
var linkPivotKinds = map[string]bool{
	"fp": true, "pubkey": true, "cred": true, "domain": true, "malware": true,
}

const (
	corrGraphMaxSources = 40
	corrGraphMaxHubs    = 28
	corrMaxClusters     = 40
)

// buildSharedGraph renders the shared-infrastructure bipartite graph from the
// pivot index: only pivots shared by 2+ IPs become hubs, and only the IPs that
// touch a shared hub appear — so every edge is correlation evidence.
func buildSharedGraph(sources []corrSource, pivotIPs map[string]map[string]bool, pivotInfo map[string]sharedPivot) string {
	sevByIP := map[string]string{}
	cntByIP := map[string]int{}
	for _, s := range sources {
		sevByIP[s.IP] = s.MaxSev
		cntByIP[s.IP] = s.Count
	}
	// Collect shared pivots, strongest (most IPs) first.
	type hub struct {
		key string
		p   sharedPivot
	}
	var hubs []hub
	for key, ips := range pivotIPs {
		if len(ips) < 2 {
			continue
		}
		info := pivotInfo[key]
		info.IPs = len(ips)
		hubs = append(hubs, hub{key, info})
	}
	sort.Slice(hubs, func(i, j int) bool {
		if hubs[i].p.IPs != hubs[j].p.IPs {
			return hubs[i].p.IPs > hubs[j].p.IPs
		}
		return hubs[i].key < hubs[j].key
	})
	if len(hubs) > corrGraphMaxHubs {
		hubs = hubs[:corrGraphMaxHubs]
	}
	var gsrc, ghub []sharedNode
	var edges []graphEdge
	srcSeen := map[string]bool{}
	for _, h := range hubs {
		hid := "hub:" + h.key
		ghub = append(ghub, sharedNode{ID: hid, Label: h.p.Label, Kind: h.p.Kind, Count: h.p.IPs})
		for ip := range pivotIPs[h.key] {
			sid := "ip:" + ip
			if !srcSeen[ip] {
				if len(gsrc) >= corrGraphMaxSources {
					continue
				}
				srcSeen[ip] = true
				gsrc = append(gsrc, sharedNode{ID: sid, Label: ip, Sev: sevByIP[ip], Count: cntByIP[ip]})
			}
			edges = append(edges, graphEdge{From: sid, To: hid})
		}
	}
	if len(gsrc) == 0 || len(ghub) == 0 {
		return ""
	}
	b, err := json.Marshal(struct {
		Sources []sharedNode `json:"sources"`
		Hubs    []sharedNode `json:"hubs"`
		Edges   []graphEdge  `json:"edges"`
	}{gsrc, ghub, edges})
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

	// Cross-source pivot index: "kind\x00value" -> set of source IPs, plus the
	// display info for that pivot. A pivot shared by 2+ IPs is the correlation
	// evidence that binds them.
	pivotIPs := map[string]map[string]bool{}
	pivotInfo := map[string]sharedPivot{}
	recordPivot := func(ip, kind, value, label, href string) {
		if value == "" {
			return
		}
		key := kind + "\x00" + value
		set := pivotIPs[key]
		if set == nil {
			set = map[string]bool{}
			pivotIPs[key] = set
			pivotInfo[key] = sharedPivot{Kind: kind, Label: label, Href: href}
		}
		set[ip] = true
	}

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
				recordPivot(ip, "fp", k+"/"+val, k+":"+short(val), "/fingerprints/"+k+"/"+val)
			}
		}
		for _, pk := range metaStrings(ev.Meta, "ssh_pubkey_fps") {
			recordPivot(ip, "pubkey", pk, "pubkey:"+short(pk), "")
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
			recordPivot(ip, "domain", d, short(d), "/search?q="+d)
		}
		for _, t := range metaStrings(ev.Meta, "tools") {
			addCapped(&a.s.Tools, a.tool, t, corrMaxPerList)
		}
		for _, c := range extractCreds(ev) {
			label := c.User
			if c.Pass != "" {
				label += " : " + c.Pass
			}
			if label != "" && label != " : " {
				addCapped(&a.s.Creds, a.cred, label, corrMaxPerList)
				recordPivot(ip, "cred", label, label, "")
			}
		}
		for _, m := range malwareKinds(ev) {
			addCapped(&a.s.Malware, a.mal, m, corrMaxPerList)
			recordPivot(ip, "malware", m, short(m), "")
		}
		for _, t := range eventTag(ev).Tactics {
			a.tactic[t] = true
		}
		if _, ok := ev.Meta["session_cast"]; ok {
			a.s.Sessions++
		}
	}

	// Drop pivots not shared by 2+ IPs, and broad/low-signal kinds, before
	// clustering — they'd link unrelated hosts.
	for key, ips := range pivotIPs {
		if len(ips) < 2 || !linkPivotKinds[pivotInfo[key].Kind] {
			delete(pivotIPs, key)
			delete(pivotInfo, key)
		}
	}
	v.SharedCount = len(pivotIPs)

	allSources := make([]corrSource, 0, len(order))
	for _, ip := range order {
		a := by[ip]
		a.s.Tactics = orderTactics(a.tactic)
		allSources = append(allSources, a.s)
	}

	v.Clusters = buildCorrClusters(order, allSources, pivotIPs, pivotInfo)
	v.GraphB64 = buildSharedGraph(allSources, pivotIPs, pivotInfo)

	// Detail list: busiest sources first, bounded.
	v.Sources = append(v.Sources, allSources...)
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

// buildCorrClusters groups IPs that share any linking pivot into connected
// components (union-find) and summarises each: members, event volume, peak
// severity, and the shared pivots that bind them.
func buildCorrClusters(order []string, sources []corrSource, pivotIPs map[string]map[string]bool, pivotInfo map[string]sharedPivot) []corrCluster {
	if len(pivotIPs) == 0 {
		return nil
	}
	idx := map[string]int{}
	for i, ip := range order {
		idx[ip] = i
	}
	d := newDSU(len(order))
	for key := range pivotIPs {
		var first = -1
		for ip := range pivotIPs[key] {
			i, ok := idx[ip]
			if !ok {
				continue
			}
			if first < 0 {
				first = i
			} else {
				d.union(first, i)
			}
		}
	}
	srcByIP := map[string]corrSource{}
	for _, s := range sources {
		srcByIP[s.IP] = s
	}
	comp := map[int][]string{}
	for i, ip := range order {
		root := d.find(i)
		comp[root] = append(comp[root], ip)
	}
	var out []corrCluster
	for _, members := range comp {
		if len(members) < 2 {
			continue // a lone IP isn't correlated with anything
		}
		sort.Strings(members)
		memberSet := map[string]bool{}
		for _, m := range members {
			memberSet[m] = true
		}
		c := corrCluster{ID: clusterID(members), Members: members}
		for _, m := range members {
			s := srcByIP[m]
			c.Events += s.Count
			if sevRank(s.MaxSev) > sevRank(c.MaxSev) {
				c.MaxSev = s.MaxSev
			}
		}
		// The shared pivots that live entirely within this cluster.
		for key, ips := range pivotIPs {
			within := 0
			for ip := range ips {
				if memberSet[ip] {
					within++
				}
			}
			if within >= 2 {
				p := pivotInfo[key]
				p.IPs = within
				c.Shared = append(c.Shared, p)
			}
		}
		sort.Slice(c.Shared, func(i, j int) bool {
			if c.Shared[i].IPs != c.Shared[j].IPs {
				return c.Shared[i].IPs > c.Shared[j].IPs
			}
			return c.Shared[i].Label < c.Shared[j].Label
		})
		if len(c.Shared) > 12 {
			c.Shared = c.Shared[:12]
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Members) != len(out[j].Members) {
			return len(out[i].Members) > len(out[j].Members)
		}
		if sevRank(out[i].MaxSev) != sevRank(out[j].MaxSev) {
			return sevRank(out[i].MaxSev) > sevRank(out[j].MaxSev)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > corrMaxClusters {
		out = out[:corrMaxClusters]
	}
	return out
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
	dur, rkey, rlabel, rlinks := pageRange(r, "/correlation")
	since := time.Now().Add(-dur)
	evs, err := s.windowEvents(ctx, dur, corrScanMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	view := buildCorrelationView(since, evs)
	view.RangeKey, view.RangeLabel, view.RangeLinks = rkey, rlabel, rlinks
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "correlation", view); err != nil {
		slog.Warn("ui: render correlation", "err", err)
	}
}
