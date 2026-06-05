package ui

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/portsvc"
)

// Additional analytics for the /charts page: port×hour heatmap, destination-port
// leaderboard, CVE age + EPSS-weighted exposure + CWE distribution, per-entity
// (ASN/country) trend sparklines, a force-directed actor-clustering graph, and a
// coverage-gap report (ports probed that no listener answers). All are pure
// aggregations over the same recent-events scan the rest of the page uses.

var seriesPalette = []string{"#4a6fa5", "#d59a3a", "#5a9367", "#c0506a", "#7e6bb5", "#3a8fb7", "#b3823a", "#7a8b99"}

func seriesColor(i int) string { return seriesPalette[i%len(seriesPalette)] }

// portLabel renders a destination port as "<n> <service>" when the port has a
// well-known name, else just the number.
func portLabel(p int) string {
	if n := portsvc.Name(p); n != "" {
		return strconv.Itoa(p) + " " + n
	}
	return strconv.Itoa(p)
}

// portHourHeatmap buckets events into destination-port × hour-of-day (UTC).
func portHourHeatmap(evs []*event.Event) (chartFig, bool) {
	cols := make([]string, 24)
	for h := 0; h < 24; h++ {
		cols[h] = fmt.Sprintf("%02d", h)
	}
	counts := map[string]map[string]int{}
	for _, ev := range evs {
		if ev.Dest.Port <= 0 {
			continue
		}
		row := portLabel(ev.Dest.Port)
		if counts[row] == nil {
			counts[row] = map[string]int{}
		}
		counts[row][fmt.Sprintf("%02d", ev.Time.UTC().Hour())]++
	}
	if len(counts) == 0 {
		return chartFig{}, false
	}
	return matrixHeatmap("heatmap", "Destination port × hour of day (UTC)", cols, counts, 18, "events"), true
}

// destPortLeaderboard ranks the most-probed destination ports.
func destPortLeaderboard(evs []*event.Event) (chartFig, bool) {
	c := map[int]int{}
	for _, ev := range evs {
		if ev.Dest.Port > 0 {
			c[ev.Dest.Port]++
		}
	}
	if len(c) == 0 {
		return chartFig{}, false
	}
	type kv struct{ p, n int }
	items := make([]kv, 0, len(c))
	for p, n := range c {
		items = append(items, kv{p, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].p < items[j].p
	})
	if len(items) > 20 {
		items = items[:20]
	}
	rows := make([]chBar, 0, len(items))
	for _, it := range items {
		rows = append(rows, chBar{Label: portLabel(it.p), Value: it.n})
	}
	return chartFigure("hbar", "Top destination ports probed", map[string]any{"series": rows}), true
}

// eventCVEs is defined in dashboard.go (collects an event's cve:* rule /
// anomaly / emulated-vuln markers).

func cveYear(id string) int {
	p := strings.Split(id, "-")
	if len(p) >= 2 {
		if y, err := strconv.Atoi(p[1]); err == nil {
			return y
		}
	}
	return 0
}

func cweLabel(c string) string {
	if n := cve.CWEName(c); n != "" {
		return c + " " + n
	}
	return c
}

// cveAnalytics builds the CVE leaderboard, the disclosure-year (n-day age)
// histogram, the EPSS-weighted exposure ranking, and the CWE distribution from
// the CVE exploit attempts in the window.
func cveAnalytics(evs []*event.Event) []chartFig {
	attempts := map[string]int{}
	for _, ev := range evs {
		for _, id := range eventCVEs(ev) {
			attempts[id]++
		}
	}
	if len(attempts) == 0 {
		return nil
	}
	var figs []chartFig

	// Leaderboard.
	figs = append(figs, chartFigure("hbar", "Top CVE exploit attempts", map[string]any{"series": topBarsFromMap(attempts, 20)}))

	// Disclosure-year histogram (how old are the exploits being thrown).
	yearCount := map[int]int{}
	for id, n := range attempts {
		if y := cveYear(id); y > 0 {
			yearCount[y] += n
		}
	}
	if len(yearCount) > 0 {
		years := sortedIntKeys(yearCount)
		bins := make([]chBar, 0, len(years))
		for _, y := range years {
			bins = append(bins, chBar{Label: strconv.Itoa(y), Value: yearCount[y]})
		}
		figs = append(figs, chartFigure("bar", "CVE attempts by disclosure year (n-day age)", map[string]any{"series": bins}))
	}

	// EPSS-weighted exposure: attempts × EPSS, the relative-priority ranking.
	type wkv struct {
		id string
		w  float64
	}
	var weighted []wkv
	for id, n := range attempts {
		if rec, ok := cve.Lookup(id); ok && rec.EPSS > 0 {
			weighted = append(weighted, wkv{id, float64(n) * rec.EPSS})
		}
	}
	if len(weighted) > 0 {
		sort.Slice(weighted, func(i, j int) bool { return weighted[i].w > weighted[j].w })
		if len(weighted) > 15 {
			weighted = weighted[:15]
		}
		rows := make([]chBar, 0, len(weighted))
		for _, w := range weighted {
			rows = append(rows, chBar{Label: w.id, Value: int(w.w*100 + 0.5)}) // ×100 so small EPSS still renders
		}
		figs = append(figs, chartFigure("hbar", "EPSS-weighted exposure (attempts × EPSS ×100)", map[string]any{"series": rows}))
	}

	// CWE weakness classes targeted.
	cweCount := map[string]int{}
	for id, n := range attempts {
		if rec, ok := cve.Lookup(id); ok {
			for _, c := range rec.CWE {
				cweCount[cweLabel(c)] += n
			}
		}
	}
	if len(cweCount) > 0 {
		figs = append(figs, chartFigure("hbar", "Weakness classes targeted (CWE)", map[string]any{"series": topBarsFromMap(cweCount, 15)}))
	}
	return figs
}

// entitySparklines renders one trend line per top entity (e.g. ASN, country)
// over time, so you can see which sources are ramping up or fading.
func entitySparklines(title string, evs []*event.Event, key func(*event.Event) string, n int, bucket time.Duration) (chartFig, bool) {
	if bucket <= 0 {
		bucket = time.Hour
	}
	total := map[string]int{}
	for _, ev := range evs {
		if k := key(ev); k != "" {
			total[k]++
		}
	}
	top := topKeys(total, n)
	if len(top) == 0 {
		return chartFig{}, false
	}
	want := map[string]bool{}
	for _, k := range top {
		want[k] = true
	}
	series := map[string]map[int64]int{}
	for _, k := range top {
		series[k] = map[int64]int{}
	}
	for _, ev := range evs {
		k := key(ev)
		if !want[k] {
			continue
		}
		series[k][ev.Time.Truncate(bucket).UnixMilli()]++
	}
	out := make([]map[string]any, 0, len(top))
	for i, k := range top {
		buckets := sortedInt64Keys(series[k])
		pts := make([]chPoint, 0, len(buckets))
		for _, b := range buckets {
			pts = append(pts, chPoint{X: float64(b), Y: float64(series[k][b])})
		}
		out = append(out, map[string]any{"name": k, "points": pts, "color": seriesColor(i)})
	}
	return chartFigure("line", title, map[string]any{"series": out, "xType": "time"}), true
}

// actorGraph builds a force-directed clustering graph: each top source IP links
// to its ASN and TLS/SSH fingerprint hub nodes, so a single actor rotating IPs
// across one ASN / reusing a fingerprint forms a visible cluster.
func actorGraph(evs []*event.Event) (chartFig, bool) {
	const maxSources = 40
	srcCount := map[string]int{}
	srcASN := map[string]string{}
	srcFP := map[string]string{}
	for _, ev := range evs {
		ip := ev.Source.IP
		if ip == "" {
			continue
		}
		srcCount[ip]++
		if a := asnLabel(ev.Meta); a != "" {
			srcASN[ip] = a
		}
		if _, ok := srcFP[ip]; !ok {
			for _, k := range []string{"ja4", "ja4h", "ja3", "hassh"} {
				if v, _ := ev.Meta[k].(string); v != "" {
					srcFP[ip] = k + ":" + v
					break
				}
			}
		}
	}
	top := topKeys(srcCount, maxSources)
	if len(top) < 2 {
		return chartFig{}, false
	}
	var nodes []chNode
	var edges []chEdge
	hub := map[string]bool{}
	addHub := func(id, label, kind string) {
		if !hub[id] {
			hub[id] = true
			nodes = append(nodes, chNode{ID: id, Label: label, Group: id, Kind: kind})
		}
	}
	for _, ip := range top {
		grp := srcASN[ip]
		if grp == "" {
			grp = "unknown"
		}
		nodes = append(nodes, chNode{ID: "ip:" + ip, Label: ip, Group: grp, Kind: "source"})
		if a := srcASN[ip]; a != "" {
			addHub("asn:"+a, a, "asn")
			edges = append(edges, chEdge{From: "ip:" + ip, To: "asn:" + a})
		}
		if f := srcFP[ip]; f != "" {
			addHub("fp:"+f, shortLabel(f, 22), "fingerprint")
			edges = append(edges, chEdge{From: "ip:" + ip, To: "fp:" + f})
		}
	}
	return chartFigure("force", "Actor clustering (sources ↔ shared ASN / fingerprint)",
		map[string]any{"nodes": nodes, "edges": edges}), true
}

// covRow is one row of the coverage-gap report.
type covRow struct {
	Port    int
	Label   string
	Count   int
	Sources int
}

// coverageGap reports destination ports that were probed but that no configured
// listener answers — a "what are they scanning that we don't emulate" list that
// doubles as a recommendation for which decoys to add next.
func coverageGap(cfg *config.Config, evs []*event.Event) (chartFig, []covRow, bool) {
	configured := configuredPorts(cfg)
	count := map[int]int{}
	srcs := map[int]map[string]bool{}
	for _, ev := range evs {
		p := ev.Dest.Port
		if p <= 0 || configured[p] {
			continue
		}
		count[p]++
		if srcs[p] == nil {
			srcs[p] = map[string]bool{}
		}
		if ev.Source.IP != "" {
			srcs[p][ev.Source.IP] = true
		}
	}
	if len(count) == 0 {
		return chartFig{}, nil, false
	}
	rows := make([]covRow, 0, len(count))
	for p, n := range count {
		rows = append(rows, covRow{Port: p, Label: portLabel(p), Count: n, Sources: len(srcs[p])})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Port < rows[j].Port
	})
	if len(rows) > 30 {
		rows = rows[:30]
	}
	bars := make([]chBar, 0, len(rows))
	for i, r := range rows {
		if i >= 15 {
			break
		}
		bars = append(bars, chBar{Label: r.Label, Value: r.Count})
	}
	return chartFigure("hbar", "Coverage gap — probed ports with no listener", map[string]any{"series": bars}), rows, true
}

// configuredPorts is the set of TCP/UDP ports answered by a configured listener
// or a honeynet host service.
func configuredPorts(cfg *config.Config) map[int]bool {
	out := map[int]bool{}
	if cfg == nil {
		return out
	}
	for _, l := range cfg.Listeners {
		if _, port, err := net.SplitHostPort(l.Bind); err == nil {
			if p, err := strconv.Atoi(port); err == nil {
				out[p] = true
			}
		}
	}
	for _, hn := range cfg.Honeynets {
		for _, h := range hn.Hosts {
			for _, sp := range h.Services {
				if sp.Port > 0 {
					out[sp.Port] = true
				}
			}
		}
	}
	return out
}

// --- small shared helpers --------------------------------------------------

func topBarsFromMap(m map[string]int, n int) []chBar {
	keys := topKeys(m, n)
	out := make([]chBar, 0, len(keys))
	for _, k := range keys {
		out = append(out, chBar{Label: k, Value: m[k]})
	}
	return out
}

func sortedIntKeys(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedInt64Keys(m map[int64]int) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func shortLabel(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
