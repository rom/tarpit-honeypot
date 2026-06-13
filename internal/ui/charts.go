package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// handleCharts renders the analytics page: every chart type the packaged
// charts.js supports, driven by the same 24h data as the summary dashboard.
//
// Operators can narrow every chart with include ("only") / exclude patterns on
// source IP, ASN, country, rule, handler, port and proto — multiple at once
// (e.g. exclude two noisy IPs and an ASN). With no filter active it keeps the
// fast, full-window SQL path; once a filter is set it derives the whole page
// from the filtered event scan so every chart reflects the same set.
func (s *Server) handleCharts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// One-shot "add filter" submit (mode + dim + val from the add form): fold it
	// into the canonical only=/exclude= params and redirect, so the URL stays
	// bookmarkable and a refresh doesn't re-add the same clause.
	if strings.TrimSpace(q.Get("val")) != "" {
		http.Redirect(w, r, chartAddRedirect(q), http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	win := summaryRange(q.Get("range"))
	since := time.Now().Add(-win.dur)
	only, exclude := parseChartFilters(q)
	filtered := len(only)+len(exclude) > 0

	var (
		sum   store.Summary
		hours []store.HourBucket
		evs   []*event.Event
	)
	if !filtered {
		// Fast path (unchanged): full-window, index-backed SQL summary + buckets,
		// plus a 20k scan for the meta-derived charts. NoPayload: the enrichment
		// reads meta dimensions only (tactics / geo / ASN / tool / handler / CVE),
		// never the payload bytes or banner, so skip dragging 20k blobs through.
		var err error
		if sum, err = s.store.Summary(ctx, since); err != nil {
			serverError(w, r.URL.Path, err)
			return
		}
		sum.TopSources = s.visibleSourceCounts(sum.TopSources) // presentation hide list
		hours, _ = s.store.EventsPerBucket(ctx, since, win.bucket)
		if e, qerr := s.query(ctx, store.Filter{Since: since, Limit: 20000, NoPayload: true}); qerr == nil {
			evs = e
		}
	} else {
		// Filtered: push the include/exclude into the scan (s.query also drops
		// hidden IPs), then derive the summary + trend from exactly the events
		// that survive — so every chart, not just the meta-derived ones, reflects
		// the same filtered set.
		f := chartFiltersToStore(only, exclude, store.Filter{Since: since, Limit: maxEventsLimit, NoPayload: true})
		if e, qerr := s.query(ctx, f); qerr == nil {
			evs = e
		}
		sum = summaryFromEvents(evs, since)
		hours = bucketsFromEvents(evs, since, win.bucket)
	}

	d := buildDashboard(sum, hours, win.bucket)
	enrichDashboard(&d, evs)
	page := buildAnalytics(d, hours, evs)
	if fig, rows, ok := coverageGap(s.fullConfig, evs); ok {
		page.Sections = append(page.Sections, chartSection{Heading: "Coverage gap", Figs: []chartFig{fig}})
		page.CoverageGap = rows
	}
	page.RangeLabel = win.label
	page.RangeLinks = rangeLinksForCharts(win.key, only, exclude)
	page.Filters = chartFilterChips(win.key, only, exclude)
	page.FilterActive = filtered
	page.FilterCarry = chartFilterHidden(win.key, only, exclude)
	page.FilterDims = chartFilterDims
	page.ClearHref = chartClearHref(win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "charts", page); err != nil {
		slog.Warn("ui: render charts", "err", err)
	}
}

// chartFig is a server-emitted charts.js figure: a chart type + base64-encoded
// JSON config the packaged charts.js renders client-side. base64 keeps the JSON
// out of HTML-escaping's way and matches the existing data-graph-b64 pattern.
// The "chartfig" template block renders it with a no-JS fallback.
type chartFig struct {
	Type  string
	Title string
	B64   string
}

func chartFigure(typ, title string, data any) chartFig {
	b, err := json.Marshal(data)
	if err != nil {
		return chartFig{Type: typ, Title: title}
	}
	return chartFig{Type: typ, Title: title, B64: base64.StdEncoding.EncodeToString(b)}
}

// chartSection groups figures under a heading on the analytics page.
type chartSection struct {
	Heading string
	Figs    []chartFig
}

type chartsPage struct {
	Sections    []chartSection
	CoverageGap []covRow
	Scanned     int
	Empty       bool
	RangeLabel  string
	RangeLinks  []rangeLink
	// Include/exclude filter UI.
	Filters      []chartChip   // active filter pills (with remove links)
	FilterActive bool          // any filter set
	FilterCarry  []chartHidden // hidden inputs so the add form keeps current state
	FilterDims   []string      // dimensions offered in the add form's <select>
	ClearHref    string        // "clear all" target (keeps the range)
}

// --- chart include/exclude filters -----------------------------------------

// chartFilterDims are the dimensions an operator can build an only/exclude
// pattern on, in the order the add-form <select> offers them. Kept in sync with
// chartFiltersToStore below.
var chartFilterDims = []string{"ip", "asn", "asn_org", "country", "country_name", "city", "rule", "handler", "port", "proto"}

func chartDimOK(d string) bool {
	for _, x := range chartFilterDims {
		if x == d {
			return true
		}
	}
	return false
}

// chartDimVal is one include/exclude clause: a dimension + the value to match.
type chartDimVal struct{ Dim, Val string }

// chartChip is one active-filter pill: its mode/dim/value for display and the
// URL that removes just that clause.
type chartChip struct {
	Mode       string // "only" / "exclude"
	Dim        string
	Val        string
	RemoveHref string
}

// chartHidden is a name/value pair rendered as a hidden <input> so the add form
// carries the current range + filters forward when a new clause is submitted.
type chartHidden struct{ Name, Value string }

// parseChartFilters reads the repeated only=/exclude= params (each "dim:value")
// into ordered, de-duplicated include / exclude lists, keeping only known
// dimensions with a non-empty value.
func parseChartFilters(q url.Values) (only, exclude []chartDimVal) {
	parse := func(key string) []chartDimVal {
		var out []chartDimVal
		seen := map[string]bool{}
		for _, raw := range q[key] {
			raw = strings.TrimSpace(raw)
			i := strings.IndexByte(raw, ':')
			if i <= 0 {
				continue
			}
			dim := strings.ToLower(strings.TrimSpace(raw[:i]))
			val := strings.TrimSpace(raw[i+1:])
			if val == "" || !chartDimOK(dim) || seen[dim+":"+val] {
				continue
			}
			seen[dim+":"+val] = true
			out = append(out, chartDimVal{Dim: dim, Val: val})
		}
		return out
	}
	return parse("only"), parse("exclude")
}

// chartFiltersToStore folds the include / exclude clauses onto a base store
// filter, mapping each chart dimension to its column / meta filter.
func chartFiltersToStore(only, exclude []chartDimVal, base store.Filter) store.Filter {
	apply := func(list []chartDimVal, incl bool) {
		for _, dv := range list {
			switch dv.Dim {
			case "ip":
				if incl {
					base.SourceIPs = append(base.SourceIPs, dv.Val)
				} else {
					base.ExcludeSourceIPs = append(base.ExcludeSourceIPs, dv.Val)
				}
			case "rule":
				if incl {
					base.RuleIDs = append(base.RuleIDs, dv.Val)
				} else {
					base.ExcludeRuleIDs = append(base.ExcludeRuleIDs, dv.Val)
				}
			case "handler":
				if incl {
					base.Handlers = append(base.Handlers, dv.Val)
				} else {
					base.ExcludeHandlers = append(base.ExcludeHandlers, dv.Val)
				}
			case "proto":
				if incl {
					base.Protos = append(base.Protos, dv.Val)
				} else {
					base.ExcludeProtos = append(base.ExcludeProtos, dv.Val)
				}
			case "country":
				cv := strings.ToUpper(dv.Val)
				if incl {
					base.Countries = append(base.Countries, cv)
				} else {
					base.ExcludeCountries = append(base.ExcludeCountries, cv)
				}
			case "asn":
				if n := parseASN(dv.Val); n > 0 {
					if incl {
						base.ASNs = append(base.ASNs, n)
					} else {
						base.ExcludeASNs = append(base.ExcludeASNs, n)
					}
				}
			case "port":
				if n, err := strconv.Atoi(dv.Val); err == nil && n > 0 && n <= 65535 {
					if incl {
						base.DstPorts = append(base.DstPorts, n)
					} else {
						base.ExcludeDstPorts = append(base.ExcludeDstPorts, n)
					}
				}
			case "city":
				if incl {
					base.Cities = append(base.Cities, dv.Val)
				} else {
					base.ExcludeCities = append(base.ExcludeCities, dv.Val)
				}
			case "country_name":
				if incl {
					base.CountryNames = append(base.CountryNames, dv.Val)
				} else {
					base.ExcludeCountryNames = append(base.ExcludeCountryNames, dv.Val)
				}
			case "asn_org":
				if incl {
					base.ASNOrgs = append(base.ASNOrgs, dv.Val)
				} else {
					base.ExcludeASNOrgs = append(base.ExcludeASNOrgs, dv.Val)
				}
			}
		}
	}
	apply(only, true)
	apply(exclude, false)
	return base
}

// chartQuery builds the canonical query (range + every only/exclude clause) for
// a charts URL — the single source of truth the range chips, the active-filter
// remove links and the add-form redirect all serialize through.
func chartQuery(key string, only, exclude []chartDimVal) url.Values {
	v := url.Values{}
	if key != "" && key != "24h" {
		v.Set("range", key)
	}
	for _, dv := range only {
		v.Add("only", dv.Dim+":"+dv.Val)
	}
	for _, dv := range exclude {
		v.Add("exclude", dv.Dim+":"+dv.Val)
	}
	return v
}

func chartsURL(v url.Values) string {
	if enc := v.Encode(); enc != "" {
		return "/charts?" + enc
	}
	return "/charts"
}

func rangeLinksForCharts(active string, only, exclude []chartDimVal) []rangeLink {
	out := []rangeLink{}
	for _, key := range summaryRanges {
		out = append(out, rangeLink{Label: key, Href: chartsURL(chartQuery(key, only, exclude)), Active: key == active})
	}
	return out
}

func removeChartFilter(list []chartDimVal, i int) []chartDimVal {
	out := make([]chartDimVal, 0, len(list)-1)
	out = append(out, list[:i]...)
	return append(out, list[i+1:]...)
}

func chartFilterChips(key string, only, exclude []chartDimVal) []chartChip {
	var chips []chartChip
	for i, dv := range only {
		chips = append(chips, chartChip{Mode: "only", Dim: dv.Dim, Val: dv.Val,
			RemoveHref: chartsURL(chartQuery(key, removeChartFilter(only, i), exclude))})
	}
	for i, dv := range exclude {
		chips = append(chips, chartChip{Mode: "exclude", Dim: dv.Dim, Val: dv.Val,
			RemoveHref: chartsURL(chartQuery(key, only, removeChartFilter(exclude, i)))})
	}
	return chips
}

func chartFilterHidden(key string, only, exclude []chartDimVal) []chartHidden {
	var out []chartHidden
	if key != "" && key != "24h" {
		out = append(out, chartHidden{"range", key})
	}
	for _, dv := range only {
		out = append(out, chartHidden{"only", dv.Dim + ":" + dv.Val})
	}
	for _, dv := range exclude {
		out = append(out, chartHidden{"exclude", dv.Dim + ":" + dv.Val})
	}
	return out
}

func chartClearHref(key string) string {
	v := url.Values{}
	if key != "" && key != "24h" {
		v.Set("range", key)
	}
	return chartsURL(v)
}

// chartAddRedirect turns an add-form submit (mode + dim + val, alongside the
// existing only/exclude params) into the canonical charts URL to redirect to.
func chartAddRedirect(q url.Values) string {
	only, exclude := parseChartFilters(q)
	dim := strings.ToLower(strings.TrimSpace(q.Get("dim")))
	val := strings.TrimSpace(q.Get("val"))
	if chartDimOK(dim) && val != "" {
		dv := chartDimVal{Dim: dim, Val: val}
		if q.Get("mode") == "exclude" {
			exclude = append(exclude, dv)
		} else {
			only = append(only, dv)
		}
	}
	return chartsURL(chartQuery(q.Get("range"), only, exclude))
}

// summaryFromEvents rebuilds the store.Summary aggregates from an in-memory
// event slice — used when chart filters are active, so the severity / rule /
// source / handler / target / country charts reflect exactly the filtered set,
// the way the SQL Summary would over the full window.
func summaryFromEvents(evs []*event.Event, since time.Time) store.Summary {
	sum := store.Summary{
		Since: since, BySeverity: map[string]int{}, ByRule: map[string]int{},
		ByProto: map[string]int{}, ByHandler: map[string]int{}, ByTarget: map[string]int{},
		ByCountry: map[string]int{},
	}
	srcCount := map[string]int{}
	for _, ev := range evs {
		sum.Total++
		sum.BySeverity[ev.Severity.String()]++
		if ev.RuleID != "" {
			sum.ByRule[ev.RuleID]++
		}
		if ev.Proto != "" {
			sum.ByProto[ev.Proto]++
		}
		if ev.Handler != "" {
			sum.ByHandler[ev.Handler]++
		}
		if ev.Dest.IP != "" {
			sum.ByTarget[ev.Dest.IP]++
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			sum.ByCountry[c]++
		}
		if ev.Source.IP != "" {
			srcCount[ev.Source.IP]++
		}
	}
	// Top 10 source IPs, matching the SQL summary's LIMIT 10.
	srcs := make([]store.SourceCount, 0, len(srcCount))
	for ip, c := range srcCount {
		srcs = append(srcs, store.SourceCount{IP: ip, Count: c})
	}
	sort.Slice(srcs, func(i, j int) bool {
		if srcs[i].Count != srcs[j].Count {
			return srcs[i].Count > srcs[j].Count
		}
		return srcs[i].IP < srcs[j].IP
	})
	if len(srcs) > 10 {
		srcs = srcs[:10]
	}
	sum.TopSources = srcs
	return sum
}

// bucketsFromEvents rebuilds the events-per-bucket trend from an in-memory event
// slice (zero-filled like store.EventsPerBucket), for the filtered path.
func bucketsFromEvents(evs []*event.Event, since time.Time, bucket time.Duration) []store.HourBucket {
	hourNS := int64(bucket)
	if hourNS <= 0 {
		hourNS = int64(time.Hour)
	}
	startBucket := since.UTC().UnixNano() / hourNS
	nowBucket := time.Now().UTC().UnixNano() / hourNS
	if nowBucket < startBucket {
		nowBucket = startBucket
	}
	counts := map[int64]int{}
	for _, ev := range evs {
		counts[ev.Time.UTC().UnixNano()/hourNS]++
	}
	out := make([]store.HourBucket, 0, nowBucket-startBucket+1)
	for b := startBucket; b <= nowBucket; b++ {
		out = append(out, store.HourBucket{Hour: time.Unix(0, b*hourNS).UTC(), Count: counts[b]})
	}
	return out
}

// --- chart JSON shapes (match the schemas documented in charts.js) ---------

type chBar struct {
	Label string `json:"label"`
	Value int    `json:"value"`
	Sev   string `json:"sev,omitempty"`
}
type chSlice struct {
	Label string `json:"label"`
	Value int    `json:"value"`
	Color string `json:"color,omitempty"`
}
type chPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}
type chMapPt struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Count   int     `json:"count"`
	Label   string  `json:"label,omitempty"`
	Sev     string  `json:"sev,omitempty"`
	Country string  `json:"country,omitempty"` // links the bubble to /events?country=
}
type chNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group,omitempty"`
	Kind  string `json:"kind,omitempty"`
	OS    string `json:"os,omitempty"`
}
type chEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}
type chCred struct {
	User  string `json:"user"`
	Pass  string `json:"pass"`
	Count int    `json:"count"`
}

func sevColor(s string) string {
	switch s {
	case "low":
		return "#6b8fb5"
	case "medium":
		return "#d59a3a"
	case "high":
		return "#c0506a"
	case "critical":
		return "#b00020"
	}
	return ""
}

// barsToBar / barsToPie adapt the dashboard's []barRow charts to chart configs.
func barsToBar(rows []barRow) any {
	out := make([]chBar, 0, len(rows))
	for _, r := range rows {
		sev := ""
		if len(r.Class) > 4 && r.Class[:4] == "sev-" {
			sev = r.Class[4:]
		}
		out = append(out, chBar{Label: r.Label, Value: r.Count, Sev: sev})
	}
	return map[string]any{"series": out}
}
func barsToPie(rows []barRow, sevColors bool) any {
	out := make([]chSlice, 0, len(rows))
	for _, r := range rows {
		c := ""
		if sevColors {
			c = sevColor(r.Label)
		}
		out = append(out, chSlice{Label: r.Label, Value: r.Count, Color: c})
	}
	return map[string]any{"slices": out, "donut": true}
}

// trendLine renders events-per-hour as a time-series line.
func trendLine(hours []store.HourBucket) chartFig {
	pts := make([]chPoint, 0, len(hours))
	for _, h := range hours {
		pts = append(pts, chPoint{X: float64(h.Hour.UnixMilli()), Y: float64(h.Count)})
	}
	return chartFigure("line", "Events per hour (24h)", map[string]any{
		"series": []map[string]any{{"name": "events", "points": pts, "color": "#4a6fa5"}},
		"xType":  "time",
	})
}

// severityArea renders a stacked area of event volume by severity over time.
func severityArea(evs []*event.Event) chartFig {
	sevCols := []string{"low", "medium", "high", "critical"}
	buckets := map[int64]map[string]int{}
	for _, ev := range evs {
		hk := ev.Time.Truncate(time.Hour).UnixMilli()
		m := buckets[hk]
		if m == nil {
			m = map[string]int{}
			buckets[hk] = m
		}
		m[ev.Severity.String()]++
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	vals := map[string][]int{}
	for _, s := range sevCols {
		vals[s] = make([]int, len(keys))
	}
	for i, k := range keys {
		for _, s := range sevCols {
			vals[s][i] = buckets[k][s]
		}
	}
	series := make([]map[string]any, 0, len(sevCols))
	for _, s := range sevCols {
		series = append(series, map[string]any{"name": s, "values": vals[s], "color": sevColor(s)})
	}
	return chartFigure("area", "Severity over time (stacked)", map[string]any{"x": keys, "series": series, "xType": "time"})
}

// matrixHeatmap builds rows×cols heatmap cells from a label->col->count map,
// keeping the top n rows by total.
func matrixHeatmap(typ, title string, cols []string, counts map[string]map[string]int, n int, unit string) chartFig {
	totals := map[string]int{}
	for r, m := range counts {
		for _, c := range m {
			totals[r] += c
		}
	}
	rows := topKeys(totals, n)
	cells := make([][]int, len(rows))
	for i, r := range rows {
		cells[i] = make([]int, len(cols))
		for j, c := range cols {
			cells[i][j] = counts[r][c]
		}
	}
	return chartFigure(typ, title, map[string]any{"rows": rows, "cols": cols, "cells": cells, "unit": unit})
}

// sourceMap aggregates events by GeoIP coordinate into attack-source bubbles.
func sourceMap(evs []*event.Event) (chartFig, bool) {
	type agg struct {
		lat, lon float64
		count    int
		sev      string
		label    string
		country  string
	}
	m := map[string]*agg{}
	for _, ev := range evs {
		lat, ok1 := metaFloat(ev.Meta, "geo_lat")
		lon, ok2 := metaFloat(ev.Meta, "geo_lon")
		if !ok1 || !ok2 || (lat == 0 && lon == 0) {
			continue
		}
		key := fmt.Sprintf("%.0f,%.0f", lat, lon)
		a := m[key]
		if a == nil {
			country, _ := ev.Meta["geo_country"].(string)
			label, _ := ev.Meta["geo_city"].(string)
			if label == "" {
				label = country
			}
			if label == "" {
				label = ev.Source.IP
			}
			a = &agg{lat: lat, lon: lon, label: label, country: country}
			m[key] = a
		}
		a.count++
		if sevRank(ev.Severity.String()) > sevRank(a.sev) {
			a.sev = ev.Severity.String()
		}
	}
	if len(m) == 0 {
		return chartFig{}, false
	}
	pts := make([]chMapPt, 0, len(m))
	for _, a := range m {
		pts = append(pts, chMapPt{Lat: a.lat, Lon: a.lon, Count: a.count, Label: a.label, Sev: a.sev, Country: a.country})
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].Count > pts[j].Count })
	return chartFigure("sourcemap", "Attack source map (GeoIP)", map[string]any{"points": pts}), true
}

// credCharts builds the credential-attempt chart and the account heatmap
// (top usernames × service) from captured credentials.
func credCharts(evs []*event.Event) (creds chartFig, account chartFig, ok bool) {
	pair := map[string]*chCred{}
	userSvc := map[string]map[string]int{}
	svcSet := map[string]int{}
	for _, ev := range evs {
		for _, c := range extractCreds(ev) {
			// The credential heatmap is about user/pass logins; standalone
			// secrets (tokens/tickets/communities) surface in /captures, not here.
			if c.Kind != "" && c.Kind != "password" {
				continue
			}
			if c.User == "" && c.Pass == "" {
				continue
			}
			k := c.User + "\x00" + c.Pass
			if pair[k] == nil {
				pair[k] = &chCred{User: c.User, Pass: c.Pass}
			}
			pair[k].Count++
			if c.Service != "" {
				if userSvc[c.User] == nil {
					userSvc[c.User] = map[string]int{}
				}
				userSvc[c.User][c.Service]++
				svcSet[c.Service]++
			}
		}
	}
	if len(pair) == 0 {
		return chartFig{}, chartFig{}, false
	}
	attempts := make([]chCred, 0, len(pair))
	for _, c := range pair {
		attempts = append(attempts, *c)
	}
	sort.Slice(attempts, func(i, j int) bool { return attempts[i].Count > attempts[j].Count })
	creds = chartFigure("creds", "Credential attempts (top users + user×password)", map[string]any{"attempts": attempts})
	cols := topKeys(svcSet, 12)
	account = matrixHeatmap("heatmap", "Account heatmap (username × service)", cols, userSvc, 18, "tries")
	return creds, account, true
}

// buildAnalytics assembles the /charts analytics page from the dashboard model,
// the hourly trend, and a scan of recent events.
func buildAnalytics(d dashboard, hours []store.HourBucket, evs []*event.Event) chartsPage {
	p := chartsPage{Scanned: len(evs)}
	sevCols := []string{"low", "medium", "high", "critical"}

	// Overview.
	overview := chartSection{Heading: "Overview"}
	if len(d.Severity) > 0 {
		overview.Figs = append(overview.Figs, chartFigure("pie", "Events by severity", barsToPie(d.Severity, true)))
	}
	if sl := attacksByService(evs); len(sl) > 0 {
		overview.Figs = append(overview.Figs, chartFigure("pie", "Attacks by service (%)", map[string]any{"slices": sl, "donut": true}))
	}
	if len(hours) > 0 {
		overview.Figs = append(overview.Figs, trendLine(hours))
	}
	if len(evs) > 0 {
		overview.Figs = append(overview.Figs, severityArea(evs))
	}
	if len(d.Sources) > 0 {
		overview.Figs = append(overview.Figs, chartFigure("hbar", "Top source IPs", barsToBar(d.Sources)))
	}
	if len(d.Rules) > 0 {
		overview.Figs = append(overview.Figs, chartFigure("hbar", "Top rules", barsToBar(d.Rules)))
	}
	if len(overview.Figs) > 0 {
		p.Sections = append(p.Sections, overview)
	}

	// Network traffic — incoming/outgoing throughput + packet rate over time.
	if figs := trafficCharts(evs, hours); len(figs) > 0 {
		p.Sections = append(p.Sections, chartSection{Heading: "Network traffic", Figs: figs})
	}

	// ATT&CK & threats.
	threat := chartSection{Heading: "ATT&CK & threats"}
	if len(d.Tactics) > 0 {
		threat.Figs = append(threat.Figs, chartFigure("hbar", "By ATT&CK tactic", barsToBar(d.Tactics)))
	}
	tacSev := map[string]map[string]int{}
	for _, ev := range evs {
		for _, t := range eventTag(ev).Tactics {
			if tacSev[t] == nil {
				tacSev[t] = map[string]int{}
			}
			tacSev[t][ev.Severity.String()]++
		}
	}
	if len(tacSev) > 0 {
		threat.Figs = append(threat.Figs, matrixHeatmap("heatmap", "Threat heatmap (tactic × severity)", sevCols, tacSev, 16, "events"))
	}
	if len(threat.Figs) > 0 {
		p.Sections = append(p.Sections, threat)
	}

	// Protocols.
	proto := chartSection{Heading: "Protocols"}
	if len(d.Handlers) > 0 {
		proto.Figs = append(proto.Figs, chartFigure("bar", "By handler", barsToBar(d.Handlers)))
	}
	hSev := map[string]map[string]int{}
	for _, ev := range evs {
		if ev.Handler == "" {
			continue
		}
		if hSev[ev.Handler] == nil {
			hSev[ev.Handler] = map[string]int{}
		}
		hSev[ev.Handler][ev.Severity.String()]++
	}
	if len(hSev) > 0 {
		proto.Figs = append(proto.Figs, matrixHeatmap("heatmap", "Protocol heatmap (handler × severity)", sevCols, hSev, 16, "events"))
	}
	if len(proto.Figs) > 0 {
		p.Sections = append(p.Sections, proto)
	}

	// Geography.
	geo := chartSection{Heading: "Geography & infrastructure"}
	if fig, ok := sourceMap(evs); ok {
		geo.Figs = append(geo.Figs, fig)
	}
	if len(d.Countries) > 0 {
		geo.Figs = append(geo.Figs, chartFigure("hbar", "Top source countries", barsToBar(d.Countries)))
	}
	if len(d.ASNs) > 0 {
		geo.Figs = append(geo.Figs, chartFigure("hbar", "Top source ASNs", barsToBar(d.ASNs)))
	}
	if len(geo.Figs) > 0 {
		p.Sections = append(p.Sections, geo)
	}

	// Credentials & tooling.
	cred := chartSection{Heading: "Credentials & tooling"}
	if c, acct, ok := credCharts(evs); ok {
		cred.Figs = append(cred.Figs, c, acct)
	}
	if len(d.Tools) > 0 {
		cred.Figs = append(cred.Figs, chartFigure("hbar", "Top tools / scanners", barsToBar(d.Tools)))
	}
	if len(cred.Figs) > 0 {
		p.Sections = append(p.Sections, cred)
	}

	// Ports & exposure.
	ports := chartSection{Heading: "Ports & exposure"}
	if fig, ok := portHourHeatmap(evs); ok {
		ports.Figs = append(ports.Figs, fig)
	}
	if fig, ok := destPortLeaderboard(evs); ok {
		ports.Figs = append(ports.Figs, fig)
	}
	if len(ports.Figs) > 0 {
		p.Sections = append(p.Sections, ports)
	}

	// Vulnerabilities (CVE / CWE).
	if figs := cveAnalytics(evs); len(figs) > 0 {
		p.Sections = append(p.Sections, chartSection{Heading: "Vulnerabilities (CVE / CWE)", Figs: figs})
	}

	// Trends — per-entity (ASN / country) volume over time.
	trends := chartSection{Heading: "Trends (per-entity)"}
	if fig, ok := entitySparklines("Top ASNs over time", evs, func(ev *event.Event) string { return asnLabel(ev.Meta) }, 6, time.Hour); ok {
		trends.Figs = append(trends.Figs, fig)
	}
	if fig, ok := entitySparklines("Top source countries over time", evs, func(ev *event.Event) string { c, _ := ev.Meta["geo_country"].(string); return c }, 6, time.Hour); ok {
		trends.Figs = append(trends.Figs, fig)
	}
	if len(trends.Figs) > 0 {
		p.Sections = append(p.Sections, trends)
	}

	// Actor clustering (force-directed).
	if fig, ok := actorGraph(evs); ok {
		p.Sections = append(p.Sections, chartSection{Heading: "Actor clustering", Figs: []chartFig{fig}})
	}

	p.Empty = len(p.Sections) == 0
	return p
}

// buildTopologyGraph turns the honeynet topology into a node-link graph: one
// column per network, a gateway node plus the host nodes, edges host->gateway.
func buildTopologyGraph(nets []topoNetworkView) chartFig {
	var nodes []chNode
	var edges []chEdge
	for _, n := range nets {
		gw := "gw:" + n.ID
		glabel := n.Gateway
		if glabel == "" {
			glabel = n.ID + " gw"
		}
		nodes = append(nodes, chNode{ID: gw, Label: glabel, Group: n.ID, Kind: "gateway"})
		if n.DNS != "" {
			dns := "dns:" + n.ID
			nodes = append(nodes, chNode{ID: dns, Label: n.DNS, Group: n.ID, Kind: "resolver"})
			edges = append(edges, chEdge{From: dns, To: gw})
		}
		for _, h := range n.Hosts {
			id := n.ID + "/" + h.IP
			label := h.IP
			if h.Hostname != "" {
				label = h.Hostname
			}
			nodes = append(nodes, chNode{ID: id, Label: label, Group: n.ID, Kind: "host", OS: h.OS})
			edges = append(edges, chEdge{From: id, To: gw})
		}
	}
	return chartFigure("topology", "Honeynet topology", map[string]any{"nodes": nodes, "edges": edges})
}

// healthCharts builds the small charts shown on the health page.
func healthCharts(v healthView) []chartFig {
	var out []chartFig
	if len(v.ByProto) > 0 {
		out = append(out, chartFigure("pie", "Events by transport (24h)", countersToPie(v.ByProto)))
	}
	if len(v.Sinks) > 0 {
		var rows []chBar
		for _, sh := range v.Sinks {
			rows = append(rows, chBar{Label: sh.Channel, Value: sh.Dropped + sh.Failed})
		}
		out = append(out, chartFigure("hbar", "Sink dropped+failed events", map[string]any{"series": rows}))
	}
	if v.SnifferActive && len(v.Frames) > 0 {
		out = append(out, chartFigure("bar", "L2 frames by protocol", countersToBar(v.Frames)))
	}
	return out
}

func countersToPie(cs []counter) any {
	out := make([]chSlice, 0, len(cs))
	for _, c := range cs {
		out = append(out, chSlice{Label: c.Label, Value: c.Value})
	}
	return map[string]any{"slices": out}
}
func countersToBar(cs []counter) any {
	out := make([]chBar, 0, len(cs))
	for _, c := range cs {
		out = append(out, chBar{Label: c.Label, Value: c.Value})
	}
	return map[string]any{"series": out}
}

// --- small helpers ---------------------------------------------------------

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	if len(items) > n {
		items = items[:n]
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.k
	}
	return out
}

func metaFloat(m map[string]any, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}
