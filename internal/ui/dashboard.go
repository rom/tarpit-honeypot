package ui

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// barRow is one row of a CSS bar chart (no JS — the bars are plain divs
// with an inline width %, which the strict CSP allows via style-src).
type barRow struct {
	Label string
	Count int
	Pct   int // bar width: % of the busiest row (visual scale)
	// Share is the row's share of the total across the bar set (% of all
	// events in this dimension), shown as a number next to the count.
	Share int
	Href  string
	Class string
	// External marks a bar whose Href points off-site (e.g. an ATT&CK
	// technique linking to attack.mitre.org) so the template opens it in a new
	// tab with a safe rel.
	External bool
}

// counter is one labeled number in the summary's top counters strip.
type counter struct {
	Label string
	Value int
	// Class is an optional CSS class that tints the counter's background by
	// category (transport: c-total/c-tcp/c-udp/c-icmp; severity:
	// sev-bg-critical/high/medium/low). Empty = the default surface color.
	Class string
	// Href, when set, makes the counter a link to the matching event listing
	// (e.g. the UDP counter -> /events?proto=udp). Empty = not clickable.
	Href string
}

// hourBar is one bar of the "events per hour" spark, carrying the data needed
// to draw an aligned x-axis tick beneath it.
type hourBar struct {
	Pct      int    // bar height, % of the busiest hour
	Count    int    // events in this hour
	Full     string // tooltip label, e.g. "06-02 15h"
	Hour     string // short axis label, e.g. "15"
	ShowTick bool   // print the axis label under this bar (every 6h)
	From     string // bucket start (RFC3339) — links the bar to /events?from=&to=
	To       string // bucket end (RFC3339)
}

// dashboard is the summary page's chart model.
type dashboard struct {
	Sum store.Summary
	// Counters is the at-a-glance strip at the top: event volume by
	// transport + severity (always from the store).
	Counters []counter
	// Frames are the AF_PACKET sniffer's L2 frame counters (only when the
	// sniffer is running); HasFrames gates the panel.
	Frames    []counter
	HasFrames bool
	Severity  []barRow
	Rules     []barRow
	Sources   []barRow
	Trend     []hourBar
	// Enrichment charts (filled by enrichDashboard from a scan of recent
	// events; the store's SQL summary only covers severity/rule/source).
	Tactics   []barRow
	Countries []barRow
	ASNs      []barRow
	Tools     []barRow
	Handlers  []barRow
	Cities    []barRow // top source cities (geo_city)
	ASNOrgs   []barRow // top networks by operator name (asn_org)
	// Attacks ranks the most-seen ATT&CK techniques (the behaviour — the
	// "how"); CVEs ranks the most-probed vulnerabilities (the specific weakness
	// — the "what"). They are deliberately two lists: a single technique spans
	// many CVEs and one CVE can be reached by several techniques, so collapsing
	// them would hide both axes.
	Attacks []barRow
	CVEs    []barRow
	// Intents ranks the most common attacker-intent strings the handlers
	// inferred — the plain-language "what they were trying to do" across the
	// window, each pivoting to its filtered event list.
	Intents []barRow
	// TargetIPs ranks the host's own server IPs (destinations) that were hit —
	// the multi-IP breakdown ("which of my addresses are getting attacked").
	// Only meaningful when the host serves more than one IP.
	TargetIPs []barRow
	Scanned   int
	// Charts are charts.js figures rendered alongside the CSS bars (JS on).
	Charts []chartFig
	// Time-range selector (24h / 7d / 14d / 31d / 3mo / 6mo) + the labels.
	RangeLabel string      // page heading, e.g. "last 24 hours"
	TrendTitle string      // e.g. "events per hour" / "events per day"
	RangeLinks []rangeLink // the selector chips
	// Canvas is the listener/port board (same cards as the config page), shown
	// on the summary so an operator can click straight to a port's events.
	Canvas configCanvas
	// RangeQuery is the active window key (e.g. "7d") appended to /events pivot
	// links so the listing covers the same span; "" for the 24h default.
	RangeQuery string
	// Notice, when set, is a transient banner shown above the dashboard — e.g.
	// "summary still building over a large dataset" on a cold/degraded load.
	Notice string
}

// scopeEventLinks appends the summary's active time window to every /events
// pivot link (counters + bars), so clicking a country / ASN / tool / handler /
// tactic / rule / severity / proto shows the SAME window the operator was
// viewing. Without it, /events falls back to its 24h default and a pivot off a
// 7d/31d summary looks empty. Links to other pages (/profiles, external) are
// left untouched. A 24h window is a no-op (it already matches the default).
func scopeEventLinks(d *dashboard, rangeKey string) {
	d.RangeQuery = ""
	if rangeKey == "" || rangeKey == "24h" {
		return
	}
	d.RangeQuery = rangeKey
	add := func(h string) string {
		if !strings.HasPrefix(h, "/events") {
			return h
		}
		if strings.Contains(h, "?") {
			return h + "&range=" + rangeKey
		}
		return h + "?range=" + rangeKey
	}
	for i := range d.Counters {
		d.Counters[i].Href = add(d.Counters[i].Href)
	}
	for _, rows := range [][]barRow{d.Severity, d.Rules, d.Tactics, d.Countries, d.ASNs, d.Tools, d.Handlers, d.Cities, d.ASNOrgs} {
		for i := range rows {
			rows[i].Href = add(rows[i].Href)
		}
	}
}

// rangeLink is one chip of the summary's time-range selector.
type rangeLink struct {
	Label  string
	Href   string
	Active bool
}

func buildDashboard(sum store.Summary, hours []store.HourBucket, bucket time.Duration) dashboard {
	d := dashboard{Sum: sum, TrendTitle: trendTitle(bucket)}

	sevOrder := []string{"low", "medium", "high", "critical"}
	maxSev, sumSev := 0, 0
	for _, k := range sevOrder {
		sumSev += sum.BySeverity[k]
		if sum.BySeverity[k] > maxSev {
			maxSev = sum.BySeverity[k]
		}
	}
	for _, k := range sevOrder {
		if c := sum.BySeverity[k]; c > 0 {
			d.Severity = append(d.Severity, barRow{Label: k, Count: c, Pct: pct(c, maxSev), Share: share(c, sumSev), Class: "sev-" + k, Href: "/events?severity=" + k})
		}
	}

	d.Rules = topBars(sum.ByRule, 10, "/events?rule=")

	maxSrc, sumSrc := 0, 0
	for _, s := range sum.TopSources {
		sumSrc += s.Count
		if s.Count > maxSrc {
			maxSrc = s.Count
		}
	}
	for _, s := range sum.TopSources {
		d.Sources = append(d.Sources, barRow{Label: s.IP, Count: s.Count, Pct: pct(s.Count, maxSrc), Share: share(s.Count, sumSrc), Href: "/profiles/" + s.IP})
	}

	// Indexed dimensions straight from the SQL summary (full-window accurate).
	// enrichDashboard only fills these from its sampled scan when the summary
	// didn't provide them (callers that enrich a bare dashboard).
	d.Handlers = topBars(sum.ByHandler, 12, "/events?handler=")
	d.TargetIPs = topBars(sum.ByTarget, 20, "/search?q=")
	d.Countries = countryBars(sum.ByCountry)

	maxH := 0
	for _, h := range hours {
		if h.Count > maxH {
			maxH = h.Count
		}
	}
	daily := bucket >= 24*time.Hour
	n := len(hours)
	for i, h := range hours {
		hb := hourBar{Pct: pct(h.Count, maxH), Count: h.Count}
		if daily {
			// Per-day buckets: date axis, tick a handful of evenly-spaced days.
			hb.Full = h.Hour.Format("2006-01-02")
			hb.Hour = h.Hour.Format("01-02")
			step := (n + 5) / 6
			if step < 1 {
				step = 1
			}
			hb.ShowTick = i%step == 0
		} else {
			// Sub-day buckets: hour-of-day axis, tick on 6h clock boundaries so
			// labels stay readable and line up under their bars.
			hb.Full = h.Hour.Format("01-02 15h")
			hb.Hour = h.Hour.Format("15")
			hb.ShowTick = h.Hour.Hour()%6 == 0
		}
		// The bucket's [start,end) window, so a click drills to those events.
		hb.From = h.Hour.UTC().Format(time.RFC3339)
		hb.To = h.Hour.Add(bucket).UTC().Format(time.RFC3339)
		d.Trend = append(d.Trend, hb)
	}
	return d
}

// trendTitle names the events-over-time histogram for the chosen bucket width.
func trendTitle(bucket time.Duration) string {
	day := 24 * time.Hour
	switch {
	case bucket <= 0 || bucket == time.Hour:
		return "events per hour"
	case bucket >= 7*day:
		return "events per week"
	case bucket >= day:
		return "events per day"
	default:
		return "events per " + strings.TrimSuffix(bucket.String(), "0m0s")
	}
}

// enrichDashboard adds the cross-cutting charts that need per-event meta
// (ATT&CK tactics, geo country, ASN, tool, handler) by scanning a window of
// events — the SQL summary only aggregates severity / rule / source.
func enrichDashboard(d *dashboard, evs []*event.Event) {
	d.Scanned = len(evs)
	tac, country, asn, tool, handler := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	tech, cve := map[string]int{}, map[string]int{}
	target := map[string]int{}
	city, org := map[string]int{}, map[string]int{}
	intent := map[string]int{}
	for _, ev := range evs {
		tag := eventTag(ev)
		if it, _ := ev.Meta["intent"].(string); it != "" {
			intent[it]++
		}
		for _, t := range tag.Tactics {
			tac[t]++
		}
		for _, t := range tag.Techniques {
			tech[t]++
		}
		for _, c := range eventCVEs(ev) {
			cve[c]++
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			country[c]++
		}
		if c, _ := ev.Meta["geo_city"].(string); c != "" {
			city[c]++
		}
		if o, _ := ev.Meta["asn_org"].(string); o != "" {
			org[o]++
		}
		if a := asnLabel(ev.Meta); a != "" {
			asn[a]++
		}
		for _, tl := range metaStrings(ev.Meta, "tools") {
			tool[tl]++
		}
		if ev.Handler != "" {
			handler[ev.Handler]++
		}
		if ev.Dest.IP != "" {
			target[ev.Dest.IP]++
		}
	}
	// Every summary line item links to the filtered event list. Countries /
	// handler / tool / tactic map directly to a query param; ASN is keyed on the
	// numeric AS extracted from its display label ("AS13335 Cloudflare").
	d.Tactics = topBars(tac, 14, "/events?tactic=")
	// Countries are normally sourced from the SQL summary (buildDashboard,
	// full-window, index-backed). Fall back to this sampled count only when a
	// caller enriched a bare dashboard without a summary.
	if len(d.Countries) == 0 {
		d.Countries = countryBars(country)
	}
	d.ASNs = topBars(asn, 10, "")
	for i := range d.ASNs {
		if num := asnNumber(d.ASNs[i].Label); num != "" {
			d.ASNs[i].Href = "/events?asn=" + num
		}
	}
	// City + network-operator (asn_org) rollups, each pivoting to the events
	// list filtered by that meta dimension.
	d.Cities = topBars(city, 10, "/events?geo_city=")
	d.ASNOrgs = topBars(org, 10, "/events?asn_org=")
	d.Tools = topBars(tool, 10, "/events?tool=")
	// Handlers + target IPs are normally sourced from the SQL summary
	// (buildDashboard, full-window). Fall back to this sampled count only when a
	// caller enriched a bare dashboard without a summary.
	if len(d.Handlers) == 0 {
		d.Handlers = topBars(handler, 12, "/events?handler=")
	}
	// Per-target-IP breakdown (the host's own server IPs). Links to list-events
	// filtered by that target via the search page.
	if len(d.TargetIPs) == 0 {
		d.TargetIPs = topBars(target, 20, "/search?q=")
	}
	// Top attacks: ATT&CK techniques, labelled with their human name and linking
	// to the internal technique drill-down.
	d.Attacks = topBars(tech, 12, "/attack/technique?id=")
	for i := range d.Attacks {
		if nm := techShortName(d.Attacks[i].Label); nm != "" {
			d.Attacks[i].Label = d.Attacks[i].Label + " · " + nm
		}
	}
	// Top vulnerabilities: CVE IDs, each linking to a full-text search for its
	// events (covers the rule, anomaly markers, and emulated-vuln meta).
	d.CVEs = topBars(cve, 12, "/search?q=")
}

// isAttackEvent reports whether an event represents an attack / misuse /
// exploit (vs. a benign probe) — it carries an anomaly marker, a CVE, or is
// high/critical severity.
func isAttackEvent(ev *event.Event) bool {
	if len(ev.Anomalies) > 0 || len(eventCVEs(ev)) > 0 {
		return true
	}
	if len(metaStrings(ev.Meta, "anomalies")) > 0 {
		return true
	}
	return ev.Severity >= event.SeverityHigh
}

// attacksByService returns the share of attack events per service (handler),
// for a "% of attacks by active service" pie/donut.
func attacksByService(evs []*event.Event) []chSlice {
	c := map[string]int{}
	for _, ev := range evs {
		if !isAttackEvent(ev) {
			continue
		}
		svc := ev.Handler
		if svc == "" {
			svc = ev.Proto
		}
		if svc == "" {
			continue
		}
		c[svc]++
	}
	return slicesFromMap(c)
}

// markCanvasActivity tints the summary's service board: it counts events per
// destination port over the scanned window and marks each matching listener
// card as "hit" (with its event count), so an operator sees at a glance which
// services have actually been accessed or probed.
func markCanvasActivity(cv *configCanvas, evs []*event.Event) {
	if len(cv.Listeners) == 0 {
		return
	}
	perPort := map[int]int{}
	for _, ev := range evs {
		if ev.Dest.Port > 0 {
			perPort[ev.Dest.Port]++
		}
	}
	for i := range cv.Listeners {
		if n := perPort[cv.Listeners[i].Port]; n > 0 {
			cv.Listeners[i].Hit = true
			cv.Listeners[i].Hits = n
		}
	}
}

// enrichDashboardFacets fills the same cross-cutting charts as enrichDashboard,
// but from SQL-aggregated facets instead of a sampled per-event scan. The
// logic-bearing dimensions (ATT&CK tactics/techniques, CVEs, attack
// classification) are computed by running the *same* helpers (eventTag /
// eventCVEs / isAttackEvent) once per distinct event signature, scaled by that
// signature's count — so the output matches the scan path exactly while reading
// orders of magnitude fewer rows. Countries / handlers / target IPs stay sourced
// from the SQL summary (set in buildDashboard). Returns the attacks-by-service
// slices for the donut chart. See store.DashboardFacets.
func enrichDashboardFacets(d *dashboard, f store.DashboardFacets) []chSlice {
	tac, tech, cve := map[string]int{}, map[string]int{}, map[string]int{}
	svc := map[string]int{}
	for _, a := range f.Attacks {
		// ATT&CK tactics/techniques: base rule/handler lookup augmented with the
		// event's anomaly markers — identical to eventTag over a real event.
		tag := mitre.Augment(mitre.Lookup(a.RuleID, a.Handler), a.MetaAnomalies)
		for _, t := range tag.Tactics {
			tac[t] += a.Count
		}
		for _, t := range tag.Techniques {
			tech[t] += a.Count
		}
		// CVE + attack-classification reuse the exact event helpers via a minimal
		// reconstructed event carrying only the fields they read.
		ev := &event.Event{
			RuleID:    a.RuleID,
			Handler:   a.Handler,
			Proto:     a.Proto,
			Severity:  event.Severity(a.Severity),
			Anomalies: a.Anomalies,
			Meta:      map[string]any{"anomalies": a.MetaAnomalies, "emulated_vuln_cves": a.EmulatedCVEs},
		}
		for _, c := range eventCVEs(ev) {
			cve[c] += a.Count
		}
		if isAttackEvent(ev) {
			s := a.Handler
			if s == "" {
				s = a.Proto
			}
			if s != "" {
				svc[s] += a.Count
			}
		}
	}
	d.Tactics = topBars(tac, 14, "/events?tactic=")
	d.Attacks = topBars(tech, 12, "/attack/technique?id=")
	for i := range d.Attacks {
		if nm := techShortName(d.Attacks[i].Label); nm != "" {
			d.Attacks[i].Label = d.Attacks[i].Label + " · " + nm
		}
	}
	d.CVEs = topBars(cve, 12, "/search?q=")

	// ASN: format the display label + numeric pivot exactly as the per-event
	// asnLabel did, from the grouped (number, operator) facets.
	asn := map[string]int{}
	for _, a := range f.ASNs {
		if label := asnLabel(map[string]any{"asn": a.Num, "asn_org": a.Org}); label != "" {
			asn[label] += a.Count
		}
	}
	d.ASNs = topBars(asn, 10, "")
	for i := range d.ASNs {
		if num := asnNumber(d.ASNs[i].Label); num != "" {
			d.ASNs[i].Href = "/events?asn=" + num
		}
	}
	d.Cities = topBars(f.Cities, 10, "/events?geo_city=")
	d.ASNOrgs = topBars(f.ASNOrgs, 10, "/events?asn_org=")
	d.Tools = topBars(f.Tools, 10, "/events?tool=")
	d.Intents = topBars(f.Intents, 12, "/events?intent=")
	return slicesFromMap(svc)
}

// markCanvasActivityPorts is markCanvasActivity fed by a SQL per-port count map
// (store.DashboardFacets.Ports) rather than a per-event scan.
func markCanvasActivityPorts(cv *configCanvas, ports map[int]int) {
	if len(cv.Listeners) == 0 {
		return
	}
	for i := range cv.Listeners {
		if n := ports[cv.Listeners[i].Port]; n > 0 {
			cv.Listeners[i].Hit = true
			cv.Listeners[i].Hits = n
		}
	}
}

// eventCVEs returns the CVE IDs an event recorded — from a "cve:"-prefixed
// rule, "cve:" anomaly markers, or the emulated-vuln meta — normalized to
// upper case and de-duplicated.
func eventCVEs(ev *event.Event) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if i := strings.IndexByte(s, ':'); i >= 0 && strings.EqualFold(s[:i], "cve") {
			s = s[i+1:]
		}
		up := strings.ToUpper(s)
		if !strings.HasPrefix(up, "CVE-") || seen[up] {
			return
		}
		seen[up] = true
		out = append(out, up)
	}
	add(ev.RuleID)
	for _, a := range ev.Anomalies {
		add(a)
	}
	for _, a := range metaStrings(ev.Meta, "anomalies") {
		add(a)
	}
	for _, c := range metaStrings(ev.Meta, "emulated_vuln_cves") {
		add(c)
	}
	return out
}

// techShortName returns the human-readable name of an ATT&CK technique — the
// text before the " — " in its description (e.g. "T1595" -> "Active Scanning").
func techShortName(id string) string {
	d := mitre.Describe(id)
	if d == "" {
		return ""
	}
	if i := strings.Index(d, " — "); i > 0 {
		return strings.TrimSpace(d[:i])
	}
	return d
}

// asnNumber extracts the numeric AS from a label like "AS13335 Cloudflare".
func asnNumber(label string) string {
	s := strings.TrimPrefix(label, "AS")
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return s[:n]
}

// countryBars ranks a country-code -> count map into the top-10 bars used by
// the dashboard / stats country panel, appending each code's flag emoji to the
// label (the href keeps the raw 2-letter code). Shared by the SQL-sourced path
// (buildDashboard) and the enrich fallback.
func countryBars(m map[string]int) []barRow {
	bars := topBars(m, 10, "/events?country=")
	for i := range bars {
		if f := countryFlag(bars[i].Label); f != "" {
			bars[i].Label = bars[i].Label + " " + f
		}
	}
	return bars
}

func topBars(m map[string]int, n int, hrefPrefix string) []barRow {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	total := 0
	for k, v := range m {
		items = append(items, kv{k, v})
		total += v
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
	max := 0
	for _, it := range items {
		if it.v > max {
			max = it.v
		}
	}
	out := make([]barRow, 0, len(items))
	for _, it := range items {
		href := ""
		if hrefPrefix != "" {
			href = hrefPrefix + url.QueryEscape(it.k)
		}
		out = append(out, barRow{Label: it.k, Count: it.v, Pct: pct(it.v, max), Share: share(it.v, total), Href: href})
	}
	return out
}

// share is v as a rounded percentage of total (0..100), no visual floor — the
// honest share-of-total shown next to a bar's count.
func share(v, total int) int {
	if total <= 0 {
		return 0
	}
	return (v*100 + total/2) / total
}

// pct scales v to 0..100 against max, with a 2% floor so a non-zero bar is
// always visible.
func pct(v, max int) int {
	if max <= 0 {
		return 0
	}
	p := v * 100 / max
	if p < 2 && v > 0 {
		p = 2
	}
	return p
}

// hexDump renders a classic offset/hex/ASCII dump of a base64-encoded
// payload, capped so the page stays bounded. Empty input / decode failure
// returns "".
func hexDump(b64 string) string {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(data) == 0 {
		return ""
	}
	const max = 4096
	truncated := false
	if len(data) > max {
		data = data[:max]
		truncated = true
	}
	var sb strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&sb, "%08x  ", off)
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&sb, "%02x ", data[i])
			} else {
				sb.WriteString("   ")
			}
			if i == off+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for i := off; i < end; i++ {
			c := data[i]
			if c >= 0x20 && c < 0x7f {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	if truncated {
		sb.WriteString("... (truncated)\n")
	}
	return sb.String()
}
