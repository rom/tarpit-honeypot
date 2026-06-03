package ui

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
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
	for _, ev := range evs {
		for _, t := range eventTag(ev).Tactics {
			tac[t]++
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			country[c]++
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
	}
	// Every summary line item links to the filtered event list. Countries /
	// handler / tool / tactic map directly to a query param; ASN is keyed on the
	// numeric AS extracted from its display label ("AS13335 Cloudflare").
	d.Tactics = topBars(tac, 14, "/events?tactic=")
	d.Countries = topBars(country, 10, "/events?country=")
	d.ASNs = topBars(asn, 10, "")
	for i := range d.ASNs {
		if num := asnNumber(d.ASNs[i].Label); num != "" {
			d.ASNs[i].Href = "/events?asn=" + num
		}
	}
	d.Tools = topBars(tool, 10, "/events?tool=")
	d.Handlers = topBars(handler, 12, "/events?handler=")
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
