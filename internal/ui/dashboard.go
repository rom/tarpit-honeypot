package ui

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// barRow is one row of a CSS bar chart (no JS — the bars are plain divs
// with an inline width %, which the strict CSP allows via style-src).
type barRow struct {
	Label string
	Count int
	Pct   int
	Href  string
	Class string
}

// counter is one labeled number in the summary's top counters strip.
type counter struct {
	Label string
	Value int
	// Class is an optional CSS class that tints the counter's background by
	// category (transport: c-total/c-tcp/c-udp/c-icmp; severity:
	// sev-bg-critical/high/medium/low). Empty = the default surface color.
	Class string
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
	Trend     []barRow
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
}

func buildDashboard(sum store.Summary, hours []store.HourBucket) dashboard {
	d := dashboard{Sum: sum}

	sevOrder := []string{"low", "medium", "high", "critical"}
	maxSev := 0
	for _, k := range sevOrder {
		if sum.BySeverity[k] > maxSev {
			maxSev = sum.BySeverity[k]
		}
	}
	for _, k := range sevOrder {
		if c := sum.BySeverity[k]; c > 0 {
			d.Severity = append(d.Severity, barRow{Label: k, Count: c, Pct: pct(c, maxSev), Class: "sev-" + k, Href: "/events?severity=" + k})
		}
	}

	d.Rules = topBars(sum.ByRule, 10, "/events?rule=")

	maxSrc := 0
	for _, s := range sum.TopSources {
		if s.Count > maxSrc {
			maxSrc = s.Count
		}
	}
	for _, s := range sum.TopSources {
		d.Sources = append(d.Sources, barRow{Label: s.IP, Count: s.Count, Pct: pct(s.Count, maxSrc), Href: "/profiles/" + s.IP})
	}

	maxH := 0
	for _, h := range hours {
		if h.Count > maxH {
			maxH = h.Count
		}
	}
	for _, h := range hours {
		d.Trend = append(d.Trend, barRow{Label: h.Hour.Format("01-02 15h"), Count: h.Count, Pct: pct(h.Count, maxH)})
	}
	return d
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
	d.Tactics = topBars(tac, 14, "")
	d.Countries = topBars(country, 10, "")
	d.ASNs = topBars(asn, 10, "")
	d.Tools = topBars(tool, 10, "")
	d.Handlers = topBars(handler, 12, "")
}

func topBars(m map[string]int, n int, hrefPrefix string) []barRow {
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
			href = hrefPrefix + it.k
		}
		out = append(out, barRow{Label: it.k, Count: it.v, Pct: pct(it.v, max), Href: href})
	}
	return out
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
