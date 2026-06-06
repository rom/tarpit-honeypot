package ui

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// statsView is the data behind the /stats page — a compact, numeric companion
// to the visual /charts page. It surfaces the headline counts an operator
// reports up the chain (volume, severity mix, attacker breadth) plus the
// top-N tables across every dimension, all scoped to the selected window.
type statsView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Headline   []statKV
	Blocks     []statBlock
	Notice     string
}

// statKV is one big headline metric (a label, a value, and an optional sub-note).
type statKV struct {
	Label string
	Value string
	Sub   string
}

// statBlock is a titled top-N table reusing the dashboard barRow layout.
type statBlock struct {
	Title string
	Rows  []barRow
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	win := summaryRange(r.URL.Query().Get("range"))
	since := time.Now().Add(-win.dur)

	sum, err := s.store.Summary(ctx, since)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	sum.TopSources = s.visibleSourceCounts(sum.TopSources)
	hours, _ := s.store.EventsPerBucket(ctx, since, win.bucket)
	d := buildDashboard(sum, hours, win.bucket)
	var evs []*event.Event
	if e, qerr := s.query(ctx, store.Filter{Since: since, Limit: 20000, NoPayload: true}); qerr == nil {
		evs = e
		enrichDashboard(&d, evs)
	}

	view := buildStatsView(d, sum, win)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "stats", view); err != nil {
		slog.Warn("ui: render stats", "err", err)
	}
}

// buildStatsView assembles the headline metrics + top-N blocks from an already
// aggregated dashboard.
func buildStatsView(d dashboard, sum store.Summary, win sumWindow) statsView {
	v := statsView{
		RangeLabel: win.label,
		RangeLinks: rangeLinksFor("/stats", win.key),
	}

	hours := win.dur.Hours()
	if hours < 1 {
		hours = 1
	}
	highCrit := sum.BySeverity["high"] + sum.BySeverity["critical"]
	pct := func(n int) string {
		if sum.Total == 0 {
			return "0%"
		}
		return fmt.Sprintf("%d%%", n*100/sum.Total)
	}

	v.Headline = []statKV{
		{Label: "Events", Value: humanInt(sum.Total), Sub: win.label},
		{Label: "High + Critical", Value: humanInt(highCrit), Sub: pct(highCrit) + " of events"},
		{Label: "Events / hour", Value: fmt.Sprintf("%.1f", float64(sum.Total)/hours), Sub: "average over window"},
		{Label: "Attacker sources", Value: humanInt(len(sum.TopSources)), Sub: "tracked (top-N)"},
		{Label: "Source countries", Value: humanInt(len(d.Countries)), Sub: "distinct (sampled)"},
		{Label: "ATT&CK techniques", Value: humanInt(len(d.Attacks)), Sub: "distinct (sampled)"},
		{Label: "CVEs probed", Value: humanInt(len(d.CVEs)), Sub: "distinct (sampled)"},
		{Label: "Tools fingerprinted", Value: humanInt(len(d.Tools)), Sub: "distinct (sampled)"},
	}

	// Protocol distribution from the authoritative SQL summary.
	v.Blocks = append(v.Blocks, statBlock{Title: "Severity", Rows: d.Severity})
	v.Blocks = append(v.Blocks, statBlock{Title: "Transport / protocol", Rows: protoBars(sum)})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top services (handlers)", Rows: d.Handlers})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top source countries", Rows: d.Countries})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top networks (ASN)", Rows: d.ASNs})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top ATT&CK tactics", Rows: d.Tactics})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top ATT&CK techniques", Rows: d.Attacks})
	v.Blocks = append(v.Blocks, statBlock{Title: "Most-probed CVEs", Rows: d.CVEs})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top tools / scanners", Rows: annotateToolVendors(d.Tools)})
	v.Blocks = append(v.Blocks, statBlock{Title: "Top attacker sources", Rows: sourceBars(sum)})

	if d.Notice != "" {
		v.Notice = d.Notice
	}
	return v
}

// protoBars turns the summary's by-proto counts into ranked bars.
func protoBars(sum store.Summary) []barRow {
	return mapToBars(sum.ByProto, sum.Total, "/events?proto=")
}

// sourceBars ranks the top attacker source IPs.
func sourceBars(sum store.Summary) []barRow {
	rows := make([]barRow, 0, len(sum.TopSources))
	max := 0
	for _, sc := range sum.TopSources {
		if sc.Count > max {
			max = sc.Count
		}
	}
	for _, sc := range sum.TopSources {
		r := barRow{Label: sc.IP, Count: sc.Count, Href: "/profiles/" + sc.IP}
		if max > 0 {
			r.Pct = sc.Count * 100 / max
		}
		if sum.Total > 0 {
			r.Share = sc.Count * 100 / sum.Total
		}
		rows = append(rows, r)
		if len(rows) >= 15 {
			break
		}
	}
	return rows
}

// annotateToolVendors appends the vendor/affiliation to each tool row's label
// so the statistics table doubles as a quick reference ("nuclei — ProjectDiscovery").
func annotateToolVendors(in []barRow) []barRow {
	out := make([]barRow, len(in))
	copy(out, in)
	for i := range out {
		if vendor := toolfp.Vendor(out[i].Label); vendor != "" {
			out[i].Label = out[i].Label + " — " + vendor
		}
	}
	return out
}

// mapToBars ranks a label->count map into barRows with a pivot href prefix.
func mapToBars(m map[string]int, total int, hrefPrefix string) []barRow {
	type kv struct {
		k string
		n int
	}
	var pairs []kv
	max := 0
	for k, n := range m {
		pairs = append(pairs, kv{k, n})
		if n > max {
			max = n
		}
	}
	// simple insertion sort (small N) descending by count.
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && pairs[j-1].n < pairs[j].n; j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
	rows := make([]barRow, 0, len(pairs))
	for _, p := range pairs {
		r := barRow{Label: p.k, Count: p.n}
		if hrefPrefix != "" && p.k != "" {
			r.Href = hrefPrefix + p.k
		}
		if max > 0 {
			r.Pct = p.n * 100 / max
		}
		if total > 0 {
			r.Share = p.n * 100 / total
		}
		rows = append(rows, r)
	}
	return rows
}

// humanInt renders an int with thousands separators (12,345).
func humanInt(n int) string {
	if n < 0 {
		return "-" + humanInt(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	pre := len(s) % 3
	if pre > 0 {
		out = append(out, s[:pre]...)
	}
	for i := pre; i < len(s); i += 3 {
		if len(out) > 0 {
			out = append(out, ',')
		}
		out = append(out, s[i:i+3]...)
	}
	return string(out)
}
