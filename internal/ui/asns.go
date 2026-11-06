package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// The networks page ranks autonomous systems by how many DISTINCT source IPs
// (attacking hosts) they originated — answering "which AS do my attackers come
// from?". It reuses the cached full-window event snapshot and the existing
// asn= event filter (so an AS row links to every event from that whole AS).
const (
	asnsWindow   = 7 * 24 * time.Hour
	asnsScanMax  = 50000
	asnsMaxRows  = 250
	asnsSampleIP = 5 // sample attacker IPs shown per AS
)

// asnRow is one autonomous system's aggregate in the networks view.
type asnRow struct {
	Rank      int
	ASN       int
	Org       string
	Attackers int // distinct source IPs seen from this AS
	Events    int
	Countries []string
	MaxSev    string
	LastSeen  time.Time
	SampleIPs []string // a few example attacker IPs (link to their profiles)
	Href      string   // /events?asn=<n>
}

// asnsPage is the networks template's data.
type asnsPage struct {
	Rows           []asnRow
	Window         string
	TotalASNs      int
	TotalAttackers int
	TotalEvents    int
	Truncated      bool // more ASNs existed than asnsMaxRows
}

// buildASNsView aggregates events by ASN into attacker-ranked rows.
func buildASNsView(evs []*event.Event) asnsPage {
	type acc struct {
		org       string
		ips       map[string]struct{}
		events    int
		countries map[string]struct{}
		maxSev    string
		last      time.Time
	}
	m := map[int]*acc{}
	allIPs := map[string]struct{}{}
	total := 0
	for _, ev := range evs {
		asn := metaInt(ev.Meta, "asn")
		if asn == 0 { // only enriched events carry an ASN
			continue
		}
		a := m[asn]
		if a == nil {
			a = &acc{ips: map[string]struct{}{}, countries: map[string]struct{}{}}
			m[asn] = a
		}
		if o, _ := ev.Meta["asn_org"].(string); o != "" && a.org == "" {
			a.org = o
		}
		if ev.Source.IP != "" {
			a.ips[ev.Source.IP] = struct{}{}
			allIPs[ev.Source.IP] = struct{}{}
		}
		a.events++
		total++
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			a.countries[c] = struct{}{}
		}
		if sevRank(ev.Severity.String()) > sevRank(a.maxSev) {
			a.maxSev = ev.Severity.String()
		}
		if ev.Time.After(a.last) {
			a.last = ev.Time
		}
	}
	rows := make([]asnRow, 0, len(m))
	for asn, a := range m {
		ips := sortedSet(a.ips)
		sample := ips
		if len(sample) > asnsSampleIP {
			sample = sample[:asnsSampleIP]
		}
		rows = append(rows, asnRow{
			ASN: asn, Org: a.org, Attackers: len(a.ips), Events: a.events,
			Countries: sortedSet(a.countries), MaxSev: a.maxSev, LastSeen: a.last,
			SampleIPs: sample, Href: "/events?asn=" + strconv.Itoa(asn),
		})
	}
	// Rank by distinct attacking hosts, then event volume, then AS number.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Attackers != rows[j].Attackers {
			return rows[i].Attackers > rows[j].Attackers
		}
		if rows[i].Events != rows[j].Events {
			return rows[i].Events > rows[j].Events
		}
		return rows[i].ASN < rows[j].ASN
	})
	page := asnsPage{
		Window: "7d", TotalASNs: len(rows), TotalAttackers: len(allIPs), TotalEvents: total,
	}
	if len(rows) > asnsMaxRows {
		rows = rows[:asnsMaxRows]
		page.Truncated = true
	}
	for i := range rows {
		rows[i].Rank = i + 1
	}
	page.Rows = rows
	return page
}

func (s *Server) handleASNs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.windowEvents(ctx, asnsWindow, asnsScanMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "asns", buildASNsView(evs)); err != nil {
		slog.Warn("ui: render asns", "err", err)
	}
}

func (s *Server) handleAPIASNs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.windowEvents(ctx, asnsWindow, asnsScanMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	writeJSON(w, buildASNsView(evs))
}
