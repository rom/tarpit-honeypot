package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Threat map / geo dashboard. A single live operations screen: a GeoIP attack
// map (reusing the packaged sourcemap chart) over country / ASN / network-class
// breakdowns and threat-intelligence counters (known-bad source hits, Tor
// exits, feed matches), plus a ticker of the most recent high-severity attacks
// with their origin. Auto-refreshes via the standard meta-refresh, so it
// doubles as the "live attack map" on a wall display.

const mapWindow = 24 * time.Hour
const mapScanMax = 20000

type threatMapView struct {
	Since        time.Time
	RangeKey     string
	RangeLabel   string
	RangeLinks   []rangeLink
	Total        int
	GeoLocated   int // events with usable lat/lon
	HasMap       bool
	MapB64       string
	Counters     []counter
	Countries    []barRow
	ASNs         []barRow
	NetClasses   []barRow
	IntelSources []barRow // threat-intel feed/label -> hits
	Recent       []mapHit // most recent high-severity, geo-tagged attacks
}

type mapHit struct {
	Time    time.Time
	Source  string
	Country string
	City    string
	ASN     string
	Sev     string
	Handler string
	RuleID  string
	Intel   bool // matched a threat-intel feed / Tor / known-bad list
}

func buildThreatMapView(since time.Time, evs []*event.Event) threatMapView {
	v := threatMapView{Since: since, Total: len(evs)}

	country := map[string]int{}
	asn := map[string]int{}
	netClass := map[string]int{}
	intelLabel := map[string]int{}
	var intelHits, torExits, distinctIntelIPs int
	intelIP := map[string]bool{}

	for _, ev := range evs {
		if _, ok1 := metaFloat(ev.Meta, "geo_lat"); ok1 {
			if _, ok2 := metaFloat(ev.Meta, "geo_lon"); ok2 {
				v.GeoLocated++
			}
		}
		if c, _ := ev.Meta["geo_country"].(string); c != "" {
			country[c]++
		}
		if a := asnLabel(ev.Meta); a != "" {
			asn[a]++
		}
		if nc, _ := ev.Meta["net_class"].(string); nc != "" {
			netClass[nc]++
		}
		intel := false
		if hit, _ := ev.Meta["threat_intel_hit"].(bool); hit {
			intel = true
		}
		if ext, _ := ev.Meta["external_intel"].(string); ext != "" {
			intelLabel[ext]++
			intel = true
		}
		for _, ti := range metaStrings(ev.Meta, "threat_intel") {
			intelLabel[ti]++
			intel = true
		}
		if tor, _ := ev.Meta["tor_exit"].(bool); tor {
			torExits++
			intelLabel["tor-exit"]++
			intel = true
		}
		if intel {
			intelHits++
			if ev.Source.IP != "" && !intelIP[ev.Source.IP] {
				intelIP[ev.Source.IP] = true
				distinctIntelIPs++
			}
		}
	}

	if fig, ok := sourceMap(evs); ok {
		v.HasMap = true
		v.MapB64 = fig.B64
	}

	v.Counters = []counter{
		{Label: "events", Value: len(evs), Class: "c-total", Href: "/events"},
		{Label: "geo-located", Value: v.GeoLocated, Class: "c-icmp"},
		{Label: "countries", Value: len(country), Class: "c-tcp", Href: "#map-countries"},
		{Label: "ASNs", Value: len(asn), Class: "c-udp", Href: "#map-asns"},
		{Label: "threat-intel hits", Value: intelHits, Class: "sev-bg-high"},
		{Label: "known-bad sources", Value: distinctIntelIPs, Class: "sev-bg-critical"},
		{Label: "tor exits", Value: torExits, Class: "sev-bg-medium"},
	}
	v.Countries = topBars(country, 20, "")
	v.ASNs = topBars(asn, 20, "")
	v.NetClasses = topBars(netClass, 12, "")
	v.IntelSources = topBars(intelLabel, 15, "")

	// Recent high-severity, geo-tagged attacks (events arrive time-DESC).
	for _, ev := range evs {
		if sevRank(ev.Severity.String()) < sevRank("high") {
			continue
		}
		c, _ := ev.Meta["geo_country"].(string)
		city, _ := ev.Meta["geo_city"].(string)
		intel := false
		if hit, _ := ev.Meta["threat_intel_hit"].(bool); hit {
			intel = true
		}
		if tor, _ := ev.Meta["tor_exit"].(bool); tor {
			intel = true
		}
		v.Recent = append(v.Recent, mapHit{
			Time: ev.Time, Source: ev.Source.IP, Country: c, City: city,
			ASN: asnLabel(ev.Meta), Sev: ev.Severity.String(),
			Handler: ev.Handler, RuleID: ev.RuleID, Intel: intel,
		})
		if len(v.Recent) >= 40 {
			break
		}
	}
	sort.SliceStable(v.Recent, func(i, j int) bool { return v.Recent[i].Time.After(v.Recent[j].Time) })
	return v
}

func (s *Server) handleThreatMap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	dur, rkey, rlabel, rlinks := pageRange(r, "/map")
	since := time.Now().Add(-dur)
	evs, err := s.windowEvents(ctx, dur, s.scanCap(mapScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildThreatMapView(since, evs)
	v.RangeKey, v.RangeLabel, v.RangeLinks = rkey, rlabel, rlinks
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "threatmap", v); err != nil {
		slog.Warn("ui: render threatmap", "err", err)
	}
}

func (s *Server) handleAPIThreatMap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-mapWindow)
	evs, err := s.windowEvents(ctx, mapWindow, s.scanCap(mapScanMax))
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	writeJSON(w, buildThreatMapView(since, evs))
}
