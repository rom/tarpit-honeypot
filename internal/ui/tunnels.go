package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Tunnels & covert-transport view. This is an HONEST view: the honeypot
// terminates connections, it does not carry real SSH/SOCKS/k8s/service-mesh
// pivots, so there are no live tunnels to graph. What it CAN show is the
// detections of tunnelling / covert channels it observes — DNS tunnels,
// encrypted-DNS, DGA, sniffer encapsulation (GRE/6in4/…), ICMP tunnels, QUIC,
// and unknown-protocol probes — aggregated by type / source / recency.

const tunnelWindow = 24 * time.Hour
const tunnelScanMax = 20000

// tunnelKinds maps an anomaly marker (or auto protocol_guess) to a friendly
// covert-transport kind. Only these are surfaced on the tunnels view.
var tunnelKinds = map[string]string{
	"dns-tunnel-suspected": "dns-tunnel",
	"dns-qname-overlong":   "dns-tunnel",
	"dns-dga-suspected":    "dga-domain",
	"dns-over-https":       "encrypted-dns (doh)",
	"dns-over-tls":         "encrypted-dns (dot)",
	"dnscrypt-probe":       "encrypted-dns (dnscrypt)",
	"sniffer:icmp_tunnel":  "icmp-tunnel",
	"unknown-protocol":     "unknown-protocol",
}

type tunnelsView struct {
	Since   time.Time
	Types   []barRow
	Sources []tunnelSource
	Recent  []tunnelHit
}

type tunnelSource struct {
	IP    string
	Count int
	Kinds []string
}

type tunnelHit struct {
	Time   time.Time
	Source string
	Kind   string
	Detail string
}

func buildTunnelsView(since time.Time, evs []*event.Event) tunnelsView {
	v := tunnelsView{Since: since}
	typeCount := map[string]int{}
	srcKinds := map[string]map[string]bool{}
	srcCount := map[string]int{}

	record := func(ev *event.Event, kind, detail string) {
		typeCount[kind]++
		ip := ev.Source.IP
		if ip != "" {
			if srcKinds[ip] == nil {
				srcKinds[ip] = map[string]bool{}
			}
			srcKinds[ip][kind] = true
			srcCount[ip]++
		}
		v.Recent = append(v.Recent, tunnelHit{Time: ev.Time, Source: ip, Kind: kind, Detail: detail})
	}

	for _, ev := range evs {
		// Encapsulation / covert L3 transport from the sniffer carries the
		// specific overlay in meta.encap_type.
		if ev.RuleID == "sniffer:encapsulation" {
			detail, _ := ev.Meta["encap_type"].(string)
			record(ev, "encapsulation", detail)
			continue
		}
		// auto catch-all guessed QUIC on an unmodelled port = covert QUIC.
		if g, _ := ev.Meta["protocol_guess"].(string); g == "quic" {
			record(ev, "quic", "")
			continue
		}
		// Anomaly-marker driven detections.
		for _, a := range metaStrings(ev.Meta, "anomalies") {
			if kind, ok := tunnelKinds[a]; ok {
				detail := ""
				if a == "dns-dga-suspected" || a == "dns-tunnel-suspected" {
					detail, _ = ev.Meta["qname"].(string)
				}
				record(ev, kind, detail)
			}
		}
	}

	v.Types = topBars(typeCount, 20, "")
	for ip, kinds := range srcKinds {
		ks := make([]string, 0, len(kinds))
		for k := range kinds {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		v.Sources = append(v.Sources, tunnelSource{IP: ip, Count: srcCount[ip], Kinds: ks})
	}
	sort.Slice(v.Sources, func(i, j int) bool {
		if v.Sources[i].Count != v.Sources[j].Count {
			return v.Sources[i].Count > v.Sources[j].Count
		}
		return v.Sources[i].IP < v.Sources[j].IP
	})
	if len(v.Sources) > 30 {
		v.Sources = v.Sources[:30]
	}
	sort.Slice(v.Recent, func(i, j int) bool { return v.Recent[i].Time.After(v.Recent[j].Time) })
	if len(v.Recent) > 50 {
		v.Recent = v.Recent[:50]
	}
	return v
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-tunnelWindow)
	evs, err := s.query(ctx, store.Filter{Since: since, Limit: tunnelScanMax})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "tunnels", buildTunnelsView(since, evs)); err != nil {
		slog.Warn("ui: render tunnels", "err", err)
	}
}
