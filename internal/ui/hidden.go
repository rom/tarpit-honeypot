package ui

import (
	"context"
	"net"
	"net/netip"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// ipMatcher is the presentation-layer display allowlist: source IPs / CIDRs the
// operator chose to HIDE from the web UI. The events stay in the store and in
// every export / SIEM feed — they are simply not rendered in any view. Built
// once from ui.hidden_ips at New(); a config reload rebuilds it.
type ipMatcher struct {
	exact map[string]struct{}
	cidrs []netip.Prefix
}

// newIPMatcher parses a list of IPs and CIDRs. Malformed entries are skipped.
func newIPMatcher(list []string) *ipMatcher {
	if len(list) == 0 {
		return nil
	}
	m := &ipMatcher{exact: map[string]struct{}{}}
	for _, s := range list {
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			m.cidrs = append(m.cidrs, p)
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			m.exact[ip.String()] = struct{}{}
			continue
		}
		// Tolerate non-normalized text (e.g. with a zone or surrounding space).
		if ip := net.ParseIP(s); ip != nil {
			if a, ok := netip.AddrFromSlice(ip); ok {
				m.exact[a.Unmap().String()] = struct{}{}
			}
		}
	}
	if len(m.exact) == 0 && len(m.cidrs) == 0 {
		return nil
	}
	return m
}

// match reports whether ip is on the hide list.
func (m *ipMatcher) match(ip string) bool {
	if m == nil || ip == "" {
		return false
	}
	if _, ok := m.exact[ip]; ok {
		return true
	}
	if len(m.cidrs) == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range m.cidrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- Server-side presentation filters --------------------------------------

// hides reports whether a source IP should be hidden from the UI.
func (s *Server) hides(ip string) bool { return s.hidden != nil && s.hidden.match(ip) }

// query runs a store query and drops events whose source is on the UI
// hide list — the single chokepoint every view goes through, so a hidden IP
// never reaches any rendered page or JSON endpoint.
func (s *Server) query(ctx context.Context, f store.Filter) ([]*event.Event, error) {
	evs, err := s.store.Query(ctx, f)
	if err != nil || s.hidden == nil {
		return evs, err
	}
	out := evs[:0]
	for _, ev := range evs {
		if !s.hidden.match(ev.Source.IP) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// visibleSourceCounts / visibleAggregates / visibleIOCs filter the SQL-side
// rollups (which don't go through query) by the same hide list.
func (s *Server) visibleSourceCounts(in []store.SourceCount) []store.SourceCount {
	if s.hidden == nil {
		return in
	}
	out := in[:0]
	for _, c := range in {
		if !s.hidden.match(c.IP) {
			out = append(out, c)
		}
	}
	return out
}

func (s *Server) visibleAggregates(in []store.SourceAggregate) []store.SourceAggregate {
	if s.hidden == nil {
		return in
	}
	out := in[:0]
	for _, a := range in {
		if !s.hidden.match(a.IP) {
			out = append(out, a)
		}
	}
	return out
}

// linkTechBars rewrites technique bar links to point at attack.mitre.org when
// out-linking is enabled (the bar Label is the technique id). When disabled it
// leaves the internal drill-down link untouched. Recursively handles the
// per-tactic nested technique bars.
func (s *Server) linkTechBars(bars []barRow) []barRow {
	if !s.cfg.AttackLinksEnabled() {
		return bars
	}
	for i := range bars {
		if u := attackURL(bars[i].Label); u != "" {
			bars[i].Href = u
			bars[i].External = true
		}
	}
	return bars
}

func (s *Server) visibleIOCs(in []store.IOCRow) []store.IOCRow {
	if s.hidden == nil {
		return in
	}
	out := in[:0]
	for _, r := range in {
		// Hide the bare-IP indicator and any indicator last attributed to a
		// hidden source.
		if (r.Type == "ip" && s.hidden.match(r.Value)) || s.hidden.match(r.LastSource) {
			continue
		}
		out = append(out, r)
	}
	return out
}
