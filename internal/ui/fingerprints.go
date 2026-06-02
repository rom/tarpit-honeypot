package ui

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/portsvc"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Fingerprint reputation: pivot from a network fingerprint (JA3 / JA4 / JA4H
// / JA3S / HASSH / HASSH-server) to everywhere it has been observed. The
// index ranks fingerprints by event volume (a cheap GROUP BY per kind); the
// detail view scans that fingerprint's events and builds a reputation
// dossier — distinct source IPs, ASNs, countries, protocols, destination
// ports, attack types (rules), tools, captured malware, and which sensors in
// the fleet saw it (cross-sensor correlation).

const (
	fingerprintListWindow   = 30 * 24 * time.Hour
	fingerprintDetailWindow = 90 * 24 * time.Hour
	fingerprintDetailMax    = 5000 // events scanned per fingerprint
	fingerprintListMax      = 250  // rows on the index
)

type fingerprintsPage struct {
	Rows   []store.FingerprintRow
	Window string
}

// FingerprintReport is the reputation dossier for one fingerprint. The
// breakdowns are CSS bar charts (barRow) so the page renders without JS.
type FingerprintReport struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Count     int       `json:"events"`
	IPs       int       `json:"distinct_ips"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Partial   bool      `json:"partial"`
	Sensors   []barRow  `json:"sensors,omitempty"` // fleet correlation
	TopIPs    []barRow  `json:"top_ips,omitempty"`
	Countries []barRow  `json:"countries,omitempty"`
	ASNs      []barRow  `json:"asns,omitempty"`
	Protocols []barRow  `json:"protocols,omitempty"`
	Ports     []barRow  `json:"ports,omitempty"`
	Rules     []barRow  `json:"attack_types,omitempty"`
	Tools     []barRow  `json:"tools,omitempty"`
	Malware   []barRow  `json:"malware,omitempty"`
}

// buildFingerprintReport aggregates the events that carry one fingerprint.
func buildFingerprintReport(kind, value string, evs []*event.Event) FingerprintReport {
	rep := FingerprintReport{Kind: kind, Value: value, Count: len(evs)}
	ipCount := map[string]int{}
	sensorCount := map[string]int{}
	countryCount := map[string]int{}
	asnCount := map[string]int{}
	protoCount := map[string]int{}
	ruleCount := map[string]int{}
	toolCount := map[string]int{}
	malwareCount := map[string]int{}
	portCount := map[int]int{}

	for _, ev := range evs {
		if rep.FirstSeen.IsZero() || ev.Time.Before(rep.FirstSeen) {
			rep.FirstSeen = ev.Time
		}
		if ev.Time.After(rep.LastSeen) {
			rep.LastSeen = ev.Time
		}
		if ev.Source.IP != "" {
			ipCount[ev.Source.IP]++
		}
		if ev.Sensor != "" {
			sensorCount[ev.Sensor]++
		}
		if ev.Proto != "" {
			protoCount[ev.Proto]++
		}
		if ev.RuleID != "" {
			ruleCount[ev.RuleID]++
		}
		if ev.Dest.Port != 0 {
			portCount[ev.Dest.Port]++
		}
		if c, ok := ev.Meta["geo_country"].(string); ok && c != "" {
			countryCount[c]++
		}
		if a := asnLabel(ev.Meta); a != "" {
			asnCount[a]++
		}
		for _, t := range metaStrings(ev.Meta, "tools") {
			toolCount[t]++
		}
		for _, m := range malwareKinds(ev) {
			malwareCount[m]++
		}
	}

	rep.IPs = len(ipCount)
	rep.Sensors = topBars(sensorCount, 25, "")
	rep.TopIPs = topBars(ipCount, 25, "/profiles/")
	rep.Countries = topBars(countryCount, 25, "")
	rep.ASNs = topBars(asnCount, 25, "")
	rep.Protocols = topBars(protoCount, 10, "")
	rep.Rules = topBars(ruleCount, 20, "/events?rule=")
	rep.Tools = topBars(toolCount, 25, "")
	rep.Malware = topBars(malwareCount, 25, "")
	rep.Ports = portBars(portCount, 25)
	return rep
}

// asnLabel renders an event's ASN as "AS<n> <org>" / "AS<n>" / "<org>".
func asnLabel(meta map[string]any) string {
	org, _ := meta["asn_org"].(string)
	num := metaInt(meta, "asn")
	switch {
	case num > 0 && org != "":
		return "AS" + strconv.Itoa(num) + " " + org
	case num > 0:
		return "AS" + strconv.Itoa(num)
	default:
		return org
	}
}

// malwareKinds extracts captured-artifact kinds (elf/pe/script/shellcode/…)
// from an event's payload_artifacts meta (entries look like "elf:<sha> -> f").
func malwareKinds(ev *event.Event) []string {
	var out []string
	for _, a := range metaStrings(ev.Meta, "payload_artifacts") {
		kind := a
		if i := strings.IndexByte(kind, ':'); i > 0 {
			kind = kind[:i]
		}
		if kind != "" {
			out = append(out, kind)
		}
	}
	return out
}

// portBars renders a port→count map as bars, labelling each with its
// well-known service name (e.g. "22/ssh").
func portBars(m map[int]int, n int) []barRow {
	type kv struct{ port, count int }
	items := make([]kv, 0, len(m))
	for p, c := range m {
		items = append(items, kv{p, c})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].port < items[j].port
	})
	if len(items) > n {
		items = items[:n]
	}
	max := 0
	for _, it := range items {
		if it.count > max {
			max = it.count
		}
	}
	out := make([]barRow, 0, len(items))
	for _, it := range items {
		out = append(out, barRow{Label: portsvc.Label(it.port), Count: it.count, Pct: pct(it.count, max)})
	}
	return out
}

func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.store.Fingerprints(ctx, time.Now().Add(-fingerprintListWindow), fingerprintListMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "fingerprints", fingerprintsPage{Rows: rows, Window: "30d"}); err != nil {
		slog.Warn("ui: render fingerprints", "err", err)
	}
}

// parseFingerprintPath splits "/fingerprints/<kind>/<value>" (or the API
// equivalent) into kind + value. The value may legitimately be empty-checked
// by the caller.
func parseFingerprintPath(path, prefix string) (kind, value string) {
	rest := strings.TrimPrefix(path, prefix)
	kind, value, _ = strings.Cut(rest, "/")
	return kind, value
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	kind, value := parseFingerprintPath(r.URL.Path, "/fingerprints/")
	if !store.FingerprintKindKnown(kind) || value == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	evs, err := s.query(ctx, store.Filter{
		FPKind:  kind,
		FPValue: value,
		Since:   time.Now().Add(-fingerprintDetailWindow),
		Limit:   fingerprintDetailMax,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	if len(evs) == 0 {
		http.NotFound(w, r)
		return
	}
	rep := buildFingerprintReport(kind, value, evs)
	rep.Partial = len(evs) >= fingerprintDetailMax
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "fingerprint", rep); err != nil {
		slog.Warn("ui: render fingerprint", "err", err)
	}
}

func (s *Server) handleAPIFingerprints(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.store.Fingerprints(ctx, time.Now().Add(-fingerprintListWindow), fingerprintListMax)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	writeJSON(w, rows)
}

func (s *Server) handleAPIFingerprint(w http.ResponseWriter, r *http.Request) {
	kind, value := parseFingerprintPath(r.URL.Path, "/api/fingerprints/")
	if !store.FingerprintKindKnown(kind) || value == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	evs, err := s.query(ctx, store.Filter{
		FPKind:  kind,
		FPValue: value,
		Since:   time.Now().Add(-fingerprintDetailWindow),
		Limit:   fingerprintDetailMax,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	rep := buildFingerprintReport(kind, value, evs)
	rep.Partial = len(evs) >= fingerprintDetailMax
	writeJSON(w, rep)
}

// writeJSON is a small helper mirroring the other API handlers.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
