package ui

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Advanced search. Structured fields that map to store columns (source / rule /
// severity / since) are pushed into the SQL query to bound the scan; everything
// else — full-text, ATT&CK tactic, geo country, tool, fingerprint, ASN, dest
// IP/port, anomaly tag, has-payload/session/cve/credential — is matched Go-side
// over the captured event so the search covers the decoded payload and flattened
// meta too, not just a few indexed columns. Natural-language search is
// intentionally out of scope (it would require an LLM the sensor doesn't ship).

const searchResultCap = 500
const searchScanMax = 20000

type searchQuery struct {
	SourceIP    string
	DestIP      string
	RuleID      string
	Severity    string
	Handler     string
	Port        string
	Since       string
	Tactic      string
	Country     string
	Tool        string
	Tag         string // anomaly / ATT&CK technique substring
	Fingerprint string // ja3 / ja4 / ja4h / ja3s / hassh value
	ASN         string
	Text        string
	HasPayload  bool
	HasSession  bool
	HasCVE      bool
	HasCred     bool
}

func (q searchQuery) empty() bool {
	return q == searchQuery{}
}

type searchView struct {
	Q        searchQuery
	Searched bool
	Matched  int
	Capped   bool
	Results  []*event.Event
}

func parseSearchQuery(r *http.Request) searchQuery {
	g := func(k string) string { return strings.TrimSpace(r.URL.Query().Get(k)) }
	return searchQuery{
		SourceIP:    g("source"),
		DestIP:      g("dst"),
		RuleID:      g("rule"),
		Severity:    g("severity"),
		Handler:     g("handler"),
		Port:        g("port"),
		Since:       g("since"),
		Tactic:      g("tactic"),
		Country:     g("country"),
		Tool:        g("tool"),
		Tag:         g("tag"),
		Fingerprint: g("fp"),
		ASN:         g("asn"),
		Text:        g("q"),
		HasPayload:  g("has_payload") == "1",
		HasSession:  g("has_session") == "1",
		HasCVE:      g("has_cve") == "1",
		HasCred:     g("has_cred") == "1",
	}
}

func runSearch(ctx context.Context, st *store.Store, q searchQuery) ([]*event.Event, bool, error) {
	since := time.Now().Add(-24 * time.Hour)
	if q.Since != "" {
		if d, err := time.ParseDuration(q.Since); err == nil && d > 0 {
			since = time.Now().Add(-d)
		}
	}
	// Push only the cheap, indexed constraints to SQL; full-text is matched
	// Go-side (below) so it also covers the decoded payload + flattened meta.
	f := store.Filter{Since: since, SourceIP: q.SourceIP, RuleID: q.RuleID, Limit: searchScanMax}
	if q.Severity != "" {
		if sv, err := event.ParseSeverity(strings.ToLower(q.Severity)); err == nil {
			f.MinSeverity = sv
		}
	}
	evs, err := st.Query(ctx, f)
	if err != nil {
		return nil, false, err
	}
	port, _ := strconv.Atoi(q.Port)
	asn, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(q.ASN), "AS"))
	text := strings.ToLower(q.Text)
	out := make([]*event.Event, 0, len(evs))
	for _, ev := range evs {
		if q.Handler != "" && !strings.EqualFold(ev.Handler, q.Handler) {
			continue
		}
		if q.DestIP != "" && !strings.Contains(strings.ToLower(ev.Dest.IP), strings.ToLower(q.DestIP)) {
			continue
		}
		if port > 0 && ev.Dest.Port != port {
			continue
		}
		if q.Tactic != "" && !containsFold(eventTag(ev).Tactics, q.Tactic) {
			continue
		}
		if q.Country != "" {
			c, _ := ev.Meta["geo_country"].(string)
			if !strings.EqualFold(c, q.Country) {
				continue
			}
		}
		if asn > 0 && metaInt(ev.Meta, "asn") != asn {
			continue
		}
		if q.Tool != "" && !containsSubstrFold(metaStrings(ev.Meta, "tools"), q.Tool) {
			continue
		}
		if q.Tag != "" && !matchesTag(ev, q.Tag) {
			continue
		}
		if q.Fingerprint != "" && !matchesFingerprint(ev, q.Fingerprint) {
			continue
		}
		if q.HasPayload && ev.PayloadLen == 0 && len(metaStrings(ev.Meta, "payload_artifacts")) == 0 {
			continue
		}
		if q.HasSession {
			if _, ok := ev.Meta["session_cast"]; !ok {
				continue
			}
		}
		if q.HasCVE && !eventHasCVE(ev) {
			continue
		}
		if q.HasCred && len(extractCreds(ev)) == 0 {
			continue
		}
		if text != "" && !matchesText(ev, text) {
			continue
		}
		out = append(out, ev)
	}
	capped := false
	if len(out) > searchResultCap {
		out = out[:searchResultCap]
		capped = true
	}
	return out, capped, nil
}

// matchesText reports whether the lowercased query appears anywhere an operator
// can see: the identifiers, addresses, handler/proto, banner, every flattened
// meta value, the anomaly + ATT&CK markers, and the DECODED payload bytes.
func matchesText(ev *event.Event, low string) bool {
	for _, s := range []string{ev.RuleID, ev.BannerSent, ev.Handler, ev.Proto, ev.Sensor, ev.Source.IP, ev.Dest.IP} {
		if strings.Contains(strings.ToLower(s), low) {
			return true
		}
	}
	for _, a := range ev.Anomalies {
		if strings.Contains(strings.ToLower(a), low) {
			return true
		}
	}
	for _, t := range ev.MitreTechniques {
		if strings.Contains(strings.ToLower(t), low) {
			return true
		}
	}
	for _, v := range ev.Meta {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", v)), low) {
			return true
		}
	}
	// Decoded payload bytes (the DB stores them base64-encoded, so a plaintext
	// search would never match the column directly).
	if ev.PayloadBase64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(ev.PayloadBase64); err == nil {
			if strings.Contains(strings.ToLower(string(raw)), low) {
				return true
			}
		}
	}
	return false
}

// matchesTag matches an anomaly marker or ATT&CK technique/tactic substring.
func matchesTag(ev *event.Event, tag string) bool {
	tag = strings.ToLower(tag)
	for _, a := range ev.Anomalies {
		if strings.Contains(strings.ToLower(a), tag) {
			return true
		}
	}
	for _, a := range metaStrings(ev.Meta, "anomalies") {
		if strings.Contains(strings.ToLower(a), tag) {
			return true
		}
	}
	for _, t := range ev.MitreTechniques {
		if strings.Contains(strings.ToLower(t), tag) {
			return true
		}
	}
	return containsSubstrFold(eventTag(ev).Tactics, tag)
}

// matchesFingerprint matches any of the network fingerprints in the event meta.
func matchesFingerprint(ev *event.Event, fp string) bool {
	fp = strings.ToLower(fp)
	for _, k := range []string{"ja3", "ja4", "ja4h", "ja3s", "ja4s", "ja4x", "ja4t", "ja4ssh", "hassh", "hassh_server"} {
		if v, _ := ev.Meta[k].(string); v != "" && strings.Contains(strings.ToLower(v), fp) {
			return true
		}
	}
	return false
}

// eventHasCVE reports whether the event recorded a CVE exploit signature.
func eventHasCVE(ev *event.Event) bool {
	if strings.HasPrefix(strings.ToLower(ev.RuleID), "cve:") {
		return true
	}
	for _, a := range ev.Anomalies {
		if strings.HasPrefix(strings.ToLower(a), "cve:") {
			return true
		}
	}
	for _, a := range metaStrings(ev.Meta, "anomalies") {
		if strings.HasPrefix(strings.ToLower(a), "cve:") {
			return true
		}
	}
	return len(metaStrings(ev.Meta, "emulated_vuln_cves")) > 0
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func containsSubstrFold(xs []string, v string) bool {
	v = strings.ToLower(v)
	for _, x := range xs {
		if strings.Contains(strings.ToLower(x), v) {
			return true
		}
	}
	return false
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := parseSearchQuery(r)
	view := searchView{Q: q}
	if !q.empty() {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		results, capped, err := runSearch(ctx, s.store, q)
		if err != nil {
			serverError(w, r.URL.Path, err)
			return
		}
		view.Searched = true
		view.Results = results
		view.Matched = len(results)
		view.Capped = capped
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "search", view); err != nil {
		slog.Warn("ui: render search", "err", err)
	}
}
