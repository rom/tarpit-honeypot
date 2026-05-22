package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// Attacker profiles: a per-source-IP dossier compiled from every event that
// source produced — behaviour (rules, targeted services/ports), tool +
// scanner fingerprinting (meta.tools, JA3/JA4/HASSH), credentials tried,
// ATT&CK techniques/tactics, anomalies, and CVEs. The list view (cheap
// GROUP BY) ranks actors by a severity-weighted threat score; the detail
// view scans that actor's events and builds the full dossier, which grows
// as the source keeps interacting.

// profileListWindow / profileDetailWindow bound how far back the list and
// the per-actor dossier look.
const (
	profileListWindow   = 30 * 24 * time.Hour
	profileDetailWindow = 90 * 24 * time.Hour
	profileDetailMax    = 2000 // events scanned per actor for the dossier
)

type countItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type credPair struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Profile is the compiled dossier for one source IP.
type Profile struct {
	IP          string         `json:"ip"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Count       int            `json:"events"`
	Partial     bool           `json:"partial"` // true if more events exist than were scanned
	BySeverity  map[string]int `json:"by_severity"`
	MaxSeverity string         `json:"max_severity"`
	ThreatScore int            `json:"threat_score"`
	ThreatLevel string         `json:"threat_level"`
	// Classification is a synthesized higher-level label for this actor
	// (e.g. "C2 / red-team framework", "vulnerability scan", "credential
	// brute-force", "reconnaissance / scanning", "exploitation attempt").
	Classification string `json:"classification,omitempty"`
	// Summary is a one-line human-readable assessment of the actor.
	Summary    string   `json:"summary,omitempty"`
	Automation bool     `json:"automation"`
	Tools      []string `json:"tools,omitempty"`
	// Confidence is the highest tool-identification confidence (0-100) seen
	// across this source's events; ConfidenceLabel renders the coarse band.
	Confidence   int               `json:"confidence,omitempty"`
	Rules        []countItem       `json:"rules,omitempty"`
	Handlers     []string          `json:"handlers_targeted,omitempty"`
	Ports        []int             `json:"ports_targeted,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Anomalies    []string          `json:"anomalies,omitempty"`
	Mitre        []string          `json:"mitre_techniques,omitempty"`
	Tactics      []string          `json:"mitre_tactics,omitempty"`
	CVEs         []string          `json:"cves,omitempty"`
	Credentials  []credPair        `json:"credentials,omitempty"`
	Sensors      []string          `json:"sensors,omitempty"`
	Recent       []*event.Event    `json:"-"`
}

// buildProfile aggregates one source's events (expected newest-first) into a
// dossier.
func buildProfile(ip string, evs []*event.Event) Profile {
	p := Profile{IP: ip, BySeverity: map[string]int{}, Fingerprints: map[string]string{}}
	toolSet := map[string]struct{}{}
	anomSet := map[string]struct{}{}
	mitreSet := map[string]struct{}{}
	tacticSet := map[string]struct{}{}
	cveSet := map[string]struct{}{}
	handlerSet := map[string]struct{}{}
	sensorSet := map[string]struct{}{}
	portSet := map[int]struct{}{}
	ruleCount := map[string]int{}
	credSeen := map[string]struct{}{}
	var maxSev event.Severity

	for _, ev := range evs {
		p.Count++
		if p.FirstSeen.IsZero() || ev.Time.Before(p.FirstSeen) {
			p.FirstSeen = ev.Time
		}
		if ev.Time.After(p.LastSeen) {
			p.LastSeen = ev.Time
		}
		p.BySeverity[ev.Severity.String()]++
		if ev.Severity > maxSev {
			maxSev = ev.Severity
		}
		p.ThreatScore += int(ev.Severity) * int(ev.Severity)
		ruleCount[ev.RuleID]++
		if ev.Handler != "" {
			handlerSet[ev.Handler] = struct{}{}
		}
		if ev.Dest.Port != 0 {
			portSet[ev.Dest.Port] = struct{}{}
		}
		if ev.Sensor != "" {
			sensorSet[ev.Sensor] = struct{}{}
		}
		if strings.HasPrefix(ev.RuleID, "cve:") {
			cveSet[strings.TrimPrefix(ev.RuleID, "cve:")] = struct{}{}
		}
		for _, a := range ev.Anomalies {
			anomSet[a] = struct{}{}
		}
		for _, m := range ev.MitreTechniques {
			mitreSet[m] = struct{}{}
		}
		for _, t := range ev.MitreTactics {
			tacticSet[t] = struct{}{}
		}
		for _, t := range metaStrings(ev.Meta, "tools") {
			toolSet[t] = struct{}{}
		}
		if b, ok := ev.Meta["automation"].(bool); ok && b {
			p.Automation = true
		}
		if c := metaInt(ev.Meta, "tool_confidence"); c > p.Confidence {
			p.Confidence = c
		}
		for _, fp := range []string{"ja3", "ja4", "ja4h", "ja3s", "hassh", "hassh_server"} {
			if v, ok := ev.Meta[fp].(string); ok && v != "" {
				if _, exists := p.Fingerprints[fp]; !exists {
					p.Fingerprints[fp] = v
				}
			}
		}
		for _, c := range extractCreds(ev.Meta) {
			key := c.User + "\x00" + c.Pass
			if _, dup := credSeen[key]; !dup && len(p.Credentials) < 100 {
				credSeen[key] = struct{}{}
				p.Credentials = append(p.Credentials, c)
			}
		}
		if len(p.Recent) < 50 {
			p.Recent = append(p.Recent, ev)
		}
	}

	p.MaxSeverity = maxSev.String()
	p.ThreatLevel = threatLevel(p.ThreatScore)
	p.Tools = sortedSet(toolSet)
	p.Anomalies = sortedSet(anomSet)
	p.Mitre = sortedSet(mitreSet)
	p.Tactics = sortedSet(tacticSet)
	p.CVEs = sortedSet(cveSet)
	p.Handlers = sortedSet(handlerSet)
	p.Sensors = sortedSet(sensorSet)
	p.Ports = sortedInts(portSet)
	for r, c := range ruleCount {
		p.Rules = append(p.Rules, countItem{Name: r, Count: c})
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		if p.Rules[i].Count != p.Rules[j].Count {
			return p.Rules[i].Count > p.Rules[j].Count
		}
		return p.Rules[i].Name < p.Rules[j].Name
	})
	p.synthesize()
	return p
}

// synthesize derives a higher-level classification + one-line assessment
// from the already-aggregated signals.
func (p *Profile) synthesize() {
	has := func(list []string, want string) bool {
		for _, x := range list {
			if x == want {
				return true
			}
		}
		return false
	}
	anomPrefix := func(prefix string) bool {
		for _, a := range p.Anomalies {
			if strings.HasPrefix(a, prefix) {
				return true
			}
		}
		return false
	}
	anyTool := func(pred func(string) bool) bool {
		for _, t := range p.Tools {
			if pred(t) {
				return true
			}
		}
		return false
	}
	ruleHas := func(sub string) bool {
		for _, r := range p.Rules {
			if strings.Contains(r.Name, sub) {
				return true
			}
		}
		return false
	}

	switch {
	case anyTool(toolfp.IsC2) || has(p.Anomalies, "c2-framework"):
		p.Classification = "C2 / red-team framework"
	case len(p.CVEs) > 0 || anomPrefix("webapp:") || has(p.Anomalies, "printer-cups-rce") || has(p.Anomalies, "printer-ipp-cmd-injection"):
		p.Classification = "exploitation attempt"
	case anyTool(toolfp.IsVulnScanner) || has(p.Anomalies, "vulnerability-scanner"):
		p.Classification = "vulnerability scan"
	case ruleHas("brute_force") || ruleHas("password_spray") || len(p.Credentials) >= 5:
		p.Classification = "credential brute-force"
	case has(p.Tactics, "discovery") || has(p.Tactics, "reconnaissance") || len(p.Ports) >= 10 || ruleHas("port_scan") || ruleHas("scananalysis") || anyTool(toolfp.IsHeadless):
		p.Classification = "reconnaissance / scanning"
	case p.Automation:
		p.Classification = "automated client"
	default:
		p.Classification = "manual / unclassified"
	}

	// One-line assessment.
	span := "a single moment"
	if d := p.LastSeen.Sub(p.FirstSeen); d > time.Second {
		span = humanDur(d)
	}
	var extra []string
	if len(p.Tools) > 0 {
		extra = append(extra, "tools: "+strings.Join(p.Tools, ", "))
	}
	if len(p.Credentials) > 0 {
		extra = append(extra, fmt.Sprintf("%d credential(s) tried", len(p.Credentials)))
	}
	if len(p.CVEs) > 0 {
		extra = append(extra, fmt.Sprintf("%d CVE(s): %s", len(p.CVEs), strings.Join(p.CVEs, ", ")))
	}
	suffix := ""
	if len(extra) > 0 {
		suffix = " — " + strings.Join(extra, "; ")
	}
	p.Summary = fmt.Sprintf("%s: %d event(s) over %s, %d port(s) / %d service(s) touched, peak %s severity%s.",
		p.Classification, p.Count, span, len(p.Ports), len(p.Handlers), p.MaxSeverity, suffix)
}

// humanDur renders a duration compactly (e.g. "2h13m", "45s").
func humanDur(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd%dh", h/24, h%24)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// metaStrings coerces meta[key] (which may be a string, []string, or the
// []any JSON decodes to) into a []string.
func metaStrings(meta map[string]any, key string) []string {
	v, ok := meta[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}

// metaInt coerces meta[key] into an int. In-memory events carry an int;
// events round-tripped through the JSON store decode numbers as float64.
func metaInt(meta map[string]any, key string) int {
	switch t := meta[key].(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	}
	return 0
}

// extractCreds pulls a captured (user, pass) pair from an event's meta,
// covering the field names the various auth handlers use.
func extractCreds(meta map[string]any) []credPair {
	if len(meta) == 0 {
		return nil
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := meta[k].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	user := get("user_attempt", "http_login_user", "auth_user", "user_line", "basic_user", "username", "user", "bind_dn")
	pass := get("pass_attempt", "http_login_pass", "auth_pass", "pass_line", "basic_pass", "password", "pass", "bind_pw", "auth_password", "redis_auth")
	if user == "" && pass == "" {
		return nil
	}
	return []credPair{{User: user, Pass: pass}}
}

func threatLevel(score int) string {
	switch {
	case score >= 200:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 15:
		return "elevated"
	default:
		return "low"
	}
}

func sortedSet(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedInts(m map[int]struct{}) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// ---- handlers ----

type profilesPage struct {
	Profiles []store.SourceAggregate
	SinceStr string
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	since := profileListWindow
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = d
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	aggs, err := s.store.SourceAggregates(ctx, time.Now().Add(-since), 200)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := profilesPage{Profiles: aggs, SinceStr: r.URL.Query().Get("since")}
	if err := s.tmpl.ExecuteTemplate(w, "profiles", page); err != nil {
		slog.Warn("ui: render profiles", "err", err)
	}
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/profiles/")
	if ip == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.store.Query(ctx, store.Filter{
		SourceIP: ip,
		Since:    time.Now().Add(-profileDetailWindow),
		Limit:    profileDetailMax,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	p := buildProfile(ip, evs)
	p.Partial = len(evs) >= profileDetailMax

	// The "triggered rules" table is sortable by rule name or count via
	// ?rsort=rule|count&rorder=asc|desc (server-side — the CSP forbids JS).
	rsort := r.URL.Query().Get("rsort")
	if rsort != "rule" {
		rsort = "count"
	}
	rorder := r.URL.Query().Get("rorder")
	if rorder != "asc" {
		rorder = "desc"
	}
	sortRules(p.Rules, rsort, rorder)

	view := profileView{
		Profile: p,
		RuleHeaders: ruleHeaders{
			Rule:  ruleSortHeader(ip, "rule", rsort, rorder),
			Count: ruleSortHeader(ip, "count", rsort, rorder),
		},
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "profile", view); err != nil {
		slog.Warn("ui: render profile", "err", err)
	}
}

// profileView wraps a Profile (embedded, so the template's field access is
// unchanged) with the triggered-rules sort header links.
type profileView struct {
	Profile
	RuleHeaders ruleHeaders
}

type ruleHeaders struct{ Rule, Count sortLink }

type sortLink struct {
	Href  string
	Arrow string
}

func sortRules(rules []countItem, by, order string) {
	asc := order == "asc"
	sort.Slice(rules, func(i, j int) bool {
		var less bool
		if by == "rule" {
			less = rules[i].Name < rules[j].Name
		} else {
			if rules[i].Count != rules[j].Count {
				less = rules[i].Count < rules[j].Count
			} else {
				less = rules[i].Name < rules[j].Name
			}
		}
		if asc {
			return less
		}
		return !less
	})
}

// ruleSortHeader builds the toggle link + arrow for a triggered-rules column.
func ruleSortHeader(ip, col, curSort, curOrder string) sortLink {
	next := "desc"
	arrow := ""
	if curSort == col {
		if curOrder == "desc" {
			next = "asc"
			arrow = " ▼"
		} else {
			arrow = " ▲"
		}
	}
	return sortLink{
		Href:  fmt.Sprintf("/profiles/%s?rsort=%s&rorder=%s", ip, col, next),
		Arrow: arrow,
	}
}

func (s *Server) handleAPIProfiles(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	aggs, err := s.store.SourceAggregates(ctx, time.Now().Add(-profileListWindow), 500)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aggs)
}

func (s *Server) handleAPIProfile(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
	if ip == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.store.Query(ctx, store.Filter{
		SourceIP: ip,
		Since:    time.Now().Add(-profileDetailWindow),
		Limit:    profileDetailMax,
	})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	p := buildProfile(ip, evs)
	p.Partial = len(evs) >= profileDetailMax
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}
