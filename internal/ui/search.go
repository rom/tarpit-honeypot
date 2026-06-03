package ui

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// inputError marks an error caused by bad operator input (a malformed regex or
// time) rather than a server fault, so handleSearch can show it in the form
// instead of returning a 500.
type inputError struct{ msg string }

func (e inputError) Error() string { return e.msg }

func isUserInputErr(err error) bool {
	var ie inputError
	return errors.As(err, &ie)
}

// Advanced search. The free-text-style fields (source / dest IP, rule, handler,
// full-text) are treated as case-insensitive regular expressions matched
// Go-side, so an operator can search a partial / incomplete value ("10.0.",
// "^192\.168\.") or a real pattern. The structured constraints that map to a
// store column (time window / severity) are pushed into the SQL query to bound
// the scan; everything else — including the full-text over the decoded payload,
// the request line, HTTP headers, and every flattened/nested meta field — is
// matched over the captured event. Natural-language search is intentionally out
// of scope (it would require an LLM the sensor doesn't ship).

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
	After       string // events at/after this time (RFC3339 / date / date-time)
	Before      string // events at/before this time
	On          string // events on this day (date) or minute (date-time)
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
	// Error is a user-facing message (e.g. a bad regex or time) shown above the
	// form instead of a 500, so the operator can correct the input in place.
	Error string
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
		After:       g("after"),
		Before:      g("before"),
		On:          g("on"),
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

// compileSearch turns a user input field into a case-insensitive regexp, or nil
// when the field is blank (no constraint). A plain string is itself a valid
// (unanchored) pattern, so "10.0." matches an incomplete IP while "^10\.0\.0\.1$"
// matches exactly.
func compileSearch(pat string) (*regexp.Regexp, error) {
	if pat == "" {
		return nil, nil
	}
	return regexp.Compile("(?i)" + pat)
}

// searchTimeLayouts are accepted, most-specific first, for the after/before/on
// fields. Bare values are interpreted as UTC (the UI renders event times in UTC).
var searchTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04",
	"2006-01-02 15:04",
	"2006-01-02 15",
	"2006-01-02",
}

// parseSearchTime parses one of the accepted layouts. dateOnly is true when the
// input carried no time-of-day (so callers can treat it as a whole day).
func parseSearchTime(s string) (t time.Time, dateOnly, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false, false
	}
	for _, l := range searchTimeLayouts {
		if tt, err := time.Parse(l, s); err == nil {
			return tt.UTC(), l == "2006-01-02", true
		}
	}
	return time.Time{}, false, false
}

// searchWindow resolves the [since, until) bounds from the duration `since` plus
// the explicit after / before / on fields. Later fields win, and `on` pins both
// ends. Returns an error on an unparseable time so the form can report it.
func searchWindow(q searchQuery) (since, until time.Time, err error) {
	since = time.Now().Add(-24 * time.Hour)
	if q.Since != "" {
		if d, e := time.ParseDuration(q.Since); e == nil && d > 0 {
			since = time.Now().Add(-d)
		}
	}
	if q.After != "" {
		t, _, ok := parseSearchTime(q.After)
		if !ok {
			return since, until, inputError{fmt.Sprintf("invalid 'after' time %q (try 2006-01-02 or 2006-01-02T15:04)", q.After)}
		}
		since = t
	}
	if q.Before != "" {
		t, _, ok := parseSearchTime(q.Before)
		if !ok {
			return since, until, inputError{fmt.Sprintf("invalid 'before' time %q", q.Before)}
		}
		until = t
	}
	if q.On != "" {
		t, dateOnly, ok := parseSearchTime(q.On)
		if !ok {
			return since, until, inputError{fmt.Sprintf("invalid 'on' time %q", q.On)}
		}
		since = t
		if dateOnly {
			until = t.Add(24 * time.Hour) // the whole day
		} else {
			until = t.Add(time.Minute) // that minute
		}
	}
	return since, until, nil
}

func runSearch(ctx context.Context, st *store.Store, q searchQuery) ([]*event.Event, bool, error) {
	since, until, err := searchWindow(q)
	if err != nil {
		return nil, false, err
	}
	// The IP / rule / handler / full-text fields are regexes matched Go-side, so
	// only the time window + severity are pushed to SQL (which bounds the scan).
	srcRe, err := compileSearch(q.SourceIP)
	if err != nil {
		return nil, false, inputError{"source IP pattern — " + err.Error()}
	}
	dstRe, err := compileSearch(q.DestIP)
	if err != nil {
		return nil, false, inputError{"dest IP pattern — " + err.Error()}
	}
	ruleRe, err := compileSearch(q.RuleID)
	if err != nil {
		return nil, false, inputError{"rule pattern — " + err.Error()}
	}
	handlerRe, err := compileSearch(q.Handler)
	if err != nil {
		return nil, false, inputError{"handler pattern — " + err.Error()}
	}
	textRe, err := compileSearch(q.Text)
	if err != nil {
		return nil, false, inputError{"full-text pattern — " + err.Error()}
	}

	f := store.Filter{Since: since, Until: until, Limit: searchScanMax}
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
	out := make([]*event.Event, 0, len(evs))
	for _, ev := range evs {
		if handlerRe != nil && !handlerRe.MatchString(ev.Handler) {
			continue
		}
		if srcRe != nil && !srcRe.MatchString(ev.Source.IP) {
			continue
		}
		if dstRe != nil && !dstRe.MatchString(ev.Dest.IP) {
			continue
		}
		if port > 0 && ev.Dest.Port != port {
			continue
		}
		if ruleRe != nil && !ruleRe.MatchString(ev.RuleID) {
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
		if textRe != nil && !matchesText(ev, textRe) {
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

// matchesText reports whether the regex matches anywhere an operator can see:
// the identifiers, addresses, handler/proto, banner, the anomaly + ATT&CK
// markers, every meta field — including the request line, HTTP headers, and any
// other nested map/slice (keys and values, walked recursively) — and the
// DECODED payload bytes.
func matchesText(ev *event.Event, re *regexp.Regexp) bool {
	for _, s := range []string{ev.RuleID, ev.BannerSent, ev.Handler, ev.Proto, ev.Sensor, ev.Source.IP, ev.Dest.IP} {
		if re.MatchString(s) {
			return true
		}
	}
	for _, a := range ev.Anomalies {
		if re.MatchString(a) {
			return true
		}
	}
	for _, t := range ev.MitreTechniques {
		if re.MatchString(t) {
			return true
		}
	}
	for k, v := range ev.Meta {
		if re.MatchString(k) || metaMatch(v, re) {
			return true
		}
	}
	// Decoded payload bytes (the DB stores them base64-encoded, so a plaintext
	// search would never match the column directly).
	if ev.PayloadBase64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(ev.PayloadBase64); err == nil {
			if re.Match(raw) {
				return true
			}
		}
	}
	return false
}

// metaMatch recursively tests a meta value against the regex. Maps contribute
// both their keys and values (so a search for an HTTP header NAME like
// "x-forwarded-for" hits even though it's a key); slices and scalars are walked
// through. This is what makes the full-text reach request_line, http_headers,
// http_query_params, and any similarly-nested capture.
func metaMatch(v any, re *regexp.Regexp) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return re.MatchString(t)
	case map[string]any:
		for k, vv := range t {
			if re.MatchString(k) || metaMatch(vv, re) {
				return true
			}
		}
		return false
	case map[string]string:
		for k, vv := range t {
			if re.MatchString(k) || re.MatchString(vv) {
				return true
			}
		}
		return false
	case []any:
		for _, vv := range t {
			if metaMatch(vv, re) {
				return true
			}
		}
		return false
	case []string:
		for _, vv := range t {
			if re.MatchString(vv) {
				return true
			}
		}
		return false
	default:
		return re.MatchString(fmt.Sprintf("%v", t))
	}
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
		switch {
		case isUserInputErr(err):
			// A bad regex / time is the operator's typo, not a server fault —
			// re-render the form with the message so they can fix it in place.
			view.Error = err.Error()
		case err != nil:
			serverError(w, r.URL.Path, err)
			return
		default:
			view.Searched = true
			view.Results = results
			view.Matched = len(results)
			view.Capped = capped
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "search", view); err != nil {
		slog.Warn("ui: render search", "err", err)
	}
}
