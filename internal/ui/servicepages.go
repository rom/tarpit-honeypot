package ui

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/cve"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Per-protocol analytics pages (DNS / web / databases). Each page only exists
// when the running config has a relevant listener (hasServicePage), aggregates
// the events whose handler belongs to that category, and surfaces the queries /
// URLs / commands, the top entities, and the attacks/misuses/CVE-CWE triggered.

// Handler-name -> category. Events are tagged with the handler that produced
// them, so this is how a page knows which events are "its".
var (
	dnsHandlers = map[string]bool{"dns": true}
	webHandlers = map[string]bool{"http": true, "https": true, "http2": true}
	dbHandlers  = map[string]bool{
		"mysql": true, "postgres": true, "mssql": true, "mongodb": true,
		"redis": true, "elasticsearch": true, "oracle_tns": true,
		"cassandra": true, "etcd": true, "memcached": true, "memcached_udp": true,
	}
	// Remote-access services (interactive / remote-control surfaces).
	remoteHandlers = map[string]bool{
		"ssh": true, "ssh_interactive": true, "telnet": true,
		"rdp": true, "rdp_udp": true, "vnc": true, "winrm": true, "x11": true,
		"rlogin": true, "rsh": true, "pcanywhere": true, "teamviewer": true,
	}
	// Mail services (all SMTP / POP3 / IMAP variants).
	mailHandlers = map[string]bool{
		"smtp": true, "smtp_recv": true, "smtps": true, "submission": true,
		"pop3": true, "pop3s": true, "imap": true, "imaps": true,
	}
	// Time service.
	ntpHandlers = map[string]bool{"ntp": true}
)

func serviceCategory(handler string) string {
	switch {
	case dnsHandlers[handler]:
		return "dns"
	case webHandlers[handler]:
		return "web"
	case dbHandlers[handler]:
		return "database"
	case remoteHandlers[handler]:
		return "remote"
	case mailHandlers[handler]:
		return "mail"
	case ntpHandlers[handler]:
		return "ntp"
	}
	return ""
}

// categoryHandlers returns the handler names belonging to a service category,
// used to push the category filter into the SQL query (WHERE handler IN (…))
// instead of scanning every recent event and discarding the non-matching
// handlers Go-side.
func categoryHandlers(kind string) []string {
	var set map[string]bool
	switch kind {
	case "dns":
		set = dnsHandlers
	case "web":
		set = webHandlers
	case "database":
		set = dbHandlers
	case "remote":
		set = remoteHandlers
	case "mail":
		set = mailHandlers
	case "ntp":
		set = ntpHandlers
	default:
		return nil
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// hasServicePage reports whether the running config exposes a listener (or
// honeynet host service) in the named category, so the nav link + page show
// only when relevant.
func (s *Server) hasServicePage(kind string) bool {
	if s == nil || s.fullConfig == nil {
		return false
	}
	for _, l := range s.fullConfig.Listeners {
		if serviceCategory(l.Handler) == kind {
			return true
		}
	}
	for _, hn := range s.fullConfig.Honeynets {
		for _, h := range hn.Hosts {
			for _, sv := range h.Services {
				if serviceCategory(sv.Handler) == kind {
					return true
				}
			}
		}
	}
	return false
}

// pageRoute registers a secondary page whose nav link + route honor ui.pages:
// when the operator disables the page's slug it is hidden from the nav and the
// route returns 404.
func (s *Server) pageRoute(mux *http.ServeMux, pattern, slug string, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.PageEnabled(slug) {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	})
}

// filterByCategory returns the events whose handler belongs to kind.
func filterByCategory(evs []*event.Event, kind string) []*event.Event {
	out := make([]*event.Event, 0, len(evs))
	for _, ev := range evs {
		if serviceCategory(ev.Handler) == kind {
			out = append(out, ev)
		}
	}
	return out
}

// --- shared row/table types -------------------------------------------------

// countRow is a labeled count with an optional drill-down link.
type countRow struct {
	Label string
	Count int
	Href  string
}

// attackRow is one entry of the "attacks / misuses / vulnerabilities triggered"
// table: an anomaly marker or a CVE (with its CWE weakness class).
type attackRow struct {
	Name    string
	Count   int
	CVE     string // CVE id, when this row is a CVE
	CWE     string // first CWE id of that CVE
	CWEName string
	Desc    string // CVE name / human note
}

// metaStr reads a string meta value ("" when absent/other type).
func metaStr(ev *event.Event, key string) string {
	s, _ := ev.Meta[key].(string)
	return s
}

// perHourChart buckets events by hour into a time-series line.
func perHourChart(title string, evs []*event.Event, color string) (chartFig, bool) {
	if len(evs) == 0 {
		return chartFig{}, false
	}
	buckets := map[int64]int{}
	for _, ev := range evs {
		buckets[ev.Time.Truncate(time.Hour).UnixMilli()]++
	}
	keys := sortedInt64Keys(buckets)
	pts := make([]chPoint, 0, len(keys))
	for _, k := range keys {
		pts = append(pts, chPoint{X: float64(k), Y: float64(buckets[k])})
	}
	return chartFigure("line", title, map[string]any{
		"series": []map[string]any{{"name": "events", "points": pts, "color": color}},
		"xType":  "time",
	}), true
}

// topAttackers ranks the busiest source IPs (top 10), as both a chart series
// and a table.
func topAttackers(evs []*event.Event) (map[string]int, []countRow) {
	c := map[string]int{}
	for _, ev := range evs {
		if ev.Source.IP != "" {
			c[ev.Source.IP]++
		}
	}
	keys := topKeys(c, 10)
	rows := make([]countRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, countRow{Label: k, Count: c[k], Href: "/profiles/" + k})
	}
	return c, rows
}

// attackTable aggregates the attacks/misuses/manipulations/vulnerabilities the
// events triggered: each distinct anomaly marker (counted once per event) plus
// each CVE (with its CWE weakness class), sorted by frequency.
func attackTable(evs []*event.Event) []attackRow {
	anom := map[string]int{}
	cveCount := map[string]int{}
	for _, ev := range evs {
		seen := map[string]bool{}
		mark := func(a string) {
			a = strings.TrimSpace(a)
			if a == "" || seen[a] {
				return
			}
			seen[a] = true
			if strings.HasPrefix(strings.ToLower(a), "cve:") {
				return // CVEs are counted via eventCVEs below
			}
			anom[a]++
		}
		for _, a := range ev.Anomalies {
			mark(a)
		}
		for _, a := range metaStrings(ev.Meta, "anomalies") {
			mark(a)
		}
		cseen := map[string]bool{}
		for _, c := range eventCVEs(ev) {
			if !cseen[c] {
				cseen[c] = true
				cveCount[c]++
			}
		}
	}
	var out []attackRow
	for m, n := range anom {
		out = append(out, attackRow{Name: m, Count: n})
	}
	for id, n := range cveCount {
		row := attackRow{Name: id, Count: n, CVE: id}
		if rec, ok := cve.Lookup(id); ok {
			row.Desc = rec.Name
			if len(rec.CWE) > 0 {
				row.CWE = rec.CWE[0]
				row.CWEName = cve.CWEName(rec.CWE[0])
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// registrableDomain reduces a query name to its last two labels (a cheap
// eTLD+1 approximation, good enough for grouping honeypot DNS traffic).
func registrableDomain(qname string) string {
	q := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if q == "" {
		return ""
	}
	parts := strings.Split(q, ".")
	if len(parts) <= 2 {
		return q
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// httpStatus extracts the "code reason" from an HTTP response banner's status
// line ("HTTP/1.1 404 Not Found" -> "404 Not Found"); "" when not an HTTP reply.
func httpStatus(banner string) string {
	line := banner
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "HTTP/") {
		return ""
	}
	f := strings.SplitN(line, " ", 2)
	if len(f) < 2 {
		return ""
	}
	return strings.TrimSpace(f[1])
}

// rangeQuery / shared scaffolding ------------------------------------------

// servicePageEvents runs the standard windowed query + category filter shared
// by all three pages.
func (s *Server) servicePageEvents(r *http.Request, kind string) ([]*event.Event, sumWindow, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	win := summaryRange(r.URL.Query().Get("range"))
	since := time.Now().Add(-win.dur)
	// Push the category filter into SQL (handler IN (…), served by
	// idx_events_handler_time) and drop the payload blob + banner subquery
	// (NoPayload) — these pages aggregate over meta, never the raw bytes. This
	// reads only the matching handlers' metadata rows instead of pulling 50k
	// full rows across every service and filtering them down Go-side, which is
	// what made these pages time out once the table grew past ~100k events.
	evs, err := s.query(ctx, store.Filter{
		Since:     since,
		Handlers:  categoryHandlers(kind),
		Limit:     50000,
		NoPayload: true,
	})
	if err != nil {
		return nil, win, err
	}
	return filterByCategory(evs, kind), win, nil
}

// ============================ DNS page =====================================

type dnsView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Total      int
	Sources    int
	Domains    int
	Figs       []chartFig
	Attacks    []attackRow
	Intents    []countRow
	TopDomains []countRow
	Attackers  []countRow
	Queries    []dnsQueryRow
	Empty      bool
}

type dnsQueryRow struct {
	Time   string
	Source string
	Name   string
	Type   string
	Reply  string
	Intent string
	Anoms  []string
}

// topIntents aggregates the per-event `intent` meta label (set by the DNS / SNMP
// / NTP / http / db handlers — "what the attacker is actually doing") into a
// ranked list, deriving one from the event's signals when a handler didn't set
// it (so the web / database views always have a populated intent table).
func topIntents(evs []*event.Event) []countRow {
	c := map[string]int{}
	for _, ev := range evs {
		if it := eventIntent(ev); it != "" {
			c[it]++
		}
	}
	keys := topKeys(c, 20)
	rows := make([]countRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, countRow{Label: k, Count: c[k]})
	}
	return rows
}

// eventIntent returns the handler-set intent, or derives a concise "what the
// attacker is doing" label from the event's signals (CVE hits, web-attack
// classes, DB auth/commands, …) so views can show intent even for handlers that
// don't label it themselves.
func eventIntent(ev *event.Event) string {
	if it := metaStr(ev, "intent"); it != "" {
		return it
	}
	return deriveIntent(ev)
}

func deriveIntent(ev *event.Event) string {
	anoms := append(append([]string(nil), ev.Anomalies...), metaStrings(ev.Meta, "anomalies")...)
	for _, a := range anoms {
		if strings.HasPrefix(a, "cve:") {
			return "exploit attempt (" + strings.TrimPrefix(a, "cve:") + ")"
		}
	}
	switch serviceCategory(ev.Handler) {
	case "database":
		switch {
		case ev.Meta["password"] != nil || ev.Meta["login7_user"] != nil || metaStr(ev, "auth_user") != "" || metaStr(ev, "user") != "":
			return "database auth attempt"
		case len(metaStrings(ev.Meta, "commands")) > 0 || metaStr(ev, "mongo_command") != "" || metaStr(ev, "tns_command") != "" || metaStr(ev, "http_method") != "":
			return "database command / query"
		default:
			return "database probe / banner-grab"
		}
	case "web":
		if metaStr(ev, "http_uri") != "" || metaStr(ev, "http_method") != "" {
			return "web recon / content discovery"
		}
	}
	return ""
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if !s.hasServicePage("dns") {
		http.NotFound(w, r)
		return
	}
	evs, win, err := s.servicePageEvents(r, "dns")
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildDNS(evs)
	v.RangeLabel = win.label
	v.RangeLinks = rangeLinksFor("/dns", win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "dns", v); err != nil {
		slog.Warn("ui: render dns", "err", err)
	}
}

func buildDNS(evs []*event.Event) dnsView {
	v := dnsView{}
	if len(evs) == 0 {
		v.Empty = true
		return v
	}
	qtype := map[string]int{}
	qname := map[string]int{}
	domain := map[string]int{}
	reply := map[string]int{}
	srcSet := map[string]bool{}
	for _, ev := range evs {
		v.Total++
		if ev.Source.IP != "" {
			srcSet[ev.Source.IP] = true
		}
		if t := metaStr(ev, "qtype_name"); t != "" {
			qtype[t]++
		}
		if q := metaStr(ev, "qname"); q != "" {
			qname[q]++
			if d := registrableDomain(q); d != "" {
				domain[d]++
			}
		}
		if ev.BannerSent != "" {
			reply[ev.BannerSent]++
		}
	}
	v.Sources, v.Domains = len(srcSet), len(domain)

	if fig, ok := perHourChart("DNS queries per hour", evs, "#4a6fa5"); ok {
		v.Figs = append(v.Figs, fig)
	}
	if len(qtype) > 0 {
		v.Figs = append(v.Figs, chartFigure("bar", "DNS query types / commands", map[string]any{"series": topBarsFromMap(qtype, 20)}))
	}
	if len(qname) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top queries (qname)", map[string]any{"series": topBarsFromMap(qname, 20)}))
	}
	if len(domain) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top domains", map[string]any{"series": topBarsFromMap(domain, 20)}))
	}
	if len(reply) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top replies", map[string]any{"series": topBarsFromMap(reply, 20)}))
	}
	v.Attacks = attackTable(evs)
	v.Intents = topIntents(evs)

	// Drill-down tables behind the "domains" / "sources" counters.
	for _, d := range topKeys(domain, 100) {
		v.TopDomains = append(v.TopDomains, countRow{Label: d, Count: domain[d], Href: "/search?q=" + d})
	}
	_, v.Attackers = topAttackers(evs)

	// Query log (most recent first), bounded.
	sorted := append([]*event.Event(nil), evs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Time.After(sorted[j].Time) })
	for _, ev := range sorted {
		if len(v.Queries) >= 200 {
			break
		}
		q := metaStr(ev, "qname")
		if q == "" {
			continue
		}
		v.Queries = append(v.Queries, dnsQueryRow{
			Time:   ev.Time.UTC().Format(time.RFC3339),
			Source: ev.Source.IP,
			Name:   q,
			Type:   metaStr(ev, "qtype_name"),
			Reply:  ev.BannerSent,
			Intent: metaStr(ev, "intent"),
			Anoms:  append(append([]string(nil), ev.Anomalies...), metaStrings(ev.Meta, "anomalies")...),
		})
	}
	return v
}

// ============================ Web page =====================================

type webView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Total      int
	Sources    int
	URLs       int
	Figs       []chartFig
	Attackers  []countRow
	Attacks    []attackRow
	Intents    []countRow
	URLList    []string
	Files      []string
	Requests   []reqRow
	Empty      bool
}

// reqRow is one entry of the web request log (newest-first), carrying the
// per-request attacker intent + anomalies.
type reqRow struct {
	Time   string
	Source string
	Method string
	URI    string
	Status string
	Intent string
	Anoms  []string
}

func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request) {
	if !s.hasServicePage("web") {
		http.NotFound(w, r)
		return
	}
	evs, win, err := s.servicePageEvents(r, "web")
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildWeb(evs)
	v.RangeLabel = win.label
	v.RangeLinks = rangeLinksFor("/web", win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "web", v); err != nil {
		slog.Warn("ui: render web", "err", err)
	}
}

func buildWeb(evs []*event.Event) webView {
	v := webView{}
	if len(evs) == 0 {
		v.Empty = true
		return v
	}
	uri := map[string]int{}
	header := map[string]int{}
	reply := map[string]int{}
	attacks := map[string]int{}
	srcSet := map[string]bool{}
	urlSet := map[string]bool{}
	fileSet := map[string]bool{}
	for _, ev := range evs {
		v.Total++
		if ev.Source.IP != "" {
			srcSet[ev.Source.IP] = true
		}
		if u := metaStr(ev, "http_uri"); u != "" {
			uri[u]++
			urlSet[u] = true
			if f := uriFile(u); f != "" {
				fileSet[f] = true
			}
		}
		if pf := metaStr(ev, "probed_file"); pf != "" {
			fileSet[pf] = true
		}
		if hm, ok := ev.Meta["http_headers"].(map[string]any); ok {
			for k := range hm {
				header[k]++
			}
		}
		if hm, ok := ev.Meta["http_headers"].(map[string]string); ok {
			for k := range hm {
				header[k]++
			}
		}
		if st := httpStatus(ev.BannerSent); st != "" {
			reply[st]++
		}
		for _, a := range metaStrings(ev.Meta, "webapp_attacks") {
			attacks["webapp:"+a]++
		}
	}
	v.Sources, v.URLs = len(srcSet), len(urlSet)

	if fig, ok := perHourChart("Web requests per hour", evs, "#4a6fa5"); ok {
		v.Figs = append(v.Figs, fig)
	}
	if len(uri) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top URLs", map[string]any{"series": topBarsFromMap(uri, 20)}))
	}
	if len(header) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top HTTP headers", map[string]any{"series": topBarsFromMap(header, 20)}))
	}
	if len(reply) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top replies (HTTP status)", map[string]any{"series": topBarsFromMap(reply, 20)}))
	}
	if len(attacks) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top 10 attacks", map[string]any{"series": topBarsFromMap(attacks, 10)}))
	}
	atkByIP, atkRows := topAttackers(evs)
	_ = atkByIP
	v.Attackers = atkRows
	if len(atkRows) > 0 {
		bars := make([]chBar, 0, len(atkRows))
		for _, rr := range atkRows {
			bars = append(bars, chBar{Label: rr.Label, Value: rr.Count})
		}
		v.Figs = append(v.Figs, chartFigure("hbar", "Top 10 attackers", map[string]any{"series": bars}))
	}
	v.Attacks = attackTable(evs)
	v.Intents = topIntents(evs)
	v.URLList = sortedSetKeys(urlSet, 5000)
	v.Files = sortedSetKeys(fileSet, 5000)

	// Per-request log (newest first), with the per-request intent + anomalies.
	sorted := append([]*event.Event(nil), evs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Time.After(sorted[j].Time) })
	for _, ev := range sorted {
		if len(v.Requests) >= 200 {
			break
		}
		u := metaStr(ev, "http_uri")
		m := metaStr(ev, "http_method")
		if u == "" && m == "" {
			continue
		}
		v.Requests = append(v.Requests, reqRow{
			Time:   ev.Time.UTC().Format(time.RFC3339),
			Source: ev.Source.IP,
			Method: m,
			URI:    u,
			Status: httpStatus(ev.BannerSent),
			Intent: eventIntent(ev),
			Anoms:  append(append([]string(nil), ev.Anomalies...), metaStrings(ev.Meta, "anomalies")...),
		})
	}
	return v
}

// uriFile returns the trailing path segment of a request URI when it looks like
// a file (has a dot in the last segment), else "".
func uriFile(uri string) string {
	p := uri
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if p == "" || !strings.Contains(p, ".") {
		return ""
	}
	return p
}

// ============================ Databases page ===============================

type dbView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Total      int
	Sources    int
	Figs       []chartFig
	Attackers  []countRow
	Attacks    []attackRow
	Intents    []countRow
	Events     []dbRow
	Empty      bool
}

// dbRow is one entry of the database activity log (newest-first), with the
// per-event attacker intent + anomalies.
type dbRow struct {
	Time    string
	Source  string
	Engine  string
	Command string
	Intent  string
	Anoms   []string
}

func (s *Server) handleDatabases(w http.ResponseWriter, r *http.Request) {
	if !s.hasServicePage("database") {
		http.NotFound(w, r)
		return
	}
	evs, win, err := s.servicePageEvents(r, "database")
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildDatabases(evs)
	v.RangeLabel = win.label
	v.RangeLinks = rangeLinksFor("/databases", win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "databases", v); err != nil {
		slog.Warn("ui: render databases", "err", err)
	}
}

func buildDatabases(evs []*event.Event) dbView {
	v := dbView{}
	if len(evs) == 0 {
		v.Empty = true
		return v
	}
	query := map[string]int{}
	database := map[string]int{}
	reply := map[string]int{}
	engine := map[string]int{}
	srcSet := map[string]bool{}
	for _, ev := range evs {
		v.Total++
		if ev.Source.IP != "" {
			srcSet[ev.Source.IP] = true
		}
		if ev.Handler != "" {
			engine[ev.Handler]++
		}
		// "Query / command" varies by engine — collect whichever the handler set.
		for _, c := range metaStrings(ev.Meta, "commands") { // redis
			query[c]++
		}
		for _, k := range []string{"mongo_command", "tns_command", "http_path", "http_method"} {
			if cmd := metaStr(ev, k); cmd != "" {
				query[cmd]++
			}
		}
		// Database name requested.
		if d := metaStr(ev, "database"); d != "" {
			database[d]++
		}
		if sp, ok := ev.Meta["startup_params"].(map[string]any); ok { // postgres
			if d, _ := sp["database"].(string); d != "" {
				database[d]++
			}
		}
		if sp, ok := ev.Meta["startup_params"].(map[string]string); ok {
			if d := sp["database"]; d != "" {
				database[d]++
			}
		}
		if svc := metaStr(ev, "service_name"); svc != "" { // oracle
			database[svc]++
		}
		if ev.BannerSent != "" {
			reply[ev.BannerSent]++
		}
	}
	v.Sources = len(srcSet)

	if fig, ok := perHourChart("Database events per hour", evs, "#4a6fa5"); ok {
		v.Figs = append(v.Figs, fig)
	}
	if len(engine) > 0 {
		v.Figs = append(v.Figs, chartFigure("pie", "By database engine", map[string]any{"slices": slicesFromMap(engine), "donut": true}))
	}
	if len(query) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top queries / commands", map[string]any{"series": topBarsFromMap(query, 20)}))
	}
	if len(database) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top databases", map[string]any{"series": topBarsFromMap(database, 20)}))
	}
	if len(reply) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top replies", map[string]any{"series": topBarsFromMap(reply, 20)}))
	}
	atkByIP, atkRows := topAttackers(evs)
	_ = atkByIP
	v.Attackers = atkRows
	if len(atkRows) > 0 {
		bars := make([]chBar, 0, len(atkRows))
		for _, rr := range atkRows {
			bars = append(bars, chBar{Label: rr.Label, Value: rr.Count})
		}
		v.Figs = append(v.Figs, chartFigure("hbar", "Top 10 attackers", map[string]any{"series": bars}))
	}
	v.Attacks = attackTable(evs)
	v.Intents = topIntents(evs)

	// Per-event activity log (newest first), with engine + command + intent.
	sorted := append([]*event.Event(nil), evs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Time.After(sorted[j].Time) })
	for _, ev := range sorted {
		if len(v.Events) >= 200 {
			break
		}
		v.Events = append(v.Events, dbRow{
			Time:    ev.Time.UTC().Format(time.RFC3339),
			Source:  ev.Source.IP,
			Engine:  ev.Handler,
			Command: dbCommandSummary(ev),
			Intent:  eventIntent(ev),
			Anoms:   append(append([]string(nil), ev.Anomalies...), metaStrings(ev.Meta, "anomalies")...),
		})
	}
	return v
}

// dbCommandSummary picks the most descriptive command/query string an event
// carries across the database engines.
func dbCommandSummary(ev *event.Event) string {
	for _, k := range []string{"mongo_command", "tns_command", "http_method", "database", "auth_user", "user"} {
		if v := metaStr(ev, k); v != "" {
			return v
		}
	}
	if cmds := metaStrings(ev.Meta, "commands"); len(cmds) > 0 {
		return strings.Join(cmds, " ")
	}
	return ""
}

// ============== Generic service views: remote-access / mail / ntp ==========
//
// These mirror the DNS view (charts, top attackers, attacks/CVEs, attacker
// intent, and a per-event log) but are driven by one generic builder + template
// so the three categories share the scaffolding.

type svcView struct {
	RangeLabel string
	RangeLinks []rangeLink
	Title      string
	Slug       string
	Total      int
	Sources    int
	Figs       []chartFig
	Attackers  []countRow
	Attacks    []attackRow
	Intents    []countRow
	Log        []svcLogRow
	Empty      bool
}

// svcLogRow is one entry of a service page's per-event log, with the per-event
// attacker intent + anomalies.
type svcLogRow struct {
	Time    string
	Source  string
	Service string
	Detail  string
	Intent  string
	Anoms   []string
}

func (s *Server) handleRemote(w http.ResponseWriter, r *http.Request) {
	s.servicePage(w, r, "remote", "remote-access analytics", "remote")
}
func (s *Server) handleMail(w http.ResponseWriter, r *http.Request) {
	s.servicePage(w, r, "mail", "mail analytics", "mail")
}
func (s *Server) handleNTPPage(w http.ResponseWriter, r *http.Request) {
	s.servicePage(w, r, "ntp", "ntp analytics", "ntp")
}

func (s *Server) servicePage(w http.ResponseWriter, r *http.Request, kind, title, slug string) {
	if !s.hasServicePage(kind) {
		http.NotFound(w, r)
		return
	}
	evs, win, err := s.servicePageEvents(r, kind)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	v := buildServiceView(kind, title, evs)
	v.Slug = slug
	v.RangeLabel = win.label
	v.RangeLinks = rangeLinksFor("/"+slug, win.key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "service", v); err != nil {
		slog.Warn("ui: render service page", "slug", slug, "err", err)
	}
}

func buildServiceView(kind, title string, evs []*event.Event) svcView {
	v := svcView{Title: title}
	if len(evs) == 0 {
		v.Empty = true
		return v
	}
	engine := map[string]int{}
	srcSet := map[string]bool{}
	reply := map[string]int{}
	detail := map[string]int{}
	for _, ev := range evs {
		v.Total++
		if ev.Source.IP != "" {
			srcSet[ev.Source.IP] = true
		}
		if ev.Handler != "" {
			engine[ev.Handler]++
		}
		if ev.BannerSent != "" {
			reply[ev.BannerSent]++
		}
		if d := serviceDetail(ev, kind); d != "" {
			detail[d]++
		}
	}
	v.Sources = len(srcSet)

	if fig, ok := perHourChart(title+" per hour", evs, "#4a6fa5"); ok {
		v.Figs = append(v.Figs, fig)
	}
	if len(engine) > 0 {
		v.Figs = append(v.Figs, chartFigure("pie", "By service", map[string]any{"slices": slicesFromMap(engine), "donut": true}))
	}
	if len(detail) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", serviceDetailTitle(kind), map[string]any{"series": topBarsFromMap(detail, 20)}))
	}
	if len(reply) > 0 {
		v.Figs = append(v.Figs, chartFigure("hbar", "Top replies / banners", map[string]any{"series": topBarsFromMap(reply, 20)}))
	}
	_, v.Attackers = topAttackers(evs)
	if len(v.Attackers) > 0 {
		bars := make([]chBar, 0, len(v.Attackers))
		for _, rr := range v.Attackers {
			bars = append(bars, chBar{Label: rr.Label, Value: rr.Count})
		}
		v.Figs = append(v.Figs, chartFigure("hbar", "Top 10 attackers", map[string]any{"series": bars}))
	}
	v.Attacks = attackTable(evs)
	v.Intents = topIntents(evs)

	sorted := append([]*event.Event(nil), evs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Time.After(sorted[j].Time) })
	for _, ev := range sorted {
		if len(v.Log) >= 200 {
			break
		}
		v.Log = append(v.Log, svcLogRow{
			Time:    ev.Time.UTC().Format(time.RFC3339),
			Source:  ev.Source.IP,
			Service: ev.Handler,
			Detail:  serviceDetail(ev, kind),
			Intent:  eventIntent(ev),
			Anoms:   append(append([]string(nil), ev.Anomalies...), metaStrings(ev.Meta, "anomalies")...),
		})
	}
	return v
}

func serviceDetailTitle(kind string) string {
	switch kind {
	case "remote":
		return "Top usernames / commands"
	case "mail":
		return "Top senders / recipients / commands"
	case "ntp":
		return "Top NTP requests / intents"
	}
	return "Top details"
}

// serviceDetail picks the most telling per-event detail for the category, from
// the meta keys the relevant handlers actually set.
func serviceDetail(ev *event.Event, kind string) string {
	switch kind {
	case "remote":
		if c := metaStr(ev, "exec_command"); c != "" {
			return c
		}
		if cmds := metaStrings(ev.Meta, "shell_commands"); len(cmds) > 0 {
			return cmds[0]
		}
		if cmds := metaStrings(ev.Meta, "commands"); len(cmds) > 0 {
			return cmds[0]
		}
		for _, k := range []string{"user_attempt", "accepted_user", "auth_user", "ntlm_user"} {
			if v := metaStr(ev, k); v != "" {
				return v
			}
		}
	case "mail":
		if f := metaStr(ev, "mail_from"); f != "" {
			if t := metaStr(ev, "rcpt_to"); t != "" {
				return f + " → " + t
			}
			return f
		}
		for _, k := range []string{"rcpt_to", "auth_user", "helo"} {
			if v := metaStr(ev, k); v != "" {
				return v
			}
		}
		if e := metaStrings(ev.Meta, "expn_list"); len(e) > 0 {
			return "EXPN/VRFY " + strings.Join(e, ",")
		}
	case "ntp":
		for _, k := range []string{"intent", "ntp_request", "ntp_control_opcode"} {
			if v := metaStr(ev, k); v != "" {
				return v
			}
		}
	}
	return ""
}

// sortedSetKeys returns the set's keys sorted, capped at n.
func sortedSetKeys(set map[string]bool, n int) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}
