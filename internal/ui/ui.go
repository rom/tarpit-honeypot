// Package ui exposes a read-only HTTP UI backed by the SQLite event store.
//
// Default bind is loopback. The validator (config.Validate) refuses to start
// on a non-loopback bind without both TLS and a static auth token. The UI is
// read-only by default — it cannot delete events, change config, or trigger
// alerts. The one exception is the device delete/whitelist action, which is
// opt-in (ui.allow_device_actions) AND always requires the auth token; with
// the flag off (the default) there are no write endpoints. The sensor host
// is a target, so that stays the safe default.
package ui

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/portsvc"
	"github.com/rom/tarpit-honeypot/internal/store"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// StatsProvider lets the UI publish Prometheus-format metrics without
// importing the router/sensor packages (which would create a cycle).
// The sensor wires up a closure that pulls Router.Stats() and listener
// counts and returns them as a flat map of metric name -> samples.
type StatsProvider func() Metrics

// Metrics is the shape /metrics renders. Each Sample has a name +
// labels (zero or more) + a numeric value. The renderer emits one
// HELP+TYPE line per unique name and one numeric line per sample.
type Metrics struct {
	Samples []Sample
}

type Sample struct {
	Name   string
	Help   string
	Type   string // "counter" | "gauge"
	Labels map[string]string
	Value  float64
}

type Server struct {
	cfg           config.UI
	store         store.EventStore
	refresh       int // auto-refresh seconds for live views (0 = off)
	authToken     string
	srv           *http.Server
	tmpl          *template.Template
	stats         StatsProvider
	fullConfig    *config.Config
	topo          *honeynet.Topology
	hosts         HostsProvider
	hostsSummary  HostsSummaryProvider
	rules         RulesProvider
	deviceActions DeviceActions
	dataDir       string
	configPaths   []string   // config file path(s), for the /config "files in use" panel
	hidden        *ipMatcher // presentation-layer source-IP hide list (ui.hidden_ips)
	startTime     time.Time  // process start, for the config page uptime

	// dashCache holds the off-request dashboard build per time-range window
	// (stale-while-revalidate), so "/" stays fast regardless of event count.
	dashMu     sync.Mutex
	dashCache  map[string]dashEntry
	dashFlight map[string]bool

	// aggCache is a short-TTL cache for the /profiles list rollup
	// (SourceAggregates), keyed by (window, limit). The profiles list is a
	// whole-window GROUP BY hit by every dashboard auto-refresh; caching it
	// collapses N concurrent identical scans into one and lets a stale result
	// cover a transient slow scan instead of showing the busy page.
	aggMu    sync.Mutex
	aggCache map[string]aggEntry
}

// aggEntry is one cached SourceAggregates rollup + when it was produced.
type aggEntry struct {
	aggs []store.SourceAggregate
	at   time.Time
}

// dashEntry is one cached dashboard build + when it was produced.
type dashEntry struct {
	d  dashboard
	at time.Time
}

// SetConfigPaths wires the config file path(s) so the /config page can list
// them alongside the enrichment/database files. Optional.
func (s *Server) SetConfigPaths(paths []string) { s.configPaths = paths }

// deviceActionsEnabled reports whether the opt-in device write actions are
// usable: the operator set the flag, an auth token is configured (so a
// tokenless loopback UI stays read-only), and a registry is wired.
func (s *Server) deviceActionsEnabled() bool {
	return s.fullConfig != nil && s.fullConfig.UI.AllowDeviceActions &&
		s.authToken != "" && s.deviceActions != nil
}

// SetStatsProvider wires up Prometheus metrics. nil disables the endpoint.
func (s *Server) SetStatsProvider(p StatsProvider) { s.stats = p }

// SetConfig wires the effective (post-defaults) config so the /config
// tab can render it. Secrets stay as env-var names because the config
// model only ever stores *_env references, never expanded values, so
// the rendered YAML is safe to display.
func (s *Server) SetConfig(c *config.Config) { s.fullConfig = c }

// SetTopology wires the resolved honeynet topology so the /topology tab
// can render the virtual networks / hosts / services. nil (or an empty
// topology) renders an "no honeynet configured" placeholder.
func (s *Server) SetTopology(t *honeynet.Topology) { s.topo = t }

// SetHostsProvider wires the learned-device inventory so the /hosts tab
// can list known / seen / allow-listed hosts (IPv4 / IPv6 / MAC). nil
// disables the tab's data (renders an empty list). A provider closure
// keeps the ui package decoupled from internal/devices.
func (s *Server) SetHostsProvider(p HostsProvider) { s.hosts = p }

// HostsProvider returns a snapshot of every host the sensor has learned.
type HostsProvider func() []HostView

// SetHostsSummaryProvider wires an aggregate view of the learned-device
// inventory (totals + by-source/by-class breakdown + IP/MAC conflicts) so
// the /devices tab can render a summary panel. nil disables the panel. A
// closure keeps the ui package decoupled from internal/devices.
func (s *Server) SetHostsSummaryProvider(p HostsSummaryProvider) { s.hostsSummary = p }

// HostsSummaryProvider returns the aggregate inventory view.
type HostsSummaryProvider func() HostsSummary

// HostsSummary is the at-a-glance device panel: counts plus the IPs that
// resolve to more than one MAC (an ARP-spoof / impersonation signal).
type HostsSummary struct {
	Total     int            `json:"total"`
	Allowed   int            `json:"allowed"`
	Rogue     int            `json:"rogue"`
	BySource  []LabeledCount `json:"by_source,omitempty"`
	ByClass   []LabeledCount `json:"by_class,omitempty"`
	Conflicts []HostConflict `json:"conflicts,omitempty"`
}

// LabeledCount is a sorted (label, count) pair for the breakdown bars.
type LabeledCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// HostConflict is one IP bound to multiple MACs in the inventory.
type HostConflict struct {
	IP   string   `json:"ip"`
	MACs []string `json:"macs"`
}

// HostView is one row in the /devices table.
type HostView struct {
	Key       string            `json:"key"` // registry key (MAC if known, else IP) for actions
	IP        string            `json:"ip,omitempty"`
	MAC       string            `json:"mac,omitempty"`
	Hostname  string            `json:"hostname,omitempty"`
	Vendor    string            `json:"vendor,omitempty"`
	Source    string            `json:"source"`
	Allowed   bool              `json:"allowed"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	Count     int               `json:"count"`
	Ports     []int             `json:"ports,omitempty"`
	Services  []string          `json:"services,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// DeviceActions lets the (opt-in) devices tab mutate the inventory. The
// sensor wires this to the devices.Registry. nil = no write actions.
type DeviceActions interface {
	Delete(key string) bool
	Allow(key string) bool
}

// SetDeviceActions wires the device delete/whitelist actions. They are only
// reachable when cfg.AllowDeviceActions is true AND an auth token is set.
func (s *Server) SetDeviceActions(a DeviceActions) { s.deviceActions = a }

func New(cfg config.UI, st store.EventStore) (*Server, error) {
	if !cfg.Enabled {
		return nil, errors.New("ui: not enabled")
	}
	// st is an interface now: a caller that didn't open a store (needsStore=false)
	// passes a nil *store.Store, which arrives as a non-nil interface wrapping a
	// nil pointer. Reject both the untyped-nil and that typed-nil case so the
	// "store is required" guard behaves exactly as it did with the concrete type.
	if st == nil || st == (*store.Store)(nil) {
		return nil, errors.New("ui: store is required")
	}
	s := &Server{cfg: cfg, store: st, refresh: cfg.UIRefreshInterval(), hidden: newIPMatcher(cfg.HiddenIPs), startTime: time.Now()}
	if cfg.AuthTokenEnv != "" {
		s.authToken = os.Getenv(cfg.AuthTokenEnv)
		if s.authToken == "" {
			return nil, fmt.Errorf("ui: env %s is empty", cfg.AuthTokenEnv)
		}
	}
	t, err := template.New("").Funcs(tmplFuncs(func() int { return s.refresh }, s.cfg.CVESource, s.cfg.MapTilesURL, s.cfg.AttackLinksEnabled(), navFuncs{
		has:     func(kind string) bool { return s.hasServicePage(kind) },
		enabled: func(slug string) bool { return s.cfg.PageEnabled(slug) },
	})).Parse(tmpls)
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	return s, nil
}

// tmplFuncs is the single source of truth for the template function map, used by
// New and by the package tests so they can never drift. refresh supplies the
// auto-refresh interval.
// navFuncs supplies the nav-gating template predicates: has reports whether a
// conditional service page has a relevant listener; enabled reports whether the
// operator has hidden a page via ui.pages.
type navFuncs struct {
	has     func(string) bool
	enabled func(string) bool
}

func tmplFuncs(refresh func() int, cveSource, mapTiles string, attackLinks bool, nav navFuncs) template.FuncMap {
	if nav.has == nil {
		nav.has = func(string) bool { return false }
	}
	if nav.enabled == nil {
		nav.enabled = func(string) bool { return true }
	}
	return template.FuncMap{
		"mapTiles": func() string { return mapTiles },
		// hasPage reports whether a conditional service page (dns / web /
		// databases) should appear in the nav — true only when the running
		// config has a relevant listener. pageEnabled reports whether the
		// operator left a togglable page visible (ui.pages).
		"hasPage":     nav.has,
		"pageEnabled": nav.enabled,
		// attackURL: the canonical MITRE page (always, e.g. for the drill-down's
		// "on attack.mitre.org" link). attackLinkURL: the same, but "" when the
		// operator disabled out-linking, so labels fall back to the internal
		// drill-down. attackType: enterprise|ics, for the link tooltip.
		"attackURL":  attackURL,
		"attackType": attackType,
		// creds extracts captured credentials/secrets from an event's meta so
		// the event-detail (per-protocol) view can highlight them.
		"creds": extractCreds,
		"attackLinkURL": func(id string) string {
			if !attackLinks {
				return ""
			}
			return attackURL(id)
		},
		"fmtTime": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"join": func(s []int) string {
			var p []string
			for _, n := range s {
				p = append(p, strconv.Itoa(n))
			}
			return strings.Join(p, ", ")
		},
		"hexdump":        hexDump,
		"fmtBytes":       humanBytes,
		"refreshSeconds": refresh,
		"svcName":        portsvc.Name,
		"confLabel":      toolfp.ConfidenceLabel,
		"techDesc":       mitre.Describe,
		"cveURL":         func(id string) string { return cveURL(cveSource, id) },
		// cveOf pulls the CVE id out of a "cve:CVE-YYYY-NNNN" rule_id, or "" when
		// the rule isn't a CVE-exploit-attempt rule — so a recent-events row for a
		// CVE rule can also link out to the CVE reference.
		"cveOf": cveOf,
		// ipv6Tag renders a small "IPv6" badge after an address when it is
		// actually an IPv6 address (so listings distinguish the family at a glance).
		"ipv6Tag": ipv6Tag,
		// tunnelKindURL links a friendly tunnel-kind label (optionally scoped to
		// one source) to the events that produced that covert-transport detection.
		"tunnelKindURL": tunnelKindURL,
		// metaScalar returns the event meta minus the keys rendered in their own
		// dedicated sections (the structured HTTP capture), so the generic meta
		// table doesn't also dump them as ugly map[...] blobs.
		"metaScalar": metaScalar,
		// strMap coerces a meta value (a map after JSON round-trip is
		// map[string]any) into an ordered-rangeable map[string]string for the
		// detail-page sub-tables.
		"strMap": strMap,
		// sourceBadges renders small reputation badges for an event/profile's
		// source — blacklist / known-threat / Tor / known-scanner / intel — from
		// the enrichment meta, so every listed IP carries its reputation inline.
		"sourceBadges": sourceBadges,
		// countryFlag maps a 2-letter ISO country code to its emoji flag (US → 🇺🇸).
		"countryFlag": countryFlag,
		// handlerLink / protoTag turn a handler name / transport label into a
		// link to the matching events listing, so they're clickable pivots
		// wherever they're rendered.
		"handlerLink": handlerLink,
		"protoTag":    protoTag,
		// svcLink turns a well-known service name (pop3 / http / …) into a link
		// to that port's events. defenseName/defenseURL link a D3FEND id to its
		// MITRE page (gated by ui.attack_links, like the ATT&CK technique links).
		"svcLink":     svcLink,
		"defenseName": mitre.DefenseName,
		"defenseURL": func(id string) string {
			if !attackLinks {
				return ""
			}
			return defenseURL(id)
		},
	}
}

// countryFlag returns the Unicode regional-indicator emoji flag for a 2-letter
// ISO-3166 country code (e.g. "US" -> "🇺🇸"); "" for anything else.
func countryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return string([]rune{0x1F1E6 + rune(code[0]-'A'), 0x1F1E6 + rune(code[1]-'A')})
}

// sourceBadges builds the reputation badge HTML for a source from its event
// meta. Empty when the IP carries no flagged reputation. Each badge is a link
// to the matching event listing so an operator can pivot from a reputation tag
// straight to the traffic behind it (scanner -> that tool's events; the others
// -> the events page filtered by that reputation flag).
func sourceBadges(meta map[string]any) template.HTML {
	if len(meta) == 0 {
		return ""
	}
	var b strings.Builder
	add := func(class, text, title, href string) {
		t := template.HTMLEscapeString(title)
		x := template.HTMLEscapeString(text)
		if href != "" {
			b.WriteString(`<a class="tag ` + class + `" href="` + href + `" title="` + t + `">` + x + `</a> `)
		} else {
			b.WriteString(`<span class="tag ` + class + `" title="` + t + `">` + x + `</span> `)
		}
	}
	// Blacklist / threat-intel list hits (operator + external reputation feeds).
	if labels := metaStrings(meta, "threat_intel"); len(labels) > 0 {
		add("bad", "blacklist", "on reputation list(s): "+strings.Join(labels, ", "), "/events?flag=blacklist")
	} else if hit, _ := meta["threat_intel_hit"].(bool); hit {
		add("bad", "threat", "flagged by threat intelligence", "/events?flag=blacklist")
	}
	if ext, _ := meta["external_intel"].(string); ext != "" {
		add("bad", "intel:"+ext, "external threat feed: "+ext, "/events?flag=intel")
	}
	if fi := metaStrings(meta, "fleet_intel"); len(fi) > 0 {
		add("bad", "fleet-intel", "fleet-derived indicator: "+strings.Join(fi, ", "), "/events?flag=fleet-intel")
	}
	if tor, _ := meta["tor_exit"].(bool); tor {
		add("warn", "tor", "known Tor exit node", "/events?flag=tor")
	}
	// Known scanner: IP-level attribution (enrichment) preferred, else a
	// self-identified internet-scanner tool from the UA fingerprint.
	if sc, _ := meta["known_scanner"].(string); sc != "" {
		add("warn", "scanner:"+sc, "known network-scanning infrastructure ("+sc+")", "/events?scanner="+url.QueryEscape(sc))
	} else if sc := scannerTool(meta); sc != "" {
		add("warn", "scanner:"+sc, "self-identified internet scanner", "/events?scanner="+url.QueryEscape(sc))
	}
	// Infrastructure origin: an authoritative cloud-provider range (most
	// specific) else the datacenter/hosting net-class — strong "rented infra,
	// not residential" triage signal.
	if cp, _ := meta["cloud_provider"].(string); cp != "" {
		add("warn", "cloud:"+cp, "cloud provider IP range ("+cp+")", "/events?cloud="+url.QueryEscape(cp))
	} else if nc, _ := meta["net_class"].(string); nc == "hosting" {
		add("warn", "hosting", "datacenter / hosting network (not residential)", "/events?flag=hosting")
	}
	if nc, _ := meta["net_class"].(string); nc == "bogon" {
		add("warn", "bogon", "spoofed / reserved (bogon) source address", "/events?flag=bogon")
	}
	return template.HTML(b.String())
}

// handlerLink renders a protocol-handler name as a link to the events list
// filtered to that handler, so an operator can pivot from any handler mention
// straight to its traffic. Empty/"-" names render as a plain dash.
func handlerLink(name string) template.HTML {
	n := strings.TrimSpace(name)
	if n == "" || n == "-" {
		return template.HTML("—")
	}
	esc := template.HTMLEscapeString(n)
	return template.HTML(`<a href="/events?handler=` + url.QueryEscape(n) + `" title="show ` + esc + ` events">` + esc + `</a>`)
}

// protoTag renders a transport label (tcp/udp/icmp) as the styled badge, made
// clickable: it pivots to the events list filtered to that transport.
func protoTag(proto string) template.HTML {
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "" {
		return ""
	}
	esc := template.HTMLEscapeString(p)
	return template.HTML(`<a class="proto proto-` + esc + `" href="/events?proto=` + url.QueryEscape(p) +
		`" title="transport: ` + esc + ` — show events">` + esc + `</a>`)
}

// svcLink renders the well-known service name for a port (pop3 / http /
// smtp-submission / …) as a link to the events list filtered to that port.
// Empty when the port has no registered name.
func svcLink(port int) template.HTML {
	name := portsvc.Name(port)
	if name == "" {
		return ""
	}
	p := strconv.Itoa(port)
	return template.HTML(`<a class="svc" href="/events?port=` + p +
		`" title="filter events on port ` + p + `">` + template.HTMLEscapeString(name) + `</a>`)
}

// defenseURL builds the MITRE D3FEND page URL for a countermeasure id (e.g.
// "D3-MFA" -> the Multi-factor Authentication technique). D3FEND addresses
// techniques by their CamelCase label IRI (`d3f:<NameWithoutSpaces>`), so we map
// the id through its human name. Empty for an unknown id.
func defenseURL(id string) string {
	name := mitre.DefenseName(id)
	if name == "" {
		return ""
	}
	return "https://d3fend.mitre.org/technique/d3f:" + strings.ReplaceAll(name, " ", "") + "/"
}

// knownScannerTools are internet-wide reconnaissance engines that self-identify
// in the UA; when one appears in an event's tools, the source is a scanner.
var knownScannerTools = map[string]bool{
	"censys": true, "censys-inspect": true, "shodan": true, "binaryedge": true,
	"shadowserver": true, "stretchoid": true, "internet-measurement": true,
	"leakix": true, "expanse": true, "onyphe": true, "criminalip": true,
	"netsystems-research": true, "projectdiscovery": true, "odin-scanner": true,
	"zgrab": true, "zgrab2": true, "masscan": true, "zmap": true,
}

// eventHasFlag reports whether an event's source carries the reputation flag
// behind a sourceBadges link — the mirror of the badge logic, so clicking a
// badge lists exactly the events that would have shown it.
func eventHasFlag(ev *event.Event, flag string) bool {
	m := ev.Meta
	switch flag {
	case "blacklist":
		if len(metaStrings(m, "threat_intel")) > 0 {
			return true
		}
		hit, _ := m["threat_intel_hit"].(bool)
		return hit
	case "intel":
		s, _ := m["external_intel"].(string)
		return s != ""
	case "fleet-intel":
		return len(metaStrings(m, "fleet_intel")) > 0
	case "tor":
		t, _ := m["tor_exit"].(bool)
		return t
	case "bogon":
		nc, _ := m["net_class"].(string)
		return nc == "bogon"
	case "cloud":
		s, _ := m["cloud_provider"].(string)
		return s != ""
	case "hosting":
		if s, _ := m["cloud_provider"].(string); s != "" {
			return true
		}
		nc, _ := m["net_class"].(string)
		return nc == "hosting"
	case "scanner":
		if s, _ := m["known_scanner"].(string); s != "" {
			return true
		}
		return scannerTool(m) != ""
	}
	return false
}

// eventHasScanner reports whether an event is attributed to the named scanner —
// either by IP-level enrichment (meta.known_scanner) or by a self-identifying UA
// tool (meta.tools). The scanner reputation badge links here so it works for
// both attribution paths (the tool= filter alone missed known_scanner-only IPs).
func eventHasScanner(ev *event.Event, name string) bool {
	if sc, _ := ev.Meta["known_scanner"].(string); strings.EqualFold(sc, name) {
		return true
	}
	for _, t := range metaStrings(ev.Meta, "tools") {
		if strings.EqualFold(t, name) {
			return true
		}
	}
	return false
}

func scannerTool(meta map[string]any) string {
	for _, t := range metaStrings(meta, "tools") {
		if knownScannerTools[strings.ToLower(t)] {
			return t
		}
	}
	return ""
}

// httpDetailKeys are surfaced in the event detail page's dedicated "HTTP
// request" section, so they're filtered out of the generic meta dump.
var httpDetailKeys = map[string]bool{
	"http_headers":      true,
	"http_cookies":      true,
	"http_query_params": true,
	"http_javascript":   true,
}

// eventMetaPromoted are meta keys the event-detail page renders in its own
// dedicated sections (interpretation, downloads), so the catch-all meta table
// drops them to avoid showing the same thing twice.
var eventMetaPromoted = map[string]bool{
	"intent":       true, // shown in the interpretation section
	"anomalies":    true, // shown as anomaly tags
	"capture_path": true, // internal path; surfaced as the pcap download
	"session_cast": true, // internal path; surfaced as the replay/cast download
}

func metaScalar(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if httpDetailKeys[k] || eventMetaPromoted[k] {
			continue
		}
		out[k] = v
	}
	return out
}

func strMap(v any) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]string:
		return m
	case map[string]any:
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			} else {
				out[k] = fmt.Sprintf("%v", val)
			}
		}
	}
	return out
}

// externalOrigin returns the "scheme://host" of an absolute http(s) URL, or ""
// for an empty / relative (self-hosted, e.g. "/static/...") URL. Used to add a
// configured map-tiles image host to the CSP img-src without widening it
// otherwise.
func externalOrigin(raw string) string {
	if raw == "" || strings.HasPrefix(raw, "/") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// attackURL returns the canonical attack.mitre.org page for an ATT&CK
// technique id, or "" for a non-technique string. A sub-technique
// (T1059.001) becomes .../T1059/001/. The matrix (enterprise vs ICS) is
// encoded in the id itself (T1xxx = enterprise, T0xxx = ICS), so the single
// /techniques/<id>/ path is correct for both.
func attackURL(id string) string {
	id = strings.TrimSpace(id)
	if !validTechniqueID(id) {
		return ""
	}
	base, sub := id, ""
	if i := strings.IndexByte(id, '.'); i > 0 {
		base, sub = id[:i], id[i+1:]
	}
	u := "https://attack.mitre.org/techniques/" + base + "/"
	if sub != "" {
		u += sub + "/"
	}
	return u
}

// attackType labels a technique id's matrix for the link tooltip: ICS
// techniques are T0xxx, everything else (T1xxx) is enterprise.
func attackType(id string) string {
	if strings.HasPrefix(id, "T0") {
		return "ics"
	}
	return "enterprise"
}

// cveURL returns the external reference URL for a CVE id, per the configured
// source ("cve.org" or the default NVD). Returns "" for a non-CVE string so the
// template can fall back to a plain label.
// ipv6Tag returns a small "IPv6" badge when ip is a real IPv6 address (not an
// IPv4 or IPv4-mapped address), else "". Used next to source addresses in
// listings so the address family is obvious.
func ipv6Tag(ip string) template.HTML {
	if isIPv6(ip) {
		// Clickable: pivots to the search filtered to every IPv6-source event,
		// so "this one is v6" leads to "show me all the v6 attackers".
		return template.HTML(` <a class="tag" href="/search?family=ipv6" title="show all IPv6-source events">IPv6</a>`)
	}
	return ""
}

// isIPv6 reports whether s is a genuine IPv6 literal (not IPv4 / IPv4-mapped).
func isIPv6(s string) bool {
	p := net.ParseIP(strings.TrimSpace(s))
	return p != nil && p.To4() == nil && p.To16() != nil
}

// cveOf extracts the CVE id from a CVE-exploit-attempt rule_id
// ("cve:CVE-2021-44228" -> "CVE-2021-44228"), or "" when the rule is not a CVE
// rule. Used to add a CVE-reference link beside such rules in the profile.
func cveOf(ruleID string) string {
	id := strings.TrimPrefix(strings.TrimSpace(ruleID), "cve:")
	if id == ruleID || !looksLikeCVE(id) {
		return ""
	}
	return id
}

func cveURL(source, id string) string {
	id = strings.TrimSpace(id)
	if !looksLikeCVE(id) {
		return ""
	}
	if source == "cve.org" {
		return "https://www.cve.org/CVERecord?id=" + id
	}
	return "https://nvd.nist.gov/vuln/detail/" + id
}

// looksLikeCVE guards the id before it becomes a link: CVE-YYYY-NNNN+.
func looksLikeCVE(id string) bool {
	if len(id) < 8 || len(id) > 24 || (id[:4] != "CVE-" && id[:4] != "cve-") {
		return false
	}
	dashes := 0
	for i := 4; i < len(id); i++ {
		c := id[i]
		if c == '-' {
			dashes++
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return dashes == 1
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/events/", s.handleEvent)
	mux.HandleFunc("/profiles", s.handleProfiles)
	mux.HandleFunc("/profiles/", s.handleProfile)
	s.pageRoute(mux, "/fingerprints", "fingerprints", s.handleFingerprints)
	s.pageRoute(mux, "/fingerprints/", "fingerprints", s.handleFingerprint)
	mux.HandleFunc("/pcap/", s.handlePcap)
	mux.HandleFunc("/session/", s.handleSession)
	mux.HandleFunc("/download", s.handleDownload)
	// Secondary pages are gated by ui.pages: a disabled page is hidden from the
	// nav and its route returns 404. Per-protocol pages (dns/web/databases) also
	// 404 unless the config has a relevant listener (checked in the handler).
	s.pageRoute(mux, "/captures", "captures", s.handleCaptures)
	s.pageRoute(mux, "/credentials", "credentials", s.handleCredentials)
	s.pageRoute(mux, "/interactions", "interactions", s.handleInteractions)
	s.pageRoute(mux, "/dns", "dns", s.handleDNS)
	s.pageRoute(mux, "/web", "web", s.handleWeb)
	s.pageRoute(mux, "/databases", "databases", s.handleDatabases)
	s.pageRoute(mux, "/rules", "rules", s.handleRules)
	s.pageRoute(mux, "/remote", "remote", s.handleRemote)
	s.pageRoute(mux, "/mail", "mail", s.handleMail)
	s.pageRoute(mux, "/ntp", "ntp", s.handleNTPPage)
	mux.HandleFunc("/loot/", s.handleLoot)
	mux.HandleFunc("/replay", s.handleReplay)
	mux.HandleFunc("/config", s.handleConfig)
	s.pageRoute(mux, "/attack", "attack", s.handleAttack)
	s.pageRoute(mux, "/attack/technique", "attack", s.handleAttackTechnique)
	mux.HandleFunc("/timeline", s.handleTimeline)
	s.pageRoute(mux, "/correlation", "correlation", s.handleCorrelation)
	s.pageRoute(mux, "/campaign", "campaigns", s.handleCampaign)
	s.pageRoute(mux, "/map", "map", s.handleThreatMap)
	s.pageRoute(mux, "/fleet", "fleet", s.handleFleet)
	s.pageRoute(mux, "/iocs", "iocs", s.handleIOCs)
	s.pageRoute(mux, "/tunnels", "tunnels", s.handleTunnels)
	mux.HandleFunc("/search", s.handleSearch)
	mux.HandleFunc("/health", s.handleHealth)
	s.pageRoute(mux, "/charts", "charts", s.handleCharts)
	s.pageRoute(mux, "/stats", "statistics", s.handleStats)
	s.pageRoute(mux, "/topology", "topology", s.handleTopology)
	s.pageRoute(mux, "/hosts", "devices", s.handleHosts)
	s.pageRoute(mux, "/devices", "devices", s.handleHosts)
	mux.HandleFunc("/devices/action", s.handleDeviceAction)
	s.pageRoute(mux, "/alerting", "alerting", s.handleAlerting)
	s.pageRoute(mux, "/errors", "errors", s.handleErrors)
	s.pageRoute(mux, "/docs", "docs", s.handleDocs)
	s.pageRoute(mux, "/docs/", "docs", s.handleDoc)
	mux.HandleFunc("/theme", s.handleTheme)
	mux.HandleFunc("/size", s.handleSize)
	mux.HandleFunc("/api/events", s.handleAPIEvents)
	mux.HandleFunc("/api/profiles", s.handleAPIProfiles)
	mux.HandleFunc("/api/profiles/", s.handleAPIProfile)
	mux.HandleFunc("/api/fingerprints", s.handleAPIFingerprints)
	mux.HandleFunc("/api/fingerprints/", s.handleAPIFingerprint)
	mux.HandleFunc("/api/summary", s.handleAPISummary)
	mux.HandleFunc("/api/heartbeat", s.handleAPIHeartbeat)
	mux.HandleFunc("/api/config", s.handleAPIConfig)
	mux.HandleFunc("/api/config/canvas", s.handleAPIConfigCanvas)
	mux.HandleFunc("/api/attack", s.handleAPIAttack)
	mux.HandleFunc("/api/campaign", s.handleAPICampaign)
	mux.HandleFunc("/api/map", s.handleAPIThreatMap)
	mux.HandleFunc("/attack/navigator", s.handleNavigator)
	mux.HandleFunc("/api/topology", s.handleAPITopology)
	mux.HandleFunc("/api/hosts", s.handleAPIHosts)
	mux.HandleFunc("/api/devices", s.handleAPIHosts)
	mux.HandleFunc("/api/devices/summary", s.handleAPIHostsSummary)
	mux.HandleFunc("/api/hosts/summary", s.handleAPIHostsSummary)
	mux.HandleFunc("/api/alerting", s.handleAPIAlerting)
	mux.HandleFunc("/api/fleet", s.handleAPIFleet)
	mux.HandleFunc("/api/iocs", s.handleAPIIOCs)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/static/", s.handleStatic)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	s.srv = &http.Server{
		Addr:              s.cfg.Bind,
		Handler:           s.withAuth(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()

	// Pre-warm the default dashboard window off the request path so the first
	// "/" load is served from cache rather than blocking on a cold full-window
	// aggregation over a large event table.
	if s.store != nil {
		go func() {
			if _, err := s.refreshIndexDashboard(summaryRange("")); err != nil {
				slog.Debug("ui: dashboard pre-warm failed", "err", err)
			}
		}()
	}

	slog.Info("ui up", "bind", s.cfg.Bind, "tls", s.cfg.TLSCert != "", "auth", s.authToken != "")
	if s.cfg.TLSCert != "" {
		return s.srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.srv.ListenAndServe()
}

// withAuth wraps the mux with a bearer-token check when the server was
// configured with an auth token. Loopback-only deployments without a token
// pass through (still validated at config load).
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Scripts load only as same-origin files we package into the binary
		// (script-src 'self', no inline/eval); fetch()/XHR is same-origin
		// (connect-src 'self'); forms post same-origin. Inline styles stay
		// for the server-rendered CSS bars.
		// img-src stays 'self' + data: unless the operator configured an
		// EXTERNAL map-tiles image, in which case that origin is added so the
		// browser may load the backdrop (a self-hosted /static URL needs no
		// change). Nothing else is ever relaxed.
		imgSrc := "img-src 'self' data:"
		if o := externalOrigin(s.cfg.MapTilesURL); o != "" {
			imgSrc += " " + o
		}
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; connect-src 'self'; "+
				"style-src 'unsafe-inline'; "+imgSrc+"; "+
				"form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		// The device-action POST authorizes itself (constant-time token
		// compare, accepting the token from a form field so a browser form
		// works), so it bypasses the header-only gate here. It still
		// refuses unless the opt-in flag + token are configured.
		if r.URL.Path == "/devices/action" {
			next.ServeHTTP(w, r)
			return
		}
		if s.authToken != "" {
			tok := r.Header.Get("Authorization")
			tok = strings.TrimPrefix(tok, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.authToken)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="tarpit"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		// Also restrict non-loopback clients even if somehow they reached us
		// (e.g. operator forgot validation). Defense in depth.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil && s.authToken == "" {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// serverError logs the underlying error (which may contain the DB path or
// other internals) and returns a generic 500 to the client so nothing
// sensitive leaks in the HTTP response body.
func serverError(w http.ResponseWriter, where string, err error) {
	// A client that navigates away / closes the tab (the auto-refreshing
	// dashboard does this routinely) cancels the request context, surfacing as
	// context.Canceled. That's normal client behaviour, not a server fault — so
	// don't spam WARN, and don't bother writing a 500 to a connection that's
	// already gone. A genuine timeout (DeadlineExceeded) still logs.
	if errors.Is(err, context.Canceled) {
		slog.Debug("ui: request cancelled by client", "path", where)
		return
	}
	// A query deadline (DeadlineExceeded) is transient, not a code fault: the
	// event store is large/busy or an index is still building, so the aggregate
	// query for this page didn't finish in its window. Don't surface a bare 500
	// "internal server error" — serve a friendly, auto-refreshing page so the
	// operator isn't staring at an error, and hint at a shorter range.
	if errors.Is(err, context.DeadlineExceeded) {
		slog.Warn("ui: page query timed out (store busy/large or index building)", "path", where)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8">`+
			`<meta http-equiv="refresh" content="5"><title>busy</title>`+
			`<style>body{font-family:system-ui,sans-serif;margin:3rem;color:#444}`+
			`a{color:#4a6fa5}</style></head><body>`+
			`<h2>⏳ This view is taking longer than usual</h2>`+
			`<p>The event store is large or busy (or an index is still building), so the `+
			`query for this page exceeded its time budget. The page will retry automatically.</p>`+
			`<p>Tip: pick a shorter time range, or check <a href="/health">/health</a> and `+
			`<a href="/errors">/errors</a>.</p></body></html>`)
		return
	}
	slog.Warn("ui: request failed", "path", where, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// sumWindow is a summary-page time range: the lookback duration, the histogram
// bucket width that keeps the trend readable, and display labels.
type sumWindow struct {
	key    string
	dur    time.Duration
	bucket time.Duration
	label  string
}

// summaryRange maps the ?range= selector to a window (default 24h). The bucket
// width is chosen so the trend stays a readable ~24–90 bars across the range.
func summaryRange(key string) sumWindow {
	day := 24 * time.Hour
	switch key {
	case "7d":
		return sumWindow{"7d", 7 * day, 6 * time.Hour, "last 7 days"}
	case "14d":
		return sumWindow{"14d", 14 * day, 12 * time.Hour, "last 14 days"}
	case "31d":
		return sumWindow{"31d", 31 * day, day, "last 31 days"}
	case "3mo":
		return sumWindow{"3mo", 90 * day, day, "last 3 months"}
	case "6mo":
		return sumWindow{"6mo", 180 * day, 7 * day, "last 6 months"}
	default:
		return sumWindow{"24h", day, time.Hour, "last 24 hours"}
	}
}

// summaryRanges is the ordered set of selector keys (shared by summary + charts).
var summaryRanges = []string{"24h", "7d", "14d", "31d", "3mo", "6mo"}

// rangeLinksFor builds the selector chips for a base path ("/" or "/charts").
func rangeLinksFor(base, active string) []rangeLink {
	out := []rangeLink{}
	for _, key := range summaryRanges {
		href := base
		if key != "24h" {
			sep := "?"
			if strings.Contains(base, "?") {
				sep = "&"
			}
			href = base + sep + "range=" + key
		}
		out = append(out, rangeLink{Label: key, Href: href, Active: key == active})
	}
	return out
}

func summaryRangeLinks(active string) []rangeLink { return rangeLinksFor("/", active) }

// pageRange parses the ?range= selector for a per-page time-range switcher,
// returning the window duration, the normalized active key (unknown -> 24h),
// the human label, and the selector chips. Other query params on the request
// (e.g. a /iocs ?type= filter) are preserved on the chips so switching the
// range keeps the active filter. Shared by the tunnels / correlation / attack /
// iocs / fleet / map pages.
func pageRange(r *http.Request, path string) (dur time.Duration, key, label string, links []rangeLink) {
	win := summaryRange(r.URL.Query().Get("range"))
	q := r.URL.Query()
	q.Del("range") // the chips set this themselves
	q.Del("since") // legacy duration param — superseded by range
	base := path
	if enc := q.Encode(); enc != "" {
		base = path + "?" + enc
	}
	return win.dur, win.key, win.label, rangeLinksFor(base, win.key)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	win := summaryRange(r.URL.Query().Get("range"))
	// The dashboard aggregates the whole event window (a multi-pass summary
	// plus a bounded enrichment scan). At hundreds of thousands of events — and
	// under the write contention of a live pentest — doing that synchronously
	// inside the request blows the deadline. Serve a cached build instead
	// (stale-while-revalidate, cold loads degraded to a quick/minimal view), so
	// the page always renders and its latency is independent of event count and
	// write load. cachedIndexDashboard never errors — it can only degrade.
	d := s.cachedIndexDashboard(win)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index", d); err != nil {
		slog.Warn("ui: render index", "err", err)
	}
}

// dashTTL is how long a cached dashboard build is served before a background
// refresh is triggered. The dashboard is a whole-window rollup, so a few
// seconds of staleness is fine and keeps page loads instant at any scale.
const dashTTL = 20 * time.Second

// aggCacheTTL bounds how long a cached /profiles list rollup is reused.
const aggCacheTTL = 5 * time.Second

// cachedSourceAggregates wraps store.SourceAggregates with a short-TTL cache
// keyed by (window, limit). Concurrent auto-refreshes of /profiles within the
// TTL share one whole-window GROUP BY instead of each re-scanning the events
// table; on a slow/cancelled scan a stale entry (when present) is served rather
// than the busy page. The returned slice is treated as an immutable snapshot —
// callers apply the presentation hide-list to a copy, never mutating it.
func (s *Server) cachedSourceAggregates(ctx context.Context, window time.Duration, limit int) ([]store.SourceAggregate, error) {
	key := window.String() + "|" + strconv.Itoa(limit)
	s.aggMu.Lock()
	ent, ok := s.aggCache[key]
	s.aggMu.Unlock()
	if ok && time.Since(ent.at) < aggCacheTTL {
		return ent.aggs, nil
	}
	aggs, err := s.store.SourceAggregates(ctx, time.Now().Add(-window), limit)
	if err != nil {
		if ok { // serve the last good result through a transient slow/locked scan
			return ent.aggs, nil
		}
		return nil, err
	}
	s.aggMu.Lock()
	if s.aggCache == nil {
		s.aggCache = map[string]aggEntry{}
	}
	// Bound the map: ?since= is arbitrary, so drop expired entries before growing
	// (keys are (window,limit) pairs — realistically a handful, never large).
	if len(s.aggCache) > 32 {
		now := time.Now()
		for k, e := range s.aggCache {
			if now.Sub(e.at) >= aggCacheTTL {
				delete(s.aggCache, k)
			}
		}
	}
	s.aggCache[key] = aggEntry{aggs: aggs, at: time.Now()}
	s.aggMu.Unlock()
	return aggs, nil
}

// cachedIndexDashboard returns the dashboard for a window, computing it off the
// request path: a fresh cache entry is served as-is; a stale one is served
// immediately while a background refresh runs; a missing one is computed now
// (with a generous internal budget, not the caller's request deadline) so the
// first load can't 500.
func (s *Server) cachedIndexDashboard(win sumWindow) dashboard {
	s.dashMu.Lock()
	ent, ok := s.dashCache[win.key]
	s.dashMu.Unlock()
	if ok && time.Since(ent.at) < dashTTL {
		return ent.d
	}
	if ok {
		s.refreshIndexDashboardAsync(win)
		return ent.d // serve stale while it refreshes
	}
	// Cold: never block the request on a full-window aggregation. Kick the full
	// build in the background and serve a "quick" view now — just the indexed
	// summary, no full-row enrichment scan — under a short budget. If even that
	// can't complete (DB locked under heavy write load), serve a minimal shell.
	// Either way the page renders; it can never 500.
	s.refreshIndexDashboardAsync(win)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	d, err := s.buildIndexDashboard(ctx, win, false)
	if err != nil {
		return s.minimalDashboard(win)
	}
	d.Notice = "Summary is still building over a large dataset — enrichment charts will appear on the next refresh."
	return d
}

// minimalDashboard is the always-renderable shell (range selector + the static
// port board, no DB) used when even the quick summary can't complete in time.
func (s *Server) minimalDashboard(win sumWindow) dashboard {
	return dashboard{
		RangeLabel: win.label,
		RangeLinks: summaryRangeLinks(win.key),
		Canvas:     buildConfigCanvas(s.fullConfig),
		Notice:     "The dataset is large and the summary is still building — reload in a few seconds.",
	}
}

// refreshIndexDashboard rebuilds + caches the full dashboard for a window under
// an internal timeout decoupled from any request deadline.
func (s *Server) refreshIndexDashboard(win sumWindow) (dashboard, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, err := s.buildIndexDashboard(ctx, win, true)
	if err != nil {
		return d, err
	}
	s.dashMu.Lock()
	if s.dashCache == nil {
		s.dashCache = map[string]dashEntry{}
	}
	s.dashCache[win.key] = dashEntry{d: d, at: time.Now()}
	s.dashMu.Unlock()
	return d, nil
}

// refreshIndexDashboardAsync kicks a single background refresh per window
// (deduped) so a stale serve doesn't fan out into many concurrent rebuilds.
func (s *Server) refreshIndexDashboardAsync(win sumWindow) {
	s.dashMu.Lock()
	if s.dashFlight == nil {
		s.dashFlight = map[string]bool{}
	}
	if s.dashFlight[win.key] {
		s.dashMu.Unlock()
		return
	}
	s.dashFlight[win.key] = true
	s.dashMu.Unlock()
	go func() {
		defer func() {
			s.dashMu.Lock()
			delete(s.dashFlight, win.key)
			s.dashMu.Unlock()
		}()
		if _, err := s.refreshIndexDashboard(win); err != nil {
			slog.Warn("ui: dashboard refresh failed", "range", win.key, "err", err)
		}
	}()
}

// buildIndexDashboard performs the dashboard aggregation for a window. With
// enrich=false it does only the indexed summary + counters (fast, for the cold
// quick-view); with enrich=true it also runs the bounded per-event
// metadata scan that fills the tactics/geo/ASN/tool/handler charts.
func (s *Server) buildIndexDashboard(ctx context.Context, win sumWindow, enrich bool) (dashboard, error) {
	since := time.Now().Add(-win.dur)
	sum, err := s.store.Summary(ctx, since)
	if err != nil {
		return dashboard{}, err
	}
	sum.TopSources = s.visibleSourceCounts(sum.TopSources) // presentation hide list
	hours, err := s.store.EventsPerBucket(ctx, since, win.bucket)
	if err != nil {
		return dashboard{}, err
	}
	d := buildDashboard(sum, hours, win.bucket)
	d.RangeLabel = win.label
	d.RangeLinks = summaryRangeLinks(win.key)
	d.Canvas = buildConfigCanvas(s.fullConfig) // port cards (clickable to /events?port=)
	// Top counters strip: event volume by transport + severity (from the
	// store), plus the sniffer's raw L2 frame counters when it's running.
	// Counters link to the matching event listing so an operator can click a
	// number (e.g. "12 UDP") straight to those events.
	d.Counters = []counter{
		{Label: "events", Value: sum.Total, Class: "c-total", Href: "/events"},
		{Label: "TCP", Value: sum.ByProto["tcp"], Class: "c-tcp", Href: "/events?proto=tcp"},
		{Label: "UDP", Value: sum.ByProto["udp"], Class: "c-udp", Href: "/events?proto=udp"},
		{Label: "ICMP", Value: sum.ByProto["icmp"], Class: "c-icmp", Href: "/events?proto=icmp"},
		{Label: "critical", Value: sum.BySeverity["critical"], Class: "sev-bg-critical", Href: "/events?severity=critical"},
		{Label: "high", Value: sum.BySeverity["high"], Class: "sev-bg-high", Href: "/events?severity=high"},
		{Label: "medium", Value: sum.BySeverity["medium"], Class: "sev-bg-medium", Href: "/events?severity=medium"},
		{Label: "low", Value: sum.BySeverity["low"], Class: "sev-bg-low", Href: "/events?severity=low"},
		// Captured second-stage samples / dropped artifacts (downloaded payloads,
		// YARA-scanned, never executed). Links to the malware-capture events;
		// the raw files are on the captures page.
		{Label: "captured", Value: sum.ByRule["malware:capture"], Class: "c-captured", Href: "/events?rule=malware:capture"},
	}
	if s.stats != nil {
		fr := map[string]int{}
		for _, smp := range s.stats().Samples {
			if smp.Name == "tarpit_sniffer_frames_total" {
				fr[smp.Labels["proto"]] = int(smp.Value)
			}
		}
		if _, ok := fr["all"]; ok { // sniffer running
			d.HasFrames = true
			d.Frames = []counter{
				{Label: "received", Value: fr["all"]}, {Label: "ARP", Value: fr["arp"]}, {Label: "IPv4", Value: fr["ipv4"]},
				{Label: "IPv6", Value: fr["ipv6"]}, {Label: "TCP", Value: fr["tcp"]}, {Label: "UDP", Value: fr["udp"]}, {Label: "ICMP", Value: fr["icmp"]},
			}
		}
	}
	// Enrich with per-event dimensions (tactics / geo / ASN / tool / handler)
	// from a bounded scan of the window. Skipped for the cold quick-view; the
	// scan reads metadata only (NoPayload) so it doesn't drag the big payload
	// blobs + per-row banner subquery through for 20k rows.
	var attackSvc []chSlice
	if enrich {
		if evs, qerr := s.query(ctx, store.Filter{Since: since, Limit: 20000, NoPayload: true}); qerr == nil {
			enrichDashboard(&d, evs)
			if s.cfg.ServiceActivityEnabled() {
				markCanvasActivity(&d.Canvas, evs) // tint service cards that saw access/attempts
			}
			attackSvc = attacksByService(evs)
		}
	}
	// Carry the active window into every /events pivot link so the listing
	// covers the same span the summary aggregated over (otherwise /events
	// defaults to 24h and a pivot off a longer window looks empty).
	scopeEventLinks(&d, win.key)
	// A compact visual overview (charts.js); the full gallery lives at /charts.
	if len(d.Severity) > 0 {
		d.Charts = append(d.Charts, chartFigure("pie", "Severity", barsToPie(d.Severity, true)))
	}
	if len(attackSvc) > 0 {
		d.Charts = append(d.Charts, chartFigure("pie", "Attacks by service (%)", map[string]any{"slices": attackSvc, "donut": true}))
	}
	if len(hours) > 0 {
		d.Charts = append(d.Charts, trendLine(hours))
	}
	if len(d.Sources) > 0 {
		d.Charts = append(d.Charts, chartFigure("hbar", "Top sources", barsToBar(d.Sources)))
	}
	return d, nil
}

type colHeader struct {
	Label string
	Href  string
	Arrow string // ▲ / ▼ when this column is the active sort key
}

type eventsPage struct {
	Events      []*event.Event
	Filter      store.Filter
	SourceStr   string // raw filter inputs, echoed back so '!'/comma round-trip
	RuleStr     string
	ProtoStr    string
	SeverityStr string
	SinceStr    string
	QStr        string
	Headers     map[string]colHeader
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	q := r.URL.Query()
	sortKey := q.Get("sort")
	order := q.Get("order")
	if order != "asc" {
		order = "desc"
	}
	// tool (a meta string array) and ATT&CK tactic (computed per event) aren't
	// SQL columns, so they're post-filtered below. Widen the SQL scan past the
	// display limit first — otherwise the post-filter only sees the newest
	// `Limit` rows and a genuine match further back wrongly looks empty. (ASN
	// and country are real meta-column filters handled in the store.)
	tool, tactic, flag, scanner := q.Get("tool"), q.Get("tactic"), q.Get("flag"), q.Get("scanner")
	cloud := q.Get("cloud")
	displayLimit := f.Limit
	if tool != "" || tactic != "" || flag != "" || scanner != "" || cloud != "" {
		f.Limit = searchScanMax
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.query(ctx, f)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	evs = filterByMeta(evs, tool, tactic, "")
	if flag != "" {
		kept := evs[:0]
		for _, ev := range evs {
			if eventHasFlag(ev, flag) {
				kept = append(kept, ev)
			}
		}
		evs = kept
	}
	if scanner != "" {
		// A scanner can be attributed either at the IP level (meta.known_scanner,
		// from ASN/rDNS) or by a self-identifying UA tool (meta.tools); the
		// scanner badge links here, so match BOTH.
		kept := evs[:0]
		for _, ev := range evs {
			if eventHasScanner(ev, scanner) {
				kept = append(kept, ev)
			}
		}
		evs = kept
	}
	if cloud != "" {
		// Per-provider cloud-range filter (the cloud:<provider> badge links here).
		kept := evs[:0]
		for _, ev := range evs {
			if cp, _ := ev.Meta["cloud_provider"].(string); strings.EqualFold(cp, cloud) {
				kept = append(kept, ev)
			}
		}
		evs = kept
	}
	if displayLimit > 0 && len(evs) > displayLimit {
		evs = evs[:displayLimit]
	}
	sortEvents(evs, sortKey, order)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := eventsPage{
		Events:      evs,
		Filter:      f,
		SourceStr:   q.Get("source"),
		RuleStr:     q.Get("rule"),
		ProtoStr:    q.Get("proto"),
		SeverityStr: q.Get("severity"),
		SinceStr:    q.Get("since"),
		QStr:        q.Get("q"),
		Headers:     buildSortHeaders("/events", q, sortKey, order),
	}
	if err := s.tmpl.ExecuteTemplate(w, "events", page); err != nil {
		slog.Warn("ui: render events", "err", err)
	}
}

// filterByMeta narrows events by the post-query summary pivots that aren't
// plain DB columns: tool (a meta "tools" string array), ATT&CK tactic
// (computed per event), and ASN (the numeric meta "asn"). Each empty argument
// is a no-op; tool/tactic match case-insensitively.
func filterByMeta(evs []*event.Event, tool, tactic, asn string) []*event.Event {
	if tool == "" && tactic == "" && asn == "" {
		return evs
	}
	asnNum := 0
	if asn != "" {
		asnNum, _ = strconv.Atoi(strings.TrimPrefix(strings.ToUpper(asn), "AS"))
	}
	out := make([]*event.Event, 0, len(evs))
	for _, ev := range evs {
		if tool != "" && !containsFold(metaStrings(ev.Meta, "tools"), tool) {
			continue
		}
		if tactic != "" && !containsFold(eventTag(ev).Tactics, tactic) {
			continue
		}
		if asnNum > 0 && metaInt(ev.Meta, "asn") != asnNum {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// sortEvents orders events in place by the requested column (empty key
// keeps the store's time-descending order). order is "asc" or "desc".
func sortEvents(evs []*event.Event, key, order string) {
	if key == "" {
		return
	}
	var less func(a, b *event.Event) bool
	switch key {
	case "severity":
		less = func(a, b *event.Event) bool { return a.Severity < b.Severity }
	case "time":
		less = func(a, b *event.Event) bool { return a.Time.Before(b.Time) }
	case "source":
		less = func(a, b *event.Event) bool { return a.Source.IP < b.Source.IP }
	case "rule":
		less = func(a, b *event.Event) bool { return a.RuleID < b.RuleID }
	case "handler":
		less = func(a, b *event.Event) bool { return a.Handler < b.Handler }
	default:
		return
	}
	sort.SliceStable(evs, func(i, j int) bool { return less(evs[i], evs[j]) })
	if order == "desc" {
		for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
			evs[i], evs[j] = evs[j], evs[i]
		}
	}
}

// buildSortHeaders builds clickable column headers that preserve the
// current filters and toggle asc/desc on the active column. Sortable
// columns: time, severity, source, rule, handler.
func buildSortHeaders(path string, q url.Values, sortKey, order string) map[string]colHeader {
	carry := url.Values{}
	for _, k := range []string{"source", "rule", "proto", "since", "limit", "severity", "q"} {
		if v := q.Get(k); v != "" {
			carry.Set(k, v)
		}
	}
	out := map[string]colHeader{}
	for _, col := range []string{"time", "severity", "source", "rule", "handler"} {
		next := "asc"
		arrow := ""
		if sortKey == col {
			if order == "asc" {
				next, arrow = "desc", " ▲"
			} else {
				next, arrow = "asc", " ▼"
			}
		}
		v := url.Values{}
		for k, vs := range carry {
			v[k] = vs
		}
		v.Set("sort", col)
		v.Set("order", next)
		out[col] = colHeader{Label: col, Href: path + "?" + v.Encode(), Arrow: arrow}
	}
	return out
}

type errorsPage struct {
	Events   []*event.Event
	SinceStr string
}

// handleErrors surfaces operational / health events — listener stopped,
// listener start error, canary watcher stopped, accept-cap overflow,
// recovered panics — filtered out of the normal detection stream.
func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) {
	since := 7 * 24 * time.Hour
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = d
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.query(ctx, store.Filter{Since: time.Now().Add(-since), Limit: 1000})
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	ops := make([]*event.Event, 0, 32)
	for _, ev := range evs {
		if isOperationalEvent(ev.RuleID) {
			ops = append(ops, ev)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "errors", errorsPage{Events: ops, SinceStr: r.URL.Query().Get("since")}); err != nil {
		slog.Warn("ui: render errors", "err", err)
	}
}

// isOperationalEvent reports whether a rule_id is a sensor-health /
// operational-error event (as opposed to an attacker-interaction event).
func isOperationalEvent(rule string) bool {
	switch {
	case rule == "sensor:reload":
		return false // audit, not an error
	case strings.HasPrefix(rule, "sensor:"):
		return true
	case strings.Contains(rule, "panic"):
		return true
	case strings.HasSuffix(rule, ":accept_cap"):
		return true
	}
	return false
}

// eventDetail is the event-detail page model: the event itself (embedded, so
// the template's promoted .Time / .Meta / .BannerSent / … keep working) plus
// the derived presentation extras — prev/next conversation navigation, the
// inferred interaction phase, the de-duplicated anomaly list, and whether a
// downloadable pcap exists for it.
type eventDetail struct {
	*event.Event
	Nav      store.EventNeighbors
	Phase    string   // inferred interaction kind (auth / discovery / control / …)
	Anoms    []string // protocol-misuse markers (ev.Anomalies + meta.anomalies)
	HasPcap  bool
	PcapName string
}

// newEventDetail builds the page model's pure (no store / filesystem) parts.
func newEventDetail(ev *event.Event) eventDetail {
	return eventDetail{Event: ev, Phase: classifyInteraction(ev), Anoms: eventAnoms(ev)}
}

// eventAnoms is the union of the event's structured anomaly markers and any in
// meta ("anomalies"), de-duplicated and order-preserving.
func eventAnoms(ev *event.Event) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range ev.Anomalies {
		add(a)
	}
	for _, a := range metaStrings(ev.Meta, "anomalies") {
		add(a)
	}
	return out
}

// classifyInteraction infers, best-effort, what kind of application-level
// exchange an event represents — authentication, command/control, service
// discovery, session establishment, or a plain probe — from its anomalies,
// the handler's inferred intent, captured credentials, and the decoded
// protocol verbs. It's a coarse at-a-glance label; meta.intent carries the
// precise description.
func classifyInteraction(ev *event.Event) string {
	var b strings.Builder
	for _, a := range eventAnoms(ev) {
		b.WriteString(strings.ToLower(a))
		b.WriteByte(' ')
	}
	for _, k := range []string{"intent", "op", "method", "command", "commands", "apdu_service",
		"cotp_type", "message_type", "request_line", "ssh_kex_msg", "function"} {
		if s, _ := ev.Meta[k].(string); s != "" {
			b.WriteString(strings.ToLower(s))
			b.WriteByte(' ')
		}
	}
	hay := b.String()
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(hay, s) {
				return true
			}
		}
		return false
	}
	switch {
	case len(extractCreds(ev)) > 0 || has("auth", "login", "credential", "brute", "password", "as-req", "ntlm"):
		return "Authentication / credential attempt"
	case has("write", "operate", "control", "start", "stop", "download", "upload", "reset", "reboot",
		"firmware", "setpoint", "set point", "command", "exec", "program", "logic", "actuat", "force ", "shutdown"):
		return "Command / control action"
	case has("discover", "enumerat", "identify", "list", "browse", "getnamelist", "read-device", "read device",
		"scan", "recon", "sweep", "fingerprint", "version", "probe"):
		return "Service discovery / enumeration"
	case has("assoc", "handshake", "connect", "register", "setup", "securechannel", "secure channel",
		"negoti", "hello", "kex", "session", "cr→cc", "cotp cr"):
		return "Session establishment"
	case ev.BannerSent != "" || ev.PayloadBase64 != "":
		return "Probe / banner grab"
	}
	return ""
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/events/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ev, err := s.store.Get(ctx, id)
	if err != nil || s.hides(ev.Source.IP) { // presentation hide list
		http.NotFound(w, r)
		return
	}
	// Recompute ATT&CK/D3FEND for events stored before the mitre columns
	// existed, so the detail page is consistent with the /attack view.
	if len(ev.MitreTechniques) == 0 {
		tag := mitre.Augment(mitre.Lookup(ev.RuleID, ev.Handler), metaStrings(ev.Meta, "anomalies"))
		ev.MitreTechniques = tag.Techniques
		ev.MitreTactics = tag.Tactics
		if len(ev.MitreDefenses) == 0 {
			ev.MitreDefenses = mitre.DefensesFor(tag.Techniques)
		}
	}
	page := newEventDetail(ev)
	if nav, nerr := s.store.ConversationNav(ctx, ev); nerr == nil {
		page.Nav = nav
	}
	if _, name, ok := s.resolveEventPcap(ev); ok {
		page.HasPcap, page.PcapName = true, name
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "event", page); err != nil {
		slog.Warn("ui: render event", "err", err)
	}
}

func (s *Server) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.query(ctx, f)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(evs)
}

// handleAPIHeartbeat returns a tiny freshness token (total event count + the
// latest event time) so the JS layer can skip refreshing a page when nothing
// has changed — the no-needless-refresh / no-flash path.
func (s *Server) handleAPIHeartbeat(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	count, latest, err := s.store.Heartbeat(ctx)
	if err != nil {
		http.Error(w, "heartbeat error", http.StatusInternalServerError)
		return
	}
	last := ""
	if !latest.IsZero() {
		last = latest.Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"count": count, "last": last})
}

func (s *Server) handleAPISummary(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sum, err := s.store.Summary(ctx, since)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}

// handleConfig renders the effective config: an at-a-glance "infrastructure
// canvas" (which ports/services are listening and which collectors are
// active) followed by the full YAML. Secrets are env-var names (never
// expanded values), so the output is safe to display.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	yamlStr := s.configYAML()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	linesOnly := r.URL.Query().Get("lines") == "only"
	body, matches := highlightYAML(yamlStr, q, linesOnly)
	page := configPage{
		YAML:       yamlStr,
		YAMLHTML:   body,
		Query:      q,
		MatchCount: matches,
		LinesOnly:  linesOnly,
		Canvas:     buildConfigCanvas(s.fullConfig),
		Files:      s.configFileRows(),
		Themes:     themePickerLinks(currentTheme(r), "/config"),
		Sizes:      sizePickerLinks(currentSize(r), "/config"),
		Deployment: s.deploymentInfo(),
		Uptime:     fmtDuration(time.Since(s.startTime)),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if t, err := s.store.OldestEventTime(ctx); err == nil && !t.IsZero() {
		page.OldestEvent = t.Format(time.RFC3339)
		page.RetentionSpan = fmtDuration(time.Since(t))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "config", page); err != nil {
		slog.Warn("ui: render config", "err", err)
	}
}

// deploymentInfo is the at-a-glance "this deployment" summary (moved here from
// the docs page): listener / honeynet / host counts + device tracking + bind.
func (s *Server) deploymentInfo() deploymentInfo {
	d := deploymentInfo{UIBind: s.cfg.Bind}
	if s.fullConfig != nil {
		c := s.fullConfig
		d.Listeners = len(c.Listeners)
		d.Networks = len(c.Honeynets)
		d.DevicesOn = c.Devices.Enabled

		// Identity / naming.
		d.Domain = c.Sensor.Domain
		if d.Domain == "" {
			d.Domain = "example.internal"
		}
		d.TLSDomain = c.Sensor.TLSDomain
		if d.TLSDomain == "" {
			d.TLSDomain = d.Domain
		}
		// Flag any divergence between the generated TLS cert identity and the
		// deployment domain the rest of the deception advertises.
		d.TLSWarnings = c.TLSCoherenceWarnings()
		seenDom := map[string]bool{}
		for _, hn := range c.Honeynets {
			if hn.Domain != "" && !seenDom[hn.Domain] {
				seenDom[hn.Domain] = true
				d.NetworkDomains = append(d.NetworkDomains, hn.Domain)
			}
		}

		// Modes.
		d.ReplyPolicy = c.Sensor.ReplyPolicy
		if d.ReplyPolicy == "" {
			d.ReplyPolicy = "full"
		}
		d.NoAmplifier = c.Sensor.NoAmplifierReplies
		if c.Sensor.DBReplyDelay > 0 {
			d.DBReplyDelay = c.Sensor.DBReplyDelay.String()
		}

		// Fake web.
		for _, l := range c.Listeners {
			if l.Webapp {
				d.WebappEnabled = true
				if n := strings.TrimSpace(l.WebappBrand.Name); n != "" && d.WebappName == "" {
					d.WebappName = n
				}
			}
		}
		d.SampleRetrieval = c.Sensor.WebSampleRetrieval || c.Sensor.Payloads.FetchURLs
	}
	if s.topo != nil {
		d.Hosts = len(s.topo.HostsInNetwork(""))
	}
	return d
}

// fmtDuration renders a coarse, human "2d 3h 12m" style duration for the
// uptime / retention-span displays.
func fmtDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	day := d / (24 * time.Hour)
	d -= day * 24 * time.Hour
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	switch {
	case day > 0:
		return fmt.Sprintf("%dd %dh %dm", day, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

type deploymentInfo struct {
	Listeners int
	Networks  int
	Hosts     int
	DevicesOn bool
	UIBind    string
	// Identity / naming.
	Domain         string   // deployment DNS domain used for service identities
	TLSDomain      string   // cert CN/SAN domain (falls back to Domain)
	NetworkDomains []string // per-honeynet-network DNS domains
	TLSWarnings    []string // TLS-cert ↔ domain coherence problems (empty = OK)
	// Modes.
	ReplyPolicy  string // full / non-ot / fingerprint / fingerprint-non-ot / mute
	NoAmplifier  bool   // amplifier-mode replies suppressed
	DBReplyDelay string // artificial DB answer delay ("" = none)
	// Fake web.
	WebappEnabled   bool
	WebappName      string
	SampleRetrieval bool
}

// handleAPIConfigCanvas returns the listener/collector board as JSON for
// tooling (drift checks, dashboards).
func (s *Server) handleAPIConfigCanvas(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buildConfigCanvas(s.fullConfig))
}

// handleAPIConfig returns the effective config as raw YAML for tooling
// (curl / config drift checks).
func (s *Server) handleAPIConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write([]byte(s.configYAML()))
}

// configYAML marshals the effective config to YAML, or returns a
// placeholder when no config was wired (e.g. UI started standalone).
func (s *Server) configYAML() string {
	if s.fullConfig == nil {
		return "# config not available\n"
	}
	b, err := yaml.Marshal(s.fullConfig)
	if err != nil {
		return "# config render error: " + err.Error() + "\n"
	}
	return string(b)
}

type configPage struct {
	YAML          string
	YAMLHTML      template.HTML // YAML with case-insensitive matches wrapped in <mark>
	Query         string        // the raw search query (echoed in the input)
	MatchCount    int           // number of substring matches across the whole YAML
	LinesOnly     bool          // true when ?lines=only filters out non-matching lines
	Canvas        configCanvas
	Files         []fileRow
	Themes        []themeLink
	Sizes         []sizeLink
	Deployment    deploymentInfo // "this deployment" block (moved from docs)
	Uptime        string         // sensor running time, e.g. "2d 3h 12m"
	OldestEvent   string         // RFC3339 timestamp of the earliest event in the DB
	RetentionSpan string         // how far back that is, e.g. "29d 4h"
}

// fileRow is one config/enrichment/database/state path the sensor uses,
// for the config page's "files in use" panel.
type fileRow struct {
	Category string `json:"category"`
	Key      string `json:"key"`
	Path     string `json:"path"`
	Access   string `json:"access"` // read | write
	Exists   bool   `json:"exists"`
}

// configFileRows builds the path-inventory rows for the config page + API,
// stat-ing each path for presence.
func (s *Server) configFileRows() []fileRow {
	if s.fullConfig == nil {
		return nil
	}
	var rows []fileRow
	for _, p := range s.fullConfig.Paths(s.configPaths...) {
		access := "read"
		if p.Writable {
			access = "write"
		}
		_, statErr := os.Stat(p.Path)
		rows = append(rows, fileRow{Category: p.Category, Key: p.Key, Path: p.Path, Access: access, Exists: statErr == nil})
	}
	return rows
}

// ---- topology tab ----

type topoServiceView struct {
	Port    int    `json:"port"`
	Handler string `json:"handler"`
	Banner  string `json:"banner,omitempty"`
}

type topoHostView struct {
	IP       string            `json:"ip"`
	Hostname string            `json:"hostname,omitempty"`
	OS       string            `json:"os,omitempty"`
	MAC      string            `json:"mac,omitempty"`
	Services []topoServiceView `json:"services,omitempty"`
	// Activity overlay (events targeting this host IP in the window).
	Events    int       `json:"events"`
	Attackers int       `json:"attackers"`
	MaxSev    string    `json:"max_severity,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

type topoNetworkView struct {
	ID        string         `json:"id"`
	CIDR      string         `json:"cidr,omitempty"`
	Gateway   string         `json:"gateway,omitempty"`
	DNS       string         `json:"dns,omitempty"`
	Domain    string         `json:"domain,omitempty"`
	Hosts     []topoHostView `json:"hosts"`
	Events    int            `json:"events"`
	Attackers int            `json:"attackers"`
}

// topologyView builds a serializable snapshot of the honeynet topology.
// It deliberately copies only the safe-to-display fields (no per-host
// Identity / archetype internals) so the same view feeds the HTML page
// and the JSON API.
func (s *Server) topologyView() []topoNetworkView {
	if s.topo == nil || s.topo.Empty() {
		return nil
	}
	var out []topoNetworkView
	for _, n := range s.topo.Networks() {
		nv := topoNetworkView{ID: n.ID, CIDR: n.CIDR, Gateway: n.Gateway, DNS: n.DNS, Domain: n.Domain}
		for _, h := range n.Hosts {
			hv := topoHostView{IP: h.IP, Hostname: h.Hostname, OS: h.OS, MAC: h.MACString()}
			for _, sv := range h.Services {
				hv.Services = append(hv.Services, topoServiceView{Port: sv.Port, Handler: sv.Handler, Banner: sv.Banner})
			}
			nv.Hosts = append(nv.Hosts, hv)
		}
		out = append(out, nv)
	}
	return out
}

type topologyPage struct {
	Networks []topoNetworkView
	Active   bool // any activity overlaid?
	Graph    chartFig
}

// hostActivity aggregates events targeting each honeynet host IP (by dest IP)
// over the window: event count, distinct attacker count, max severity, and
// last-seen — the infrastructure-map activity overlay.
type hostActivity struct {
	Events    int
	MaxSev    string
	LastSeen  time.Time
	attackers map[string]bool
}

func aggregateHostActivity(evs []*event.Event) map[string]*hostActivity {
	m := map[string]*hostActivity{}
	for _, ev := range evs {
		ip := ev.Dest.IP
		if ip == "" {
			continue
		}
		a := m[ip]
		if a == nil {
			a = &hostActivity{attackers: map[string]bool{}}
			m[ip] = a
		}
		a.Events++
		if ev.Source.IP != "" {
			a.attackers[ev.Source.IP] = true
		}
		if sevRank(ev.Severity.String()) > sevRank(a.MaxSev) {
			a.MaxSev = ev.Severity.String()
		}
		if ev.Time.After(a.LastSeen) {
			a.LastSeen = ev.Time
		}
	}
	return m
}

// overlayActivity stamps per-host activity onto the topology view and reports
// whether any host saw traffic.
func overlayActivity(nets []topoNetworkView, act map[string]*hostActivity) bool {
	any := false
	for i := range nets {
		netEvents, netAtk := 0, map[string]bool{}
		for j := range nets[i].Hosts {
			h := &nets[i].Hosts[j]
			a := act[h.IP]
			if a == nil {
				continue
			}
			any = true
			h.Events = a.Events
			h.Attackers = len(a.attackers)
			h.MaxSev = a.MaxSev
			h.LastSeen = a.LastSeen
			netEvents += a.Events
			for atk := range a.attackers {
				netAtk[atk] = true
			}
		}
		nets[i].Events = netEvents
		nets[i].Attackers = len(netAtk)
	}
	return any
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	nets := s.topologyView()
	page := topologyPage{Networks: nets}
	if len(nets) > 0 {
		page.Graph = buildTopologyGraph(nets)
	}
	// Infrastructure-map activity overlay: events targeting each host IP.
	if len(nets) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		if evs, err := s.query(ctx, store.Filter{Since: time.Now().Add(-24 * time.Hour), Limit: 20000, NoPayload: true}); err == nil {
			page.Active = overlayActivity(nets, aggregateHostActivity(evs))
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "topology", page); err != nil {
		slog.Warn("ui: render topology", "err", err)
	}
}

func (s *Server) handleAPITopology(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.topologyView())
}

// ---- hosts tab ----

func (s *Server) hostsView() []HostView {
	if s.hosts == nil {
		return nil
	}
	return s.hosts()
}

func (s *Server) hostsSummaryView() *HostsSummary {
	if s.hostsSummary == nil {
		return nil
	}
	v := s.hostsSummary()
	return &v
}

type hostsPage struct {
	Hosts          []HostView
	Summary        *HostsSummary // aggregate panel (nil when no provider)
	Enabled        bool
	Query          string // substring filter (ip/mac/hostname/vendor/source)
	Status         string // "" | "seen" | "allow"
	ActionsEnabled bool   // device delete/whitelist available
	Token          string // embedded in action forms when ActionsEnabled
	Notice         string // result of the last action
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	status := r.URL.Query().Get("status")
	hosts := filterHosts(s.hostsView(), q, status)
	p := hostsPage{
		Hosts:          hosts,
		Summary:        s.hostsSummaryView(),
		Enabled:        s.fullConfig != nil && s.fullConfig.Devices.Enabled,
		Query:          r.URL.Query().Get("q"),
		Status:         status,
		ActionsEnabled: s.deviceActionsEnabled(),
		Notice:         r.URL.Query().Get("notice"),
	}
	if p.ActionsEnabled {
		p.Token = s.authToken
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "devices", p); err != nil {
		slog.Warn("ui: render devices", "err", err)
	}
}

// filterHosts applies a case-insensitive substring filter over the host
// fields plus an allow/seen status filter.
func filterHosts(in []HostView, q, status string) []HostView {
	if q == "" && status == "" {
		return in
	}
	out := make([]HostView, 0, len(in))
	for _, h := range in {
		if status == "allow" && !h.Allowed {
			continue
		}
		if status == "seen" && h.Allowed {
			continue
		}
		if q != "" {
			hay := strings.ToLower(h.IP + " " + h.MAC + " " + h.Hostname + " " + h.Vendor + " " + h.Source + " " + strings.Join(h.Services, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

func (s *Server) handleAPIHosts(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.hostsView())
}

func (s *Server) handleAPIHostsSummary(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sum := s.hostsSummaryView()
	if sum == nil {
		sum = &HostsSummary{}
	}
	_ = json.NewEncoder(w).Encode(sum)
}

// handleDeviceAction performs a device delete / whitelist. It is opt-in
// (cfg.AllowDeviceActions) and always requires the auth token — supplied as
// a form field so a browser form works (the page that renders the form was
// itself served only to a token-bearing request). POST only.
func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	if !s.deviceActionsEnabled() {
		http.Error(w, "device actions disabled", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	tok := r.FormValue("token")
	if r.Header.Get("Authorization") != "" {
		tok = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.authToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	action := r.FormValue("action")
	key := r.FormValue("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	notice := ""
	switch action {
	case "delete":
		if s.deviceActions.Delete(key) {
			notice = "deleted " + key
		} else {
			notice = "not found: " + key
		}
	case "allow":
		if s.deviceActions.Allow(key) {
			notice = "whitelisted " + key
		} else {
			notice = "not found: " + key
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	slog.Info("ui: device action", "action", action, "key", key)
	http.Redirect(w, r, "/devices?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}

// ---- alerting / forwarding tab ----

// channelView summarizes one outbound/local channel for the alerting tab.
type channelView struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Format      string `json:"format,omitempty"`
	Destination string `json:"destination,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	RateLimit   int    `json:"rate_limit_per_min,omitempty"`
	Local       bool   `json:"local"`
}

type routeView struct {
	Match    string   `json:"match"`
	Channels []string `json:"channels"`
}

type alertingPage struct {
	Channels []channelView
	Routes   []routeView
	// Quick "is X configured?" booleans for the summary banner.
	HasSyslog  bool
	HasEmail   bool
	HasWebhook bool
	HasSMS     bool
	HasSNMP    bool
	Allowlist  []string
}

func (s *Server) alertingView() alertingPage {
	var p alertingPage
	if s.fullConfig == nil {
		return p
	}
	for _, c := range s.fullConfig.Channels {
		cv := channelView{
			ID: c.ID, Type: c.Type, Format: c.Format,
			MinSeverity: c.MinSeverity, RateLimit: c.RateLimitPerMin,
			Destination: channelDestination(c),
			Local:       c.Type == "stdout" || c.Type == "jsonlog" || c.Type == "sqlite",
		}
		p.Channels = append(p.Channels, cv)
		switch c.Type {
		case "syslog":
			p.HasSyslog = true
		case "smtp":
			p.HasEmail = true
		case "webhook":
			p.HasWebhook = true
		case "twilio":
			p.HasSMS = true
		case "snmptrap":
			p.HasSNMP = true
		}
	}
	for _, r := range s.fullConfig.Routes {
		p.Routes = append(p.Routes, routeView{Match: matchSummary(r.Match), Channels: r.Channels})
	}
	p.Allowlist = s.fullConfig.Allowlist
	return p
}

// channelDestination renders where a channel forwards to, with secrets
// kept as their env-var names (the config model never stores values).
func channelDestination(c config.Channel) string {
	switch c.Type {
	case "webhook":
		return c.URL
	case "smtp":
		return fmt.Sprintf("%s:%d (from %s, to %s)", c.Host, c.Port, c.From, strings.Join(c.To, ","))
	case "syslog":
		return c.Network + " " + c.Address
	case "twilio":
		return "Twilio SMS -> " + strings.Join(c.To, ",")
	case "sns":
		return c.TopicARN
	case "snmptrap":
		return fmt.Sprintf("%s:%d", c.Host, c.Port)
	case "jsonlog":
		return "<data_dir>/events/"
	case "sqlite":
		return "<data_dir>/events.db"
	case "stdout":
		return "stdout"
	}
	return ""
}

func matchSummary(m config.Match) string {
	var parts []string
	if m.Severity != "" {
		parts = append(parts, "severity "+m.Severity)
	}
	if m.Honeynet != "" {
		parts = append(parts, "honeynet="+m.Honeynet)
	}
	if m.HoneynetOS != "" {
		parts = append(parts, "os="+m.HoneynetOS)
	}
	if m.RuleID != "" {
		parts = append(parts, "rule="+m.RuleID)
	}
	if len(parts) == 0 {
		return "(all events)"
	}
	return strings.Join(parts, " AND ")
}

func (s *Server) handleAlerting(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "alerting", s.alertingView()); err != nil {
		slog.Warn("ui: render alerting", "err", err)
	}
}

func (s *Server) handleAPIAlerting(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.alertingView())
}

// maxEventsLimit is the safety cap on how many rows the /events listing will
// return, including when the operator asks for "all". High enough that "All"
// means "everything in practice" without letting a single request scan unbounded.
const maxEventsLimit = 50000

// splitFilterTokens parses a filter-field value into include + exclude lists:
// it comma-separates values and treats a leading '!' as negation (exclude).
// Blank tokens are skipped. "a,b" includes a or b; "!a" excludes a; "a,!b"
// includes a but excludes b.
func splitFilterTokens(v string) (incl, excl []string) {
	for _, tok := range strings.Split(v, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || tok == "!" {
			continue
		}
		if strings.HasPrefix(tok, "!") {
			excl = append(excl, strings.TrimSpace(tok[1:]))
		} else {
			incl = append(incl, tok)
		}
	}
	return incl, excl
}

// parseASN extracts a numeric AS number from a token like "AS13335", "as13335"
// or "13335"; returns 0 when it isn't a positive integer.
func parseASN(v string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v)), "AS"))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func parseASNs(in []string) []int {
	var out []int
	for _, v := range in {
		if n := parseASN(v); n > 0 {
			out = append(out, n)
		}
	}
	return out
}

func parsePorts(in []string) []int {
	var out []int
	for _, v := range in {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}

func parseFilter(r *http.Request) store.Filter {
	q := r.URL.Query()
	f := store.Filter{Limit: 100}
	// Absolute window (from a clicked trend bar): from/to as RFC3339. These
	// take precedence over the relative `since` default.
	abs := false
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
			abs = true
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = t
		}
	}
	if !abs {
		switch {
		case q.Get("since") != "":
			if d, err := time.ParseDuration(q.Get("since")); err == nil {
				f.Since = time.Now().Add(-d)
			}
		case q.Get("range") != "":
			// A pivot from the summary carries its selected window so the
			// listing covers the same span the operator was looking at.
			f.Since = time.Now().Add(-summaryRange(q.Get("range")).dur)
		default:
			f.Since = time.Now().Add(-24 * time.Hour)
		}
	}
	// String dimensions accept comma-separated values and a leading '!' to
	// negate (exclude). A single positive value keeps the fast single-column
	// path (and round-trips the existing pivot links / artifact-download
	// filenames); anything else populates the multi / exclude lists the store
	// turns into IN / NOT IN clauses.
	if v := q.Get("source"); v != "" {
		incl, excl := splitFilterTokens(v)
		if len(excl) == 0 && len(incl) <= 1 {
			if len(incl) == 1 {
				f.SourceIP = incl[0]
			}
		} else {
			f.SourceIPs, f.ExcludeSourceIPs = incl, excl
		}
	}
	if v := q.Get("rule"); v != "" {
		incl, excl := splitFilterTokens(v)
		if len(excl) == 0 && len(incl) <= 1 {
			if len(incl) == 1 {
				f.RuleID = incl[0]
			}
		} else {
			f.RuleIDs, f.ExcludeRuleIDs = incl, excl
		}
	}
	if v := q.Get("proto"); v != "" {
		incl, excl := splitFilterTokens(v)
		if len(excl) == 0 && len(incl) <= 1 {
			if len(incl) == 1 {
				f.Proto = incl[0]
			}
		} else {
			f.Protos, f.ExcludeProtos = incl, excl
		}
	}
	if v := q.Get("handler"); v != "" {
		incl, excl := splitFilterTokens(v)
		if len(excl) == 0 && len(incl) <= 1 {
			if len(incl) == 1 {
				f.Handler = incl[0]
			}
		} else {
			f.Handlers, f.ExcludeHandlers = append(f.Handlers, incl...), excl
		}
	}
	if v := q.Get("port"); v != "" {
		incl, excl := splitFilterTokens(v)
		iincl, iexcl := parsePorts(incl), parsePorts(excl)
		if len(iexcl) == 0 && len(iincl) <= 1 {
			if len(iincl) == 1 {
				f.DstPort = iincl[0]
			}
		} else {
			f.DstPorts, f.ExcludeDstPorts = iincl, iexcl
		}
	}
	if v := q.Get("country"); v != "" {
		incl, excl := splitFilterTokens(v)
		if len(excl) == 0 && len(incl) <= 1 {
			if len(incl) == 1 {
				f.Country = incl[0]
			}
		} else {
			f.Countries, f.ExcludeCountries = incl, excl
		}
	}
	if v := q.Get("asn"); v != "" {
		incl, excl := splitFilterTokens(v)
		iincl, iexcl := parseASNs(incl), parseASNs(excl)
		if len(iexcl) == 0 && len(iincl) <= 1 {
			if len(iincl) == 1 {
				f.ASN = iincl[0]
			}
		} else {
			f.ASNs, f.ExcludeASNs = iincl, iexcl
		}
	}
	// Free-text GeoIP / network dimensions (comma-separated, '!'-negation): the
	// city / country-name / network-org pivots off the charts + stats tables.
	if v := q.Get("geo_city"); v != "" {
		f.Cities, f.ExcludeCities = splitFilterTokens(v)
	}
	if v := q.Get("geo_country_name"); v != "" {
		f.CountryNames, f.ExcludeCountryNames = splitFilterTokens(v)
	}
	if v := q.Get("asn_org"); v != "" {
		f.ASNOrgs, f.ExcludeASNOrgs = splitFilterTokens(v)
	}
	if v := q.Get("q"); v != "" {
		f.Text = v
	}
	if v := q.Get("severity"); v != "" {
		if sev, err := event.ParseSeverity(v); err == nil {
			f.MinSeverity = sev
		}
	}
	if v := q.Get("limit"); v != "" {
		// "all" / "0" lifts the cap to the safety maximum; otherwise a positive
		// number bounded by that maximum. (The client "Rows" control drives this
		// param for server-backed tables, so "All" really fetches everything.)
		if v == "all" || v == "0" {
			f.Limit = maxEventsLimit
		} else if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxEventsLimit {
				n = maxEventsLimit
			}
			f.Limit = n
		}
	}
	return f
}
