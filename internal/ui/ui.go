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
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
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
	store         *store.Store
	refresh       int // auto-refresh seconds for live views (0 = off)
	authToken     string
	srv           *http.Server
	tmpl          *template.Template
	stats         StatsProvider
	fullConfig    *config.Config
	topo          *honeynet.Topology
	hosts         HostsProvider
	hostsSummary  HostsSummaryProvider
	deviceActions DeviceActions
	dataDir       string
	configPaths   []string   // config file path(s), for the /config "files in use" panel
	hidden        *ipMatcher // presentation-layer source-IP hide list (ui.hidden_ips)
	startTime     time.Time  // process start, for the config page uptime
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

func New(cfg config.UI, st *store.Store) (*Server, error) {
	if !cfg.Enabled {
		return nil, errors.New("ui: not enabled")
	}
	if st == nil {
		return nil, errors.New("ui: store is required")
	}
	s := &Server{cfg: cfg, store: st, refresh: cfg.UIRefreshInterval(), hidden: newIPMatcher(cfg.HiddenIPs), startTime: time.Now()}
	if cfg.AuthTokenEnv != "" {
		s.authToken = os.Getenv(cfg.AuthTokenEnv)
		if s.authToken == "" {
			return nil, fmt.Errorf("ui: env %s is empty", cfg.AuthTokenEnv)
		}
	}
	t, err := template.New("").Funcs(tmplFuncs(func() int { return s.refresh }, s.cfg.CVESource, s.cfg.MapTilesURL, s.cfg.AttackLinksEnabled())).Parse(tmpls)
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	return s, nil
}

// tmplFuncs is the single source of truth for the template function map, used by
// New and by the package tests so they can never drift. refresh supplies the
// auto-refresh interval.
func tmplFuncs(refresh func() int, cveSource, mapTiles string, attackLinks bool) template.FuncMap {
	return template.FuncMap{
		"mapTiles": func() string { return mapTiles },
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

func metaScalar(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if httpDetailKeys[k] {
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
	mux.HandleFunc("/fingerprints", s.handleFingerprints)
	mux.HandleFunc("/fingerprints/", s.handleFingerprint)
	mux.HandleFunc("/pcap/", s.handlePcap)
	mux.HandleFunc("/session/", s.handleSession)
	mux.HandleFunc("/download", s.handleDownload)
	mux.HandleFunc("/captures", s.handleCaptures)
	mux.HandleFunc("/loot/", s.handleLoot)
	mux.HandleFunc("/replay", s.handleReplay)
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/attack", s.handleAttack)
	mux.HandleFunc("/attack/technique", s.handleAttackTechnique)
	mux.HandleFunc("/timeline", s.handleTimeline)
	mux.HandleFunc("/correlation", s.handleCorrelation)
	mux.HandleFunc("/campaign", s.handleCampaign)
	mux.HandleFunc("/map", s.handleThreatMap)
	mux.HandleFunc("/fleet", s.handleFleet)
	mux.HandleFunc("/iocs", s.handleIOCs)
	mux.HandleFunc("/tunnels", s.handleTunnels)
	mux.HandleFunc("/search", s.handleSearch)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/charts", s.handleCharts)
	mux.HandleFunc("/topology", s.handleTopology)
	mux.HandleFunc("/hosts", s.handleHosts)
	mux.HandleFunc("/devices", s.handleHosts)
	mux.HandleFunc("/devices/action", s.handleDeviceAction)
	mux.HandleFunc("/alerting", s.handleAlerting)
	mux.HandleFunc("/errors", s.handleErrors)
	mux.HandleFunc("/docs", s.handleDocs)
	mux.HandleFunc("/docs/", s.handleDoc)
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

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	win := summaryRange(r.URL.Query().Get("range"))
	since := time.Now().Add(-win.dur)
	sum, err := s.store.Summary(ctx, since)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	sum.TopSources = s.visibleSourceCounts(sum.TopSources) // presentation hide list
	hours, err := s.store.EventsPerBucket(ctx, since, win.bucket)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
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
	// from a bounded scan of the window.
	if evs, qerr := s.query(ctx, store.Filter{Since: since, Limit: 20000}); qerr == nil {
		enrichDashboard(&d, evs)
	}
	// Carry the active window into every /events pivot link so the listing
	// covers the same span the summary aggregated over (otherwise /events
	// defaults to 24h and a pivot off a longer window looks empty).
	scopeEventLinks(&d, win.key)
	// A compact visual overview (charts.js); the full gallery lives at /charts.
	if len(d.Severity) > 0 {
		d.Charts = append(d.Charts, chartFigure("pie", "Severity", barsToPie(d.Severity, true)))
	}
	if len(hours) > 0 {
		d.Charts = append(d.Charts, trendLine(hours))
	}
	if len(d.Sources) > 0 {
		d.Charts = append(d.Charts, chartFigure("hbar", "Top sources", barsToBar(d.Sources)))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index", d); err != nil {
		slog.Warn("ui: render index", "err", err)
	}
}

type colHeader struct {
	Label string
	Href  string
	Arrow string // ▲ / ▼ when this column is the active sort key
}

type eventsPage struct {
	Events      []*event.Event
	Filter      store.Filter
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
	displayLimit := f.Limit
	if tool != "" || tactic != "" || flag != "" || scanner != "" {
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
	if displayLimit > 0 && len(evs) > displayLimit {
		evs = evs[:displayLimit]
	}
	sortEvents(evs, sortKey, order)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := eventsPage{
		Events:      evs,
		Filter:      f,
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "event", ev); err != nil {
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
		d.Listeners = len(s.fullConfig.Listeners)
		d.Networks = len(s.fullConfig.Honeynets)
		d.DevicesOn = s.fullConfig.Devices.Enabled
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
		if evs, err := s.query(ctx, store.Filter{Since: time.Now().Add(-24 * time.Hour), Limit: 20000}); err == nil {
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
	if v := q.Get("source"); v != "" {
		f.SourceIP = v
	}
	if v := q.Get("rule"); v != "" {
		f.RuleID = v
	}
	if v := q.Get("proto"); v != "" {
		f.Proto = v
	}
	if v := q.Get("handler"); v != "" {
		f.Handler = v
	}
	if v := q.Get("port"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			f.DstPort = n
		}
	}
	if v := q.Get("country"); v != "" {
		f.Country = v
	}
	if v := q.Get("asn"); v != "" {
		if n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(v), "AS")); err == nil && n > 0 {
			f.ASN = n
		}
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
