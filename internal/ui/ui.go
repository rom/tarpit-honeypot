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
	"github.com/rom/tarpit-honeypot/internal/store"
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
	deviceActions DeviceActions
	dataDir       string
}

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
	s := &Server{cfg: cfg, store: st, refresh: cfg.UIRefreshInterval()}
	if cfg.AuthTokenEnv != "" {
		s.authToken = os.Getenv(cfg.AuthTokenEnv)
		if s.authToken == "" {
			return nil, fmt.Errorf("ui: env %s is empty", cfg.AuthTokenEnv)
		}
	}
	t, err := template.New("").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"join": func(s []int) string {
			var p []string
			for _, n := range s {
				p = append(p, strconv.Itoa(n))
			}
			return strings.Join(p, ", ")
		},
		"hexdump":        hexDump,
		"refreshSeconds": func() int { return s.refresh },
	}).Parse(tmpls)
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	return s, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/events/", s.handleEvent)
	mux.HandleFunc("/profiles", s.handleProfiles)
	mux.HandleFunc("/profiles/", s.handleProfile)
	mux.HandleFunc("/pcap/", s.handlePcap)
	mux.HandleFunc("/session/", s.handleSession)
	mux.HandleFunc("/download", s.handleDownload)
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/topology", s.handleTopology)
	mux.HandleFunc("/hosts", s.handleHosts)
	mux.HandleFunc("/devices", s.handleHosts)
	mux.HandleFunc("/devices/action", s.handleDeviceAction)
	mux.HandleFunc("/alerting", s.handleAlerting)
	mux.HandleFunc("/errors", s.handleErrors)
	mux.HandleFunc("/docs", s.handleDocs)
	mux.HandleFunc("/api/events", s.handleAPIEvents)
	mux.HandleFunc("/api/profiles", s.handleAPIProfiles)
	mux.HandleFunc("/api/profiles/", s.handleAPIProfile)
	mux.HandleFunc("/api/summary", s.handleAPISummary)
	mux.HandleFunc("/api/config", s.handleAPIConfig)
	mux.HandleFunc("/api/topology", s.handleAPITopology)
	mux.HandleFunc("/api/hosts", s.handleAPIHosts)
	mux.HandleFunc("/api/devices", s.handleAPIHosts)
	mux.HandleFunc("/api/alerting", s.handleAPIAlerting)
	mux.HandleFunc("/metrics", s.handleMetrics)
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
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")

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
	slog.Warn("ui: request failed", "path", where, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	since := time.Now().Add(-24 * time.Hour)
	sum, err := s.store.Summary(ctx, since)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	hours, err := s.store.EventsPerHour(ctx, since)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index", buildDashboard(sum, hours)); err != nil {
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
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.store.Query(ctx, f)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
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
	for _, k := range []string{"source", "rule", "since", "limit", "severity", "q"} {
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
	evs, err := s.store.Query(ctx, store.Filter{Since: time.Now().Add(-since), Limit: 1000})
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
	if err != nil {
		http.NotFound(w, r)
		return
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
	evs, err := s.store.Query(ctx, f)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(evs)
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

// handleConfig renders the effective config as YAML in a read-only
// page. Secrets are env-var names (never expanded values), so the
// output is safe to display.
func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	yamlStr := s.configYAML()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "config", configPage{YAML: yamlStr}); err != nil {
		slog.Warn("ui: render config", "err", err)
	}
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
	YAML string
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
}

type topoNetworkView struct {
	ID      string         `json:"id"`
	CIDR    string         `json:"cidr,omitempty"`
	Gateway string         `json:"gateway,omitempty"`
	DNS     string         `json:"dns,omitempty"`
	Domain  string         `json:"domain,omitempty"`
	Hosts   []topoHostView `json:"hosts"`
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
}

func (s *Server) handleTopology(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "topology", topologyPage{Networks: s.topologyView()}); err != nil {
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

type hostsPage struct {
	Hosts          []HostView
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

// ---- docs tab ----

// docsPage carries the static reference plus a small "this deployment"
// section so the docs reflect the running sensor.
type docsPage struct {
	Listeners int
	Networks  int
	Hosts     int
	DevicesOn bool
	UIBind    string
}

func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	p := docsPage{UIBind: s.cfg.Bind}
	if s.fullConfig != nil {
		p.Listeners = len(s.fullConfig.Listeners)
		p.Networks = len(s.fullConfig.Honeynets)
		p.DevicesOn = s.fullConfig.Devices.Enabled
	}
	if s.topo != nil {
		p.Hosts = len(s.topo.HostsInNetwork(""))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "docs", p); err != nil {
		slog.Warn("ui: render docs", "err", err)
	}
}

func parseFilter(r *http.Request) store.Filter {
	q := r.URL.Query()
	f := store.Filter{Limit: 100}
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			f.Since = time.Now().Add(-d)
		}
	} else {
		f.Since = time.Now().Add(-24 * time.Hour)
	}
	if v := q.Get("source"); v != "" {
		f.SourceIP = v
	}
	if v := q.Get("rule"); v != "" {
		f.RuleID = v
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
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			f.Limit = n
		}
	}
	return f
}
