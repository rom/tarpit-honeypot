// Package ui exposes a read-only HTTP UI backed by the SQLite event store.
//
// Default bind is loopback. The validator (config.Validate) refuses to start
// on a non-loopback bind without both TLS and a static auth token. There is
// no write endpoint — the UI cannot delete events, change config, or trigger
// alerts. That stays a hard rule: the sensor host is a target.
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
	"os"
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
	cfg        config.UI
	store      *store.Store
	authToken  string
	srv        *http.Server
	tmpl       *template.Template
	stats      StatsProvider
	fullConfig *config.Config
	topo       *honeynet.Topology
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

func New(cfg config.UI, st *store.Store) (*Server, error) {
	if !cfg.Enabled {
		return nil, errors.New("ui: not enabled")
	}
	if st == nil {
		return nil, errors.New("ui: store is required")
	}
	s := &Server{cfg: cfg, store: st}
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
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/topology", s.handleTopology)
	mux.HandleFunc("/docs", s.handleDocs)
	mux.HandleFunc("/api/events", s.handleAPIEvents)
	mux.HandleFunc("/api/summary", s.handleAPISummary)
	mux.HandleFunc("/api/config", s.handleAPIConfig)
	mux.HandleFunc("/api/topology", s.handleAPITopology)
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

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sum, err := s.store.Summary(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index", sum); err != nil {
		slog.Warn("ui: render index", "err", err)
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	evs, err := s.store.Query(ctx, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Events []*event.Event
		Filter store.Filter
	}{evs, f}
	if err := s.tmpl.ExecuteTemplate(w, "events", data); err != nil {
		slog.Warn("ui: render events", "err", err)
	}
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
