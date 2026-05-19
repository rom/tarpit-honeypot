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

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

type Server struct {
	cfg       config.UI
	store     *store.Store
	authToken string
	srv       *http.Server
	tmpl      *template.Template
}

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
		"join":    func(s []int) string { var p []string; for _, n := range s { p = append(p, strconv.Itoa(n)) }; return strings.Join(p, ", ") },
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
	mux.HandleFunc("/api/events", s.handleAPIEvents)
	mux.HandleFunc("/api/summary", s.handleAPISummary)
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
