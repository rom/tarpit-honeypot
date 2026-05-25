// Package ingest is the aggregator-side HTTP endpoint that accepts batches of
// events forwarded by child nodes (see internal/forward). It authenticates the
// caller (bearer token, optional HMAC over the body), decodes the NDJSON batch,
// and hands the events to a sink callback (the sensor's IngestBatch, which
// dedups, loop-guards, and feeds the pipeline). The wire format + signature
// verification are the forward package's, so encode and decode stay in lockstep.
package ingest

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/forward"
)

// SinkFunc admits a decoded batch and returns per-batch counts.
type SinkFunc func(evs []*event.Event) (accepted, deduped, dropped int)

// Config parameterises the endpoint.
type Config struct {
	Token      string // required bearer token
	HMACSecret []byte // optional body-signature verification
	MaxBody    int64  // reject larger batches (bytes)
	// Intel, when set, is mounted at GET /intel — the downward fleet-intel feed
	// (see internal/intel). It does its own bearer auth.
	Intel http.Handler
	// Routes are extra (pattern -> handler) mounts — the STIX/TAXII IOC export
	// (see internal/stix). Each handler does its own bearer auth.
	Routes map[string]http.Handler
}

// Handler serves POST /ingest (and GET /healthz).
type Handler struct {
	cfg  Config
	sink SinkFunc
}

// New builds the handler.
func New(cfg Config, sink SinkFunc) *Handler {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 32 << 20
	}
	return &Handler{cfg: cfg, sink: sink}
}

// Mux returns the routed handler (POST /ingest, GET /healthz).
func (h *Handler) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", h.handleIngest)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	if h.cfg.Intel != nil {
		mux.Handle("/intel", h.cfg.Intel)
	}
	for pattern, handler := range h.cfg.Routes {
		mux.Handle(pattern, handler)
	}
	return mux
}

type ingestResult struct {
	Accepted int `json:"accepted"`
	Deduped  int `json:"deduped"`
	Dropped  int `json:"dropped"`
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > h.cfg.MaxBody {
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(h.cfg.HMACSecret) > 0 && !forward.VerifySignature(h.cfg.HMACSecret, body, r.Header.Get("X-Tarpit-Signature")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	evs, err := forward.DecodeBatch(strings.NewReader(string(body)))
	if err != nil && len(evs) == 0 {
		http.Error(w, "bad batch", http.StatusBadRequest)
		return
	}
	acc, dup, drop := h.sink(evs)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ingestResult{Accepted: acc, Deduped: dup, Dropped: drop})
}

// authOK checks the bearer token in constant time.
func (h *Handler) authOK(r *http.Request) bool {
	if h.cfg.Token == "" {
		return false // an endpoint with no token must refuse everything
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(h.cfg.Token)) == 1
}
