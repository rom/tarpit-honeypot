// Package misp pushes the fleet's observed indicators (see internal/intel) to a
// MISP instance via its REST API. It pushes deltas — only indicators it hasn't
// sent before — as a single MISP event per interval, so a TIP operator gets the
// fleet's IOCs without duplicate events. Outbound through the egress allowlist.
package misp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/intel"
)

// Config parameterises the pusher.
type Config struct {
	URL          string        // MISP base URL, e.g. https://misp.corp
	Key          string        // MISP auth key (resolved from env by the caller)
	Interval     time.Duration // push period (default 5m)
	EventInfo    string        // MISP event title (default "tarpit-honeypot fleet IOCs")
	Distribution string        // MISP distribution level (default "0" = your org only)
	ThreatLevel  string        // threat_level_id (default "2" = medium)
	Client       *http.Client  // egress-allowlisted client
}

// Pusher ships IOC deltas to MISP.
type Pusher struct {
	cfg    Config
	src    func() []intel.IOC
	pushed map[string]struct{}
}

// NewPusher builds a pusher. src returns the current IOC set each tick.
func NewPusher(cfg Config, src func() []intel.IOC) *Pusher {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.EventInfo == "" {
		cfg.EventInfo = "tarpit-honeypot fleet IOCs"
	}
	if cfg.Distribution == "" {
		cfg.Distribution = "0"
	}
	if cfg.ThreatLevel == "" {
		cfg.ThreatLevel = "2"
	}
	return &Pusher{cfg: cfg, src: src, pushed: map[string]struct{}{}}
}

// Run pushes deltas until ctx is done.
func (p *Pusher) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.once(ctx)
		}
	}
}

func (p *Pusher) once(ctx context.Context) {
	var attrs []map[string]any
	var keys []string
	for _, ioc := range p.src() {
		key := ioc.Kind + "|" + ioc.Value
		if _, seen := p.pushed[key]; seen {
			continue
		}
		a, ok := attribute(ioc)
		if !ok {
			continue
		}
		attrs = append(attrs, a)
		keys = append(keys, key)
		p.pushed[key] = struct{}{}
	}
	if len(attrs) == 0 {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"Event": map[string]any{
			"info":            fmt.Sprintf("%s (%s)", p.cfg.EventInfo, time.Now().UTC().Format("2006-01-02")),
			"distribution":    p.cfg.Distribution,
			"threat_level_id": p.cfg.ThreatLevel,
			"analysis":        "1",
			"Attribute":       attrs,
		},
	})
	if err := p.post(ctx, body); err != nil {
		slog.Warn("misp: push failed", "url", p.cfg.URL, "attrs", len(attrs), "err", err)
		// Roll back the seen marks so the next tick retries these indicators.
		for _, k := range keys {
			delete(p.pushed, k)
		}
		return
	}
	slog.Info("misp: pushed IOC delta", "attributes", len(attrs))
}

func (p *Pusher) post(ctx context.Context, body []byte) error {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, strings.TrimRight(p.cfg.URL, "/")+"/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", p.cfg.Key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// attribute maps a fleet IOC to a MISP attribute object.
func attribute(ioc intel.IOC) (map[string]any, bool) {
	a := map[string]any{"category": "Network activity", "to_ids": true, "comment": "fleet:" + ioc.Reason}
	switch ioc.Kind {
	case "ip":
		a["type"] = "ip-src"
		a["value"] = ioc.Value
	case "asn":
		a["type"] = "AS"
		a["value"] = ioc.Value
	case "fingerprint":
		kind, val, ok := strings.Cut(ioc.Value, ":")
		if !ok {
			return nil, false
		}
		switch kind {
		case "ja3":
			a["type"] = "ja3-fingerprint-md5"
		case "hassh":
			a["type"] = "hassh-md5"
		default:
			a["type"] = "other"
			val = ioc.Value
		}
		a["value"] = val
	default:
		return nil, false
	}
	return a, true
}
