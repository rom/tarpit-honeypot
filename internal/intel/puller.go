package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Puller subscribes a node to an aggregator's fleet-intel feed: it GETs the
// feed on an interval and hands each snapshot to apply (which the sensor wires
// to its enricher's SetFleetIntel). The HTTP client is the egress-allowlisted
// one, so the feed URL is, by construction, an allowlisted destination.
type Puller struct {
	url      string
	token    string
	interval time.Duration
	client   *http.Client
	apply    func(*Feed)
}

// NewPuller builds a feed subscriber. interval defaults to 60s.
func NewPuller(url, token string, interval time.Duration, client *http.Client, apply func(*Feed)) *Puller {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &Puller{url: url, token: token, interval: interval, client: client, apply: apply}
}

// Run polls the feed until ctx is done, fetching once immediately so a fresh
// node gets fleet intel without waiting a full interval.
func (p *Puller) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.once(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.once(ctx)
		}
	}
}

func (p *Puller) once(ctx context.Context) {
	feed, err := p.fetch(ctx)
	if err != nil {
		slog.Warn("intel: feed fetch failed", "url", p.url, "err", err)
		return
	}
	p.apply(feed)
	slog.Debug("intel: feed applied", "ips", len(feed.IPs), "asns", len(feed.ASNs), "fingerprints", len(feed.Fingerprints))
}

func (p *Puller) fetch(ctx context.Context) (*Feed, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tarpit-honeypot-intel")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var f Feed
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// Maps converts the feed into the value->reason maps the enricher overlay
// consumes (fingerprints are already keyed "<kind>:<value>").
func (f *Feed) Maps() (ips, asns, fps map[string]string) {
	ips, asns, fps = map[string]string{}, map[string]string{}, map[string]string{}
	for _, it := range f.IPs {
		ips[it.Value] = it.Reason
	}
	for _, it := range f.ASNs {
		asns[it.Value] = it.Reason
	}
	for _, it := range f.Fingerprints {
		fps[it.Value] = it.Reason
	}
	return ips, asns, fps
}
