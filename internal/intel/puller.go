package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/rom/tarpit-honeypot/internal/egress"
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

// NewPuller builds a feed subscriber. interval defaults to 60s; a nil client
// falls back to the process-wide egress-allowlisted client so a missing wire-up
// can't slip through into an unconstrained dial.
func NewPuller(url, token string, interval time.Duration, client *http.Client, apply func(*Feed)) *Puller {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if client == nil {
		client = egress.HTTPClient(15 * time.Second)
	}
	return &Puller{url: url, token: token, interval: interval, client: client, apply: apply}
}

// maxFeedBody caps the response a child accepts from an aggregator's intel
// feed. A legitimate feed at the default 10k-per-set cap is ~1.5 MiB; 2 MiB
// gives headroom without letting a misbehaving aggregator spike client memory.
const maxFeedBody = 2 << 20

// maxFeedPerSet caps how many indicators a child will adopt from any single
// feed snapshot, regardless of what the aggregator sends. Pure defense in depth
// against an aggregator that grew its own per-set cap (or was compromised).
const maxFeedPerSet = 50_000

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
	clampFeed(feed)
	p.apply(feed)
	slog.Debug("intel: feed applied", "ips", len(feed.IPs), "asns", len(feed.ASNs), "fingerprints", len(feed.Fingerprints))
}

// clampFeed truncates each per-set list to maxFeedPerSet so a child can't be
// induced to track an unbounded indicator set by an over-sized snapshot.
func clampFeed(f *Feed) {
	if len(f.IPs) > maxFeedPerSet {
		f.IPs = f.IPs[:maxFeedPerSet]
	}
	if len(f.ASNs) > maxFeedPerSet {
		f.ASNs = f.ASNs[:maxFeedPerSet]
	}
	if len(f.Fingerprints) > maxFeedPerSet {
		f.Fingerprints = f.Fingerprints[:maxFeedPerSet]
	}
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFeedBody)).Decode(&f); err != nil {
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
