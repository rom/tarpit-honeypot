// Package feeds ingests EXTERNAL threat-intel reputation feeds (plain IP/CIDR
// lists such as the FireHOL/Spamhaus/Emerging-Threats blocklists, or simple
// JSON arrays of IPs) and folds them into the live enricher overlay, so a
// source seen in any feed is tagged external_intel + threat_intel_hit and the
// existing risk / tarpit / severity / blocklist machinery acts on it.
//
// Distinct from internal/intel (the DOWNWARD fleet feed): this pulls from
// third-party sources the operator configures. All fetches go through the
// egress allowlist (so the sensor can only reach feed hosts the operator
// permitted), are size-capped, and refresh on an interval; a fetch failure
// keeps the last good snapshot rather than clearing the overlay.
package feeds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// maxFeedBytes caps a single feed download (large public blocklists run a few
// MB; 32 MiB is generous while bounding memory).
const maxFeedBytes = 32 << 20

// Feed is one configured external source.
type Feed struct {
	// Label tags matching events (e.g. "firehol", "abuseipdb", "spamhaus").
	Label string
	// URL is the feed endpoint (must be in the egress allowlist).
	URL string
	// Format: "lines" (one IP/CIDR per line, '#' comments) or "json_ips"
	// (a JSON array of IP strings, or {"data":[{"ipAddress":"..."}]} AbuseIPDB
	// shape). Empty defaults to "lines".
	Format string
	// Header is an optional auth header line "Name: value" (e.g. an API key).
	Header string
}

// Puller periodically fetches the configured feeds and applies a merged
// IP->label overlay via apply (wired to Enricher.SetExternalIntel).
type Puller struct {
	feeds    []Feed
	interval time.Duration
	client   *http.Client
	apply    func(map[string]string)
	// last is the most recent good overlay, kept on a failed refresh.
	last map[string]string
}

// NewPuller builds a feeds subscriber. client should be the egress-governed
// HTTP client (egress.Default().HTTPClient(...)) so fetches honor the
// allowlist. interval defaults to 1h.
func NewPuller(feeds []Feed, interval time.Duration, client *http.Client, apply func(map[string]string)) *Puller {
	if interval <= 0 {
		interval = time.Hour
	}
	return &Puller{feeds: feeds, interval: interval, client: client, apply: apply}
}

// Run polls until ctx is done, fetching once immediately so a fresh sensor gets
// the feeds without waiting a full interval.
func (p *Puller) Run(ctx context.Context) {
	if len(p.feeds) == 0 || p.client == nil || p.apply == nil {
		return
	}
	p.refresh(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh(ctx)
		}
	}
}

// refresh fetches every feed, merges the results into one IP->label map, and
// applies it. A feed that fails to fetch is skipped (its prior entries are
// dropped only if every feed fails, in which case we keep the last snapshot).
func (p *Puller) refresh(ctx context.Context) {
	merged := map[string]string{}
	anyOK := false
	for _, f := range p.feeds {
		ips, err := p.fetchOne(ctx, f)
		if err != nil {
			slog.Warn("feeds: fetch failed", "label", f.Label, "url", f.URL, "err", err)
			continue
		}
		anyOK = true
		label := f.Label
		if label == "" {
			label = "external"
		}
		for ip := range ips {
			if existing, ok := merged[ip]; ok {
				merged[ip] = existing + "," + label // an IP in multiple feeds carries all labels
			} else {
				merged[ip] = label
			}
		}
	}
	if !anyOK {
		// Every feed failed — keep the last good overlay rather than clearing.
		return
	}
	p.last = merged
	p.apply(merged)
	slog.Info("feeds: external intel refreshed", "indicators", len(merged), "feeds", len(p.feeds))
}

// fetchOne downloads and parses a single feed into a set of canonical IP
// strings. CIDR entries are expanded only as the prefix string is not directly
// matchable by the IP-keyed overlay; for simplicity we record exact IPs and
// skip CIDRs here (the file-based ThreatLists handle CIDR ranges).
func (p *Puller) fetchOne(ctx context.Context, f Feed) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	if f.Header != "" {
		if name, val, ok := strings.Cut(f.Header, ":"); ok {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(val))
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, err
	}
	switch f.Format {
	case "json_ips":
		return parseJSONIPs(body)
	default:
		return parseLineIPs(body), nil
	}
}

// parseLineIPs reads one IP (or CIDR — the network address is recorded) per
// line, ignoring blanks and '#' comments and any trailing columns.
func parseLineIPs(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t#,"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if a, err := netip.ParseAddr(line); err == nil {
			out[a.String()] = ""
			continue
		}
		// A CIDR line: record the network address so an exact-IP match on the
		// network still tags; range matching is left to file ThreatLists.
		if pfx, err := netip.ParsePrefix(line); err == nil {
			out[pfx.Masked().Addr().String()] = ""
		}
	}
	return out
}

// parseJSONIPs accepts either a bare JSON array of IP strings or the AbuseIPDB
// blacklist shape {"data":[{"ipAddress":"1.2.3.4"},...]}.
func parseJSONIPs(b []byte) (map[string]string, error) {
	out := map[string]string{}
	// Try a bare array first.
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		for _, s := range arr {
			if a, e := netip.ParseAddr(strings.TrimSpace(s)); e == nil {
				out[a.String()] = ""
			}
		}
		return out, nil
	}
	// AbuseIPDB-style object.
	var obj struct {
		Data []struct {
			IPAddress string `json:"ipAddress"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	for _, d := range obj.Data {
		if a, e := netip.ParseAddr(strings.TrimSpace(d.IPAddress)); e == nil {
			out[a.String()] = ""
		}
	}
	return out, nil
}
