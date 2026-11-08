// Package kevsync pulls the CISA Known Exploited Vulnerabilities (KEV) catalog
// and keeps it as a live, queryable overlay on top of the sensor's compile-time
// CVE catalog. The compile-time catalog (internal/cve) is curated and stable;
// the KEV feed moves daily. Syncing it lets the sensor:
//
//   - mark a cve:<id> event as actively-exploited / KEV-listed (priority boost),
//     with the date it was added and whether it is used by ransomware; and
//   - compute a coverage gap-scan at runtime: KEV entries whose CVE id the
//     sensor does not yet model, so an operator knows what to add.
//
// Fetches go through the caller-supplied (egress-governed) HTTP client, are
// size-capped, and refresh on an interval; a failed refresh keeps the last good
// snapshot rather than clearing it. The default source is the CISA KEV JSON
// feed, which must be reachable from the sensor (allowlisted egress).
package kevsync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultURL is the authoritative CISA KEV JSON feed. The host must be
// reachable from the sensor's egress policy for the live sync to work.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// maxKEVBytes caps a single KEV download (the catalog is a few MB; 32 MiB is
// generous while bounding memory).
const maxKEVBytes = 32 << 20

// Entry is one KEV record, trimmed to the fields the sensor uses.
type Entry struct {
	CVEID            string `json:"cveID"`
	VendorProject    string `json:"vendorProject"`
	Product          string `json:"product"`
	Name             string `json:"vulnerabilityName"`
	DateAdded        string `json:"dateAdded"`
	DueDate          string `json:"dueDate"`
	ShortDescription string `json:"shortDescription"`
	KnownRansomware  bool   `json:"-"`
}

// kevFile is the top-level CISA KEV JSON shape.
type kevFile struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		Entry
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// Parse decodes a CISA KEV JSON document into entries.
func Parse(b []byte) ([]Entry, error) {
	var f kevFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("kevsync: parse: %w", err)
	}
	out := make([]Entry, 0, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		e := v.Entry
		if e.CVEID == "" {
			continue
		}
		e.CVEID = strings.ToUpper(strings.TrimSpace(e.CVEID))
		e.KnownRansomware = strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "known")
		out = append(out, e)
	}
	return out, nil
}

// Store is a concurrency-safe, point-in-time KEV snapshot.
type Store struct {
	mu      sync.RWMutex
	byID    map[string]Entry
	updated time.Time
	version string
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{byID: map[string]Entry{}} }

// Replace swaps in a fresh snapshot.
func (s *Store) Replace(entries []Entry, version string) {
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		m[e.CVEID] = e
	}
	s.mu.Lock()
	s.byID = m
	s.updated = time.Now()
	s.version = version
	s.mu.Unlock()
}

// LoadFile replaces the store from a local CISA-KEV-format JSON file — the
// offline / air-gapped path (scripts/fetch-kev.sh transfers the file; the
// sensor loads it instead of fetching over the network). Returns the entry
// count and catalog version.
func (s *Store) LoadFile(path string) (int, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	entries, err := Parse(b)
	if err != nil {
		return 0, "", err
	}
	var vf struct {
		CatalogVersion string `json:"catalogVersion"`
	}
	_ = json.Unmarshal(b, &vf)
	s.Replace(entries, vf.CatalogVersion)
	return len(entries), vf.CatalogVersion, nil
}

// Lookup returns the KEV entry for a CVE id (case-insensitive), if present.
func (s *Store) Lookup(id string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byID[strings.ToUpper(strings.TrimSpace(id))]
	return e, ok
}

// Contains reports whether the CVE id is in the current KEV snapshot.
func (s *Store) Contains(id string) bool {
	_, ok := s.Lookup(id)
	return ok
}

// Count returns the number of KEV entries held.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// UpdatedAt is when the snapshot was last replaced (zero if never).
func (s *Store) UpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.updated
}

// Version is the KEV catalogVersion of the current snapshot.
func (s *Store) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// All returns the entries sorted by DateAdded descending (newest first).
func (s *Store) All() []Entry {
	s.mu.RLock()
	out := make([]Entry, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, e)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].DateAdded != out[j].DateAdded {
			return out[i].DateAdded > out[j].DateAdded
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out
}

// GapScan returns the KEV entries whose CVE id is NOT present in have (the
// sensor's modeled CVE ids), newest-first — the runtime coverage gap.
func GapScan(entries []Entry, have []string) []Entry {
	set := make(map[string]struct{}, len(have))
	for _, id := range have {
		set[strings.ToUpper(strings.TrimSpace(id))] = struct{}{}
	}
	var gaps []Entry
	for _, e := range entries {
		if _, ok := set[e.CVEID]; !ok {
			gaps = append(gaps, e)
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].DateAdded != gaps[j].DateAdded {
			return gaps[i].DateAdded > gaps[j].DateAdded
		}
		return gaps[i].CVEID < gaps[j].CVEID
	})
	return gaps
}

// Fetch downloads and parses the KEV feed from url via client, sending an
// optional "Name: value" header. The caller supplies an egress-governed client.
func Fetch(ctx context.Context, client *http.Client, url, header string) ([]Entry, string, error) {
	if client == nil {
		// Defense-in-depth: never fall back to http.DefaultClient (no timeout) —
		// a stalled connection would hang the puller goroutine indefinitely and
		// stop all further refreshes. Production always passes an egress-governed
		// client with a timeout; this only guards misuse/tests.
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tarpit-honeypot-kevsync")
	if header != "" {
		if i := strings.IndexByte(header, ':'); i > 0 {
			req.Header.Set(strings.TrimSpace(header[:i]), strings.TrimSpace(header[i+1:]))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("kevsync: GET %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxKEVBytes))
	if err != nil {
		return nil, "", err
	}
	entries, err := Parse(b)
	if err != nil {
		return nil, "", err
	}
	var version string
	var vf struct {
		CatalogVersion string `json:"catalogVersion"`
	}
	_ = json.Unmarshal(b, &vf)
	version = vf.CatalogVersion
	return entries, version, nil
}

// Puller periodically refreshes a Store from the KEV feed. It mirrors
// internal/feeds: an immediate fetch on start, then on an interval, with the
// last good snapshot retained across a failed refresh.
type Puller struct {
	url      string
	header   string
	interval time.Duration
	client   *http.Client
	store    *Store
	onError  func(error)
}

// NewPuller builds a KEV subscriber. url defaults to DefaultURL, interval to
// 6h. client should be the egress-governed HTTP client so the fetch honors the
// allowlist.
func NewPuller(url, header string, interval time.Duration, client *http.Client, store *Store) *Puller {
	if url == "" {
		url = DefaultURL
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Puller{url: url, header: header, interval: interval, client: client, store: store}
}

// SetErrorHandler registers a callback invoked on each failed refresh (optional).
func (p *Puller) SetErrorHandler(f func(error)) { p.onError = f }

// Refresh fetches once and replaces the store on success.
func (p *Puller) Refresh(ctx context.Context) error {
	entries, version, err := Fetch(ctx, p.client, p.url, p.header)
	if err != nil {
		if p.onError != nil {
			p.onError(err)
		}
		return err
	}
	p.store.Replace(entries, version)
	return nil
}

// Run refreshes immediately, then every interval, until ctx is done.
func (p *Puller) Run(ctx context.Context) {
	if p.store == nil {
		return
	}
	_ = p.Refresh(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = p.Refresh(ctx)
		}
	}
}
