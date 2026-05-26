// Package intel implements the downward fleet-intel feedback channel. An
// aggregator folds its own fleet:* findings into a windowed Store of indicators
// (hot source IPs, ASNs, and TLS/SSH fingerprints), serves them as a small JSON
// feed on its authenticated endpoint, and any node subscribes (see Puller) and
// hands them to its enricher — so knowledge derived from the whole fleet tags
// events on every sensor, where the local tarpit / severity / risk / threat-
// intel machinery already acts on it. Intel flows down; events flow up.
package intel

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Item is one indicator and the fleet finding (the fleet:* rule, minus the
// prefix) that surfaced it.
type Item struct {
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Feed is the served snapshot of current fleet intel.
type Feed struct {
	Generated    time.Time `json:"generated"`
	TTLSeconds   int       `json:"ttl_seconds"`
	IPs          []Item    `json:"ips"`
	ASNs         []Item    `json:"asns"`
	Fingerprints []Item    `json:"fingerprints"`
}

type entry struct {
	reason string
	exp    time.Time
}

// Store holds the windowed indicator sets an aggregator derives from its
// fleet:* findings. Safe for concurrent use.
type Store struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	ips map[string]entry
	as  map[string]entry
	fps map[string]entry
	now func() time.Time
}

// NewStore builds an intel store. ttl is how long an indicator lingers after it
// was last seen; max caps each set.
func NewStore(ttl time.Duration, max int) *Store {
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	if max <= 0 {
		max = 10000
	}
	return &Store{
		ttl: ttl, max: max,
		ips: map[string]entry{}, as: map[string]entry{}, fps: map[string]entry{},
		now: time.Now,
	}
}

// Observe folds one fleet:* finding into the indicator sets. Non-fleet events
// and the volume-only fleet:rollup / fleet:synchronized-burst / fleet:outlier-
// sensor findings (which carry no attacker indicator) are ignored.
func (s *Store) Observe(ev *event.Event) {
	if ev == nil || !strings.HasPrefix(ev.RuleID, "fleet:") {
		return
	}
	reason := strings.TrimPrefix(ev.RuleID, "fleet:")
	switch reason {
	case "rollup", "synchronized-burst", "outlier-sensor":
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Source.IP != "" {
		s.add(s.ips, ev.Source.IP, reason)
	}
	if v := metaStr(ev, "source"); v != "" {
		s.add(s.ips, v, reason)
	}
	for _, ip := range metaStrings(ev, "sources") {
		s.add(s.ips, ip, reason)
	}
	if v := metaStr(ev, "asn"); v != "" {
		s.add(s.as, v, reason)
	}
	if v := metaStr(ev, "fingerprint"); v != "" {
		s.add(s.fps, v, reason)
	}
	// first-fleet-contact (kind+identity) and geo-distributed-actor (by+identity)
	// carry the indicator in identity.
	id := metaStr(ev, "identity")
	if id != "" {
		switch {
		case metaStr(ev, "kind") == "asn":
			s.add(s.as, id, reason)
		case metaStr(ev, "kind") == "fingerprint", metaStr(ev, "by") == "fingerprint":
			s.add(s.fps, id, reason)
		}
	}
}

// add records k with reason, refreshing its TTL. The per-set cap bounds memory;
// when full, the entry with the *earliest* expiry is evicted to make room. This
// LRU-by-TTL beats refuse-when-full (which would let a one-time flood of novel
// indicators lock out everything that arrives later until TTL).
func (s *Store) add(m map[string]entry, k, reason string) {
	exp := s.now().Add(s.ttl)
	if e, ok := m[k]; ok {
		e.exp = exp
		e.reason = reason
		m[k] = e
		return
	}
	if len(m) >= s.max {
		var oldestK string
		var oldestExp time.Time
		for kk, e := range m {
			if oldestK == "" || e.exp.Before(oldestExp) {
				oldestK = kk
				oldestExp = e.exp
			}
		}
		if oldestK != "" {
			delete(m, oldestK)
		}
	}
	m[k] = entry{reason: reason, exp: exp}
}

// Snapshot prunes expired indicators and returns the current feed.
func (s *Store) Snapshot() Feed {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	return Feed{
		Generated:    now,
		TTLSeconds:   int(s.ttl.Seconds()),
		IPs:          dump(s.ips, now),
		ASNs:         dump(s.as, now),
		Fingerprints: dump(s.fps, now),
	}
}

// dump prunes expired entries from m and returns the survivors sorted by value.
func dump(m map[string]entry, now time.Time) []Item {
	out := make([]Item, 0, len(m))
	for k, e := range m {
		if e.exp.Before(now) {
			delete(m, k)
			continue
		}
		out = append(out, Item{Value: k, Reason: e.reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// IOC is one indicator flattened with its kind, for the STIX / TAXII / MISP
// exporters. Kind is "ip", "asn", or "fingerprint" (Value keeps the
// "<kind>:<value>" form for fingerprints).
type IOC struct {
	Kind   string
	Value  string
	Reason string
}

// IOCs returns the current indicators (pruned) flattened across the three sets.
func (s *Store) IOCs() []IOC {
	f := s.Snapshot()
	out := make([]IOC, 0, len(f.IPs)+len(f.ASNs)+len(f.Fingerprints))
	for _, it := range f.IPs {
		out = append(out, IOC{Kind: "ip", Value: it.Value, Reason: it.Reason})
	}
	for _, it := range f.ASNs {
		out = append(out, IOC{Kind: "asn", Value: it.Value, Reason: it.Reason})
	}
	for _, it := range f.Fingerprints {
		out = append(out, IOC{Kind: "fingerprint", Value: it.Value, Reason: it.Reason})
	}
	return out
}

// Handler serves GET requests with the current feed as JSON, gated by a bearer
// token (constant-time). Mount it on the aggregator's authenticated endpoint.
func (s *Store) Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Snapshot())
	})
}

func metaStr(ev *event.Event, key string) string {
	if ev.Meta == nil {
		return ""
	}
	s, _ := ev.Meta[key].(string)
	return s
}

func metaStrings(ev *event.Event, key string) []string {
	if ev.Meta == nil {
		return nil
	}
	switch t := ev.Meta[key].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
