package intel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func fe(rule string, src string, meta map[string]any) *event.Event {
	return &event.Event{RuleID: rule, Source: event.Endpoint{IP: src}, Meta: meta}
}

func hasItem(items []Item, value string) bool {
	for _, it := range items {
		if it.Value == value {
			return true
		}
	}
	return false
}

func TestStoreObserveAndSnapshot(t *testing.T) {
	s := NewStore(time.Hour, 100)
	s.Observe(fe("fleet:source-multi-sensor", "203.0.113.7", map[string]any{"source": "203.0.113.7"}))
	s.Observe(fe("fleet:asn-multi-sensor", "198.51.100.2", map[string]any{"asn": "AS64500"}))
	s.Observe(fe("fleet:fingerprint-shared", "192.0.2.1", map[string]any{"fingerprint": "ja3:abc"}))
	s.Observe(fe("fleet:payload-campaign", "", map[string]any{"sources": []string{"45.0.0.9"}}))
	s.Observe(fe("fleet:first-fleet-contact", "", map[string]any{"kind": "asn", "identity": "AS-NEW"}))
	// Volume-only findings carry no attacker indicator and must be ignored.
	s.Observe(fe("fleet:rollup", "", map[string]any{"total": 99}))
	s.Observe(fe("fleet:outlier-sensor", "", map[string]any{"sensor": "s1"}))
	// Non-fleet events are ignored entirely.
	s.Observe(fe("listener:http", "8.8.8.8", nil))

	f := s.Snapshot()
	if !hasItem(f.IPs, "203.0.113.7") || !hasItem(f.IPs, "45.0.0.9") {
		t.Errorf("IPs = %v; want 203.0.113.7 + 45.0.0.9", f.IPs)
	}
	if hasItem(f.IPs, "8.8.8.8") {
		t.Errorf("non-fleet source leaked into intel: %v", f.IPs)
	}
	if !hasItem(f.ASNs, "AS64500") || !hasItem(f.ASNs, "AS-NEW") {
		t.Errorf("ASNs = %v; want AS64500 + AS-NEW", f.ASNs)
	}
	if !hasItem(f.Fingerprints, "ja3:abc") {
		t.Errorf("Fingerprints = %v; want ja3:abc", f.Fingerprints)
	}
}

func TestStoreTTLExpiry(t *testing.T) {
	s := NewStore(time.Hour, 100)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	s.Observe(fe("fleet:source-multi-sensor", "203.0.113.7", nil))
	if f := s.Snapshot(); !hasItem(f.IPs, "203.0.113.7") {
		t.Fatal("indicator missing before expiry")
	}
	now = now.Add(2 * time.Hour) // past the TTL
	if f := s.Snapshot(); hasItem(f.IPs, "203.0.113.7") {
		t.Errorf("indicator survived past TTL: %v", f.IPs)
	}
}

func TestStoreCap(t *testing.T) {
	s := NewStore(time.Hour, 1)
	s.Observe(fe("fleet:source-multi-sensor", "203.0.113.1", nil))
	s.Observe(fe("fleet:source-multi-sensor", "203.0.113.2", nil))
	if f := s.Snapshot(); len(f.IPs) != 1 {
		t.Errorf("IPs = %v; want capped to 1", f.IPs)
	}
}

func TestHandlerAuth(t *testing.T) {
	s := NewStore(time.Hour, 100)
	s.Observe(fe("fleet:source-multi-sensor", "203.0.113.7", nil))
	h := s.Handler("sekret")

	// No token -> 401.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/intel", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no-token status = %d; want 401", w.Code)
	}
	// Wrong method -> 405.
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/intel", nil)
	r.Header.Set("Authorization", "Bearer sekret")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}
	// Correct token -> 200 + the feed.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/intel", nil)
	r.Header.Set("Authorization", "Bearer sekret")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("authed status = %d; want 200", w.Code)
	}
	var f Feed
	if err := json.NewDecoder(w.Body).Decode(&f); err != nil {
		t.Fatalf("decode feed: %v", err)
	}
	if !hasItem(f.IPs, "203.0.113.7") {
		t.Errorf("served feed missing indicator: %v", f.IPs)
	}
}

func TestFeedMaps(t *testing.T) {
	f := &Feed{
		IPs:          []Item{{Value: "203.0.113.7", Reason: "source-multi-sensor"}},
		ASNs:         []Item{{Value: "AS64500", Reason: "asn-multi-sensor"}},
		Fingerprints: []Item{{Value: "ja3:abc", Reason: "fingerprint-shared"}},
	}
	ips, asns, fps := f.Maps()
	if ips["203.0.113.7"] != "source-multi-sensor" || asns["AS64500"] != "asn-multi-sensor" || fps["ja3:abc"] != "fingerprint-shared" {
		t.Errorf("Maps() = %v / %v / %v", ips, asns, fps)
	}
}
