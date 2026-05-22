package store

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestFingerprintsAndFilter(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	// Two source IPs share JA3 "aaa"; a third uses "bbb".
	mk := func(id, ip, ja3 string, t time.Time) *event.Event {
		e := mkEvent(id, ip, "listener:tls", event.SeverityMedium, t)
		e.Meta = map[string]any{"ja3": ja3, "geo_country": "RU"}
		return e
	}
	for _, e := range []*event.Event{
		mk("a", "1.1.1.1", "aaa", now.Add(-10*time.Minute)),
		mk("b", "2.2.2.2", "aaa", now.Add(-5*time.Minute)),
		mk("c", "2.2.2.2", "aaa", now.Add(-1*time.Minute)),
		mk("d", "3.3.3.3", "bbb", now.Add(-2*time.Minute)),
	} {
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := s.Fingerprints(ctx, now.Add(-time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d fingerprint rows; want 2 (%+v)", len(rows), rows)
	}
	// Ordered by event count desc → "aaa" first (3 events, 2 IPs).
	top := rows[0]
	if top.Kind != "ja3" || top.Value != "aaa" || top.Count != 3 || top.IPs != 2 {
		t.Errorf("top fingerprint wrong: %+v", top)
	}
	if top.FirstSeen.After(top.LastSeen) {
		t.Errorf("first seen after last seen: %+v", top)
	}

	// The fingerprint Filter restricts Query to matching events.
	evs, err := s.Query(ctx, Filter{FPKind: "ja3", FPValue: "aaa", Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Errorf("FP filter returned %d events; want 3", len(evs))
	}

	// An unknown kind matches nothing (and never reaches SQL as a path).
	evs, err = s.Query(ctx, Filter{FPKind: "evil$.path", FPValue: "aaa", Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Errorf("unknown FP kind returned %d events; want 0", len(evs))
	}
}

func TestFingerprintKindKnown(t *testing.T) {
	for _, k := range []string{"ja3", "ja4", "ja4h", "ja3s", "hassh", "hassh_server"} {
		if !FingerprintKindKnown(k) {
			t.Errorf("%q should be a known fingerprint kind", k)
		}
	}
	for _, k := range []string{"", "sni", "ja3'", "$.ja3", "ja3; DROP"} {
		if FingerprintKindKnown(k) {
			t.Errorf("%q must not be a known fingerprint kind", k)
		}
	}
}
