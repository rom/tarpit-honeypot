package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Regression: filtering /events by ASN must return the matching events even
// when they are NOT among the newest `Limit` rows. The old code post-filtered
// in the UI *after* a SQL LIMIT 100, so an ASN whose traffic wasn't in the
// latest 100 events came back empty. ASN is now a real meta-column SQL filter.
func TestQueryByASN(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Now().Add(-2 * time.Hour)

	// One early event from AS14618, then 150 newer events from a different ASN.
	target := mkEvent("evt-asn", "203.0.113.9", "tcp:ssh", event.SeverityHigh, base)
	target.Meta = map[string]any{"asn": uint32(14618), "asn_org": "AMAZON-AES"}
	if err := s.Insert(ctx, target); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		e := mkEvent(fmt.Sprintf("noise-%d", i), "198.51.100.5", "tcp:ssh", event.SeverityLow,
			base.Add(time.Duration(i+1)*time.Minute))
		e.Meta = map[string]any{"asn": uint32(15169), "asn_org": "GOOGLE"}
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	// LIMIT 100 (the /events default) — the AS14618 event is the OLDEST of 151,
	// so it is well outside the newest 100. The SQL ASN filter must still find it.
	got, err := s.Query(ctx, Filter{ASN: 14618, Since: base.Add(-time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "evt-asn" {
		t.Fatalf("ASN filter returned %d events, want exactly the AS14618 one", len(got))
	}

	// A non-matching ASN returns nothing.
	none, err := s.Query(ctx, Filter{ASN: 64500, Since: base.Add(-time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("unexpected matches for ASN 64500: %d", len(none))
	}
}
