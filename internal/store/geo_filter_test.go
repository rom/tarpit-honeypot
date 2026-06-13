package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// The events / charts / stats pivots can scope by the free-text GeoIP / network
// meta dimensions (geo_city, geo_country_name, asn_org) via json_extract. These
// must work even when the matching event is outside the newest LIMIT rows, and
// the exclude form must keep rows that carry no value (NULL), like ASN does.
func TestQueryByGeoMetaDimensions(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Now().Add(-2 * time.Hour)

	target := mkEvent("evt-geo", "203.0.113.9", "tcp:ssh", event.SeverityHigh, base)
	target.Meta = map[string]any{
		"geo_city": "Ashburn", "geo_country_name": "United States", "asn_org": "AMAZON-AES",
	}
	if err := s.Insert(ctx, target); err != nil {
		t.Fatal(err)
	}
	// A row with no geo/asn meta at all (must survive an exclude filter).
	bare := mkEvent("evt-bare", "192.0.2.1", "tcp:ssh", event.SeverityLow, base.Add(time.Minute))
	bare.Meta = map[string]any{"note": "x"}
	if err := s.Insert(ctx, bare); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		e := mkEvent(fmt.Sprintf("noise-%d", i), "198.51.100.5", "tcp:ssh", event.SeverityLow,
			base.Add(time.Duration(i+2)*time.Minute))
		e.Meta = map[string]any{"geo_city": "Mountain View", "geo_country_name": "United States", "asn_org": "GOOGLE"}
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	win := Filter{Since: base.Add(-time.Hour), Limit: 100}

	// Include by city — the target is the oldest of 152, well outside LIMIT 100.
	f := win
	f.Cities = []string{"Ashburn"}
	if got, err := s.Query(ctx, f); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].ID != "evt-geo" {
		t.Fatalf("Cities filter returned %d events, want exactly evt-geo", len(got))
	}

	// Include by asn_org.
	f = win
	f.ASNOrgs = []string{"AMAZON-AES"}
	if got, err := s.Query(ctx, f); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].ID != "evt-geo" {
		t.Fatalf("ASNOrgs filter returned %d events, want exactly evt-geo", len(got))
	}

	// Include by country name returns the whole US set (target + bare has none).
	f = win
	f.CountryNames = []string{"United States"}
	f.Limit = 1000
	if got, err := s.Query(ctx, f); err != nil {
		t.Fatal(err)
	} else if len(got) != 151 {
		t.Fatalf("CountryNames filter returned %d events, want 151 (target + 150 noise)", len(got))
	}

	// Exclude asn_org GOOGLE: drops the 150 noise rows, keeps the AMAZON target
	// AND the bare row that has no asn_org at all.
	f = win
	f.ExcludeASNOrgs = []string{"GOOGLE"}
	f.Limit = 1000
	got, err := s.Query(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("ExcludeASNOrgs returned %d events, want 2 (target + bare)", len(got))
	}
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !ids["evt-geo"] || !ids["evt-bare"] {
		t.Fatalf("ExcludeASNOrgs kept the wrong rows: %v", ids)
	}
}
