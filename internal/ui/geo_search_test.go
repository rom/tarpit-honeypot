package ui

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// The events-page filter accepts the new GeoIP / network meta dimensions
// (geo_city, geo_country_name, asn_org) with comma-multi + '!'-negation.
func TestParseFilterGeoDimensions(t *testing.T) {
	r := httptest.NewRequest("GET",
		"/events?geo_city=Ashburn&geo_country_name=United+States&asn_org=GOOGLE,!AMAZON-AES", nil)
	f := parseFilter(r)
	if len(f.Cities) != 1 || f.Cities[0] != "Ashburn" {
		t.Errorf("Cities = %v", f.Cities)
	}
	if len(f.CountryNames) != 1 || f.CountryNames[0] != "United States" {
		t.Errorf("CountryNames = %v", f.CountryNames)
	}
	if len(f.ASNOrgs) != 1 || f.ASNOrgs[0] != "GOOGLE" {
		t.Errorf("ASNOrgs = %v", f.ASNOrgs)
	}
	if len(f.ExcludeASNOrgs) != 1 || f.ExcludeASNOrgs[0] != "AMAZON-AES" {
		t.Errorf("ExcludeASNOrgs = %v", f.ExcludeASNOrgs)
	}
}

// The advanced search form parses the same fields (substring search), accepting
// both the canonical name and the geo_-prefixed alias a pivot link carries.
func TestParseSearchQueryGeoFields(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?city=ashb&country_name=united&asn_org=cloudflare", nil)
	q := parseSearchQuery(r)
	if q.City != "ashb" || q.CountryName != "united" || q.ASNOrg != "cloudflare" {
		t.Errorf("canonical: City=%q CountryName=%q ASNOrg=%q", q.City, q.CountryName, q.ASNOrg)
	}
	r = httptest.NewRequest("GET", "/search?geo_city=york&geo_country_name=france", nil)
	q = parseSearchQuery(r)
	if q.City != "york" || q.CountryName != "france" {
		t.Errorf("geo_-alias: City=%q CountryName=%q", q.City, q.CountryName)
	}
}

// The charts include/exclude dimensions cover the new geo/network fields and map
// onto the right store.Filter lists.
func TestChartFiltersGeoDimensions(t *testing.T) {
	q := url.Values{}
	q.Add("only", "city:Ashburn")
	q.Add("only", "asn_org:GOOGLE")
	q.Add("exclude", "country_name:United States")
	only, exclude := parseChartFilters(q)
	f := chartFiltersToStore(only, exclude, store.Filter{})
	if len(f.Cities) != 1 || f.Cities[0] != "Ashburn" {
		t.Errorf("Cities = %v", f.Cities)
	}
	if len(f.ASNOrgs) != 1 || f.ASNOrgs[0] != "GOOGLE" {
		t.Errorf("ASNOrgs = %v", f.ASNOrgs)
	}
	if len(f.ExcludeCountryNames) != 1 || f.ExcludeCountryNames[0] != "United States" {
		t.Errorf("ExcludeCountryNames = %v", f.ExcludeCountryNames)
	}
}

// End-to-end: runSearch substring-matches geo_city / geo_country_name / asn_org.
func TestRunSearchGeoSubstring(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, ip, city, cname, org string) *event.Event {
		return &event.Event{
			ID: id, Time: now, Sensor: "t", RuleID: "ssh:bruteforce", Severity: event.SeverityHigh,
			Source: event.Endpoint{IP: ip, Port: 1234}, Dest: event.Endpoint{IP: "10.0.0.1", Port: 22},
			Proto: "tcp", Handler: "ssh",
			Meta: map[string]any{"geo_city": city, "geo_country_name": cname, "asn_org": org},
		}
	}
	for _, e := range []*event.Event{
		mk("us", "1.1.1.1", "Ashburn", "United States", "AMAZON-AES"),
		mk("de", "2.2.2.2", "Frankfurt", "Germany", "Hetzner Online"),
	} {
		if err := st.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	// City substring (case-insensitive) → only the Ashburn event.
	got, _, err := runSearch(ctx, st, searchQuery{City: "ashb"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "us" {
		t.Fatalf("City search returned %d events, want exactly 'us'", len(got))
	}

	// asn_org substring → only Hetzner.
	got, _, err = runSearch(ctx, st, searchQuery{ASNOrg: "hetzner"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "de" {
		t.Fatalf("ASNOrg search returned %d events, want exactly 'de'", len(got))
	}

	// country name substring → only Germany.
	got, _, err = runSearch(ctx, st, searchQuery{CountryName: "german"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "de" {
		t.Fatalf("CountryName search returned %d events, want exactly 'de'", len(got))
	}
}
