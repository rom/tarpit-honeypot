package ui

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestSplitFilterTokens(t *testing.T) {
	incl, excl := splitFilterTokens("a, b ,!c,!  d ,, !")
	if !reflect.DeepEqual(incl, []string{"a", "b"}) {
		t.Errorf("incl = %v", incl)
	}
	if !reflect.DeepEqual(excl, []string{"c", "d"}) {
		t.Errorf("excl = %v", excl)
	}
}

func TestParseFilterNegationAndMulti(t *testing.T) {
	// A single positive value keeps the fast single-column path.
	f := parseFilter(httptest.NewRequest("GET", "/events?rule=sniffer:arp_scan", nil))
	if f.RuleID != "sniffer:arp_scan" || len(f.ExcludeRuleIDs) != 0 {
		t.Errorf("single rule: RuleID=%q excl=%v", f.RuleID, f.ExcludeRuleIDs)
	}
	// Negation populates the exclude list (and leaves the single field empty).
	f = parseFilter(httptest.NewRequest("GET", "/events?rule="+url.QueryEscape("!sniffer:arp_scan"), nil))
	if f.RuleID != "" || !reflect.DeepEqual(f.ExcludeRuleIDs, []string{"sniffer:arp_scan"}) {
		t.Errorf("negated rule: RuleID=%q excl=%v", f.RuleID, f.ExcludeRuleIDs)
	}
	// Multiple source IPs.
	f = parseFilter(httptest.NewRequest("GET", "/events?source=1.1.1.1,2.2.2.2", nil))
	if !reflect.DeepEqual(f.SourceIPs, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Errorf("multi source: %v", f.SourceIPs)
	}
	// Mixed include + exclude on one field.
	f = parseFilter(httptest.NewRequest("GET", "/events?proto="+url.QueryEscape("tcp,!udp"), nil))
	if !reflect.DeepEqual(f.Protos, []string{"tcp"}) || !reflect.DeepEqual(f.ExcludeProtos, []string{"udp"}) {
		t.Errorf("mixed proto: incl=%v excl=%v", f.Protos, f.ExcludeProtos)
	}
	// ASN negation, numeric, with an AS prefix tolerated.
	f = parseFilter(httptest.NewRequest("GET", "/events?asn="+url.QueryEscape("!AS100,!200"), nil))
	if f.ASN != 0 || !reflect.DeepEqual(f.ExcludeASNs, []int{100, 200}) {
		t.Errorf("asn negation: ASN=%d excl=%v", f.ASN, f.ExcludeASNs)
	}
}

func TestParseChartFiltersAndStore(t *testing.T) {
	q, _ := url.ParseQuery("only=ip:1.1.1.1&exclude=asn:100&exclude=asn:200&exclude=ip:2.2.2.2&only=foo:bad&exclude=rule:")
	only, exclude := parseChartFilters(q)
	if len(only) != 1 || only[0] != (chartDimVal{"ip", "1.1.1.1"}) {
		t.Errorf("only = %v", only)
	}
	// foo: is an unknown dimension (dropped); rule: has an empty value (dropped).
	wantExcl := []chartDimVal{{"asn", "100"}, {"asn", "200"}, {"ip", "2.2.2.2"}}
	if !reflect.DeepEqual(exclude, wantExcl) {
		t.Errorf("exclude = %v", exclude)
	}
	f := chartFiltersToStore(only, exclude, store.Filter{})
	if !reflect.DeepEqual(f.SourceIPs, []string{"1.1.1.1"}) ||
		!reflect.DeepEqual(f.ExcludeSourceIPs, []string{"2.2.2.2"}) ||
		!reflect.DeepEqual(f.ExcludeASNs, []int{100, 200}) {
		t.Errorf("store filter = %+v", f)
	}
}

func TestParseChartFiltersDedup(t *testing.T) {
	q, _ := url.ParseQuery("exclude=ip:1.1.1.1&exclude=ip:1.1.1.1")
	if _, exclude := parseChartFilters(q); len(exclude) != 1 {
		t.Errorf("dedup failed: %v", exclude)
	}
}

func TestChartAddRedirect(t *testing.T) {
	q, _ := url.ParseQuery("range=7d&exclude=ip:1.1.1.1&mode=exclude&dim=asn&val=14061")
	u, err := url.Parse(chartAddRedirect(q))
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/charts" {
		t.Fatalf("path = %q", u.Path)
	}
	got := u.Query()
	if got.Get("range") != "7d" {
		t.Errorf("range lost: %v", got)
	}
	if ex := got["exclude"]; len(ex) != 2 || ex[0] != "ip:1.1.1.1" || ex[1] != "asn:14061" {
		t.Errorf("exclude = %v", ex)
	}
	// The transient add-form params must not leak into the canonical URL.
	if got.Get("val") != "" || got.Get("mode") != "" || got.Get("dim") != "" {
		t.Errorf("add-form params leaked: %v", got)
	}
}

func TestChartFilterChipsRemove(t *testing.T) {
	only := []chartDimVal{{"ip", "1.1.1.1"}}
	exclude := []chartDimVal{{"asn", "100"}, {"asn", "200"}}
	chips := chartFilterChips("24h", only, exclude)
	if len(chips) != 3 {
		t.Fatalf("chips = %d, want 3", len(chips))
	}
	// chips[1] is the first exclude (asn:100); removing it must drop only that.
	u, err := url.Parse(chips[1].RemoveHref)
	if err != nil {
		t.Fatal(err)
	}
	if ex := u.Query()["exclude"]; len(ex) != 1 || ex[0] != "asn:200" {
		t.Errorf("remove asn:100 → exclude=%v", ex)
	}
	if u.Query().Get("only") != "ip:1.1.1.1" {
		t.Errorf("remove dropped the only clause: %q", chips[1].RemoveHref)
	}
}

func TestSummaryFromEvents(t *testing.T) {
	now := time.Now().UTC()
	mk := func(id, ip, rule, handler, country string, sev event.Severity) *event.Event {
		return &event.Event{
			ID: id, Time: now, RuleID: rule, Severity: sev,
			Source: event.Endpoint{IP: ip}, Dest: event.Endpoint{IP: "10.0.0.1"},
			Proto: "tcp", Handler: handler,
			Meta: map[string]any{"geo_country": country},
		}
	}
	evs := []*event.Event{
		mk("a", "1.1.1.1", "r1", "ssh", "US", event.SeverityHigh),
		mk("b", "1.1.1.1", "r1", "ssh", "US", event.SeverityHigh),
		mk("c", "2.2.2.2", "r2", "http", "CN", event.SeverityLow),
	}
	sum := summaryFromEvents(evs, now.Add(-time.Hour))
	if sum.Total != 3 || sum.ByRule["r1"] != 2 || sum.ByHandler["ssh"] != 2 ||
		sum.ByCountry["US"] != 2 || sum.ByCountry["CN"] != 1 {
		t.Errorf("summary = %+v", sum)
	}
	if len(sum.TopSources) != 2 || sum.TopSources[0].IP != "1.1.1.1" || sum.TopSources[0].Count != 2 {
		t.Errorf("top sources = %v", sum.TopSources)
	}
}

func TestBucketsFromEvents(t *testing.T) {
	now := time.Now().UTC()
	since := now.Add(-3 * time.Hour)
	evs := []*event.Event{
		{ID: "a", Time: now.Add(-150 * time.Minute)},
		{ID: "b", Time: now.Add(-150 * time.Minute)},
		{ID: "c", Time: now.Add(-10 * time.Minute)},
	}
	b := bucketsFromEvents(evs, since, time.Hour)
	total := 0
	for _, hb := range b {
		total += hb.Count
	}
	if total != 3 {
		t.Errorf("bucket total = %d, want 3", total)
	}
	if len(b) < 3 {
		t.Errorf("expected ~4 hourly buckets, got %d", len(b))
	}
}
