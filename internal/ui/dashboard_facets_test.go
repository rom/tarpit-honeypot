package ui

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// The SQL-GROUP-BY facet path must produce byte-for-byte the same enrichment
// charts as the old per-event scan path. This golden test seeds a store with a
// dataset exercising every dimension (ATT&CK tactics/techniques from rule +
// handler + anomalies, CVEs from all three sources, geo city, ASN + operator,
// tools, per-port activity, the attack predicate) and asserts the two paths
// agree field-for-field.
func TestDashboardFacetsMatchesScanPath(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	// A deliberately repetitive, multi-dimension dataset. Repetition is the point
	// (the facet path groups identical signatures), so several events share a
	// signature while differing in geo/ASN/tool so those dimensions get counts.
	type seed struct {
		rule, handler, proto string
		sev                  event.Severity
		port                 int
		anomCol              []string       // anomalies column
		meta                 map[string]any // geo/asn/tools/meta-anomalies/emulated cves
		n                    int            // how many copies
	}
	seeds := []seed{
		{"listener:ssh", "ssh", "tcp", event.SeverityHigh, 22, nil,
			map[string]any{"geo_city": "Oslo", "asn": 13335, "asn_org": "Cloudflare", "tools": []string{"nmap"}}, 5},
		{"listener:ssh", "ssh", "tcp", event.SeverityHigh, 22, []string{"bruteforce"},
			map[string]any{"geo_city": "Oslo", "asn": 13335, "asn_org": "Cloudflare", "tools": []string{"hydra", "nmap"}, "anomalies": []string{"bruteforce"}}, 3},
		{"cve:CVE-2021-44228", "http", "tcp", event.SeverityCritical, 8080, nil,
			map[string]any{"geo_city": "Berlin", "asn": 3320, "asn_org": "DTAG", "tools": []string{"log4shell-scanner"}}, 4},
		{"listener:http", "http", "tcp", event.SeverityMedium, 80, []string{"cve:CVE-2019-5021"},
			map[string]any{"geo_city": "Berlin", "asn": 3320, "asn_org": "DTAG", "anomalies": []string{"cve:CVE-2019-5021"}}, 2},
		{"listener:http", "http", "tcp", event.SeverityLow, 80, nil,
			map[string]any{"emulated_vuln_cves": []string{"CVE-2017-0144"}, "geo_city": "Paris", "asn": 3215, "asn_org": "Orange"}, 6},
		{"listener:modbus", "modbus", "tcp", event.SeverityMedium, 502, nil,
			map[string]any{"asn": 0, "tools": []string{"nmap"}}, 2},
	}
	i := 0
	for _, s := range seeds {
		for j := 0; j < s.n; j++ {
			ev := &event.Event{
				ID: fmt.Sprintf("e%d", i), Time: now.Add(-time.Duration(i) * time.Minute),
				Sensor: "s", RuleID: s.rule, Handler: s.handler, Proto: s.proto,
				Severity: s.sev, Anomalies: s.anomCol,
				Source: event.Endpoint{IP: fmt.Sprintf("10.0.0.%d", i%250)},
				Dest:   event.Endpoint{IP: "192.0.2.1", Port: s.port},
				Meta:   s.meta,
			}
			if err := st.Insert(ctx, ev); err != nil {
				t.Fatalf("insert: %v", err)
			}
			i++
		}
	}
	since := now.Add(-24 * time.Hour)

	// --- old scan path -----------------------------------------------------
	evs, err := st.Query(ctx, store.Filter{Since: since, Limit: 100000, NoPayload: true})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("no events read back")
	}
	var dOld dashboard
	enrichDashboard(&dOld, evs)
	cvOld := configCanvas{Listeners: []portCard{{Port: 22}, {Port: 80}, {Port: 8080}, {Port: 502}, {Port: 23}}}
	markCanvasActivity(&cvOld, evs)
	svcOld := attacksByService(evs)

	// --- new facet path ----------------------------------------------------
	facets, err := st.DashboardFacets(ctx, since, 20000)
	if err != nil {
		t.Fatalf("facets: %v", err)
	}
	var dNew dashboard
	svcNew := enrichDashboardFacets(&dNew, facets)
	cvNew := configCanvas{Listeners: []portCard{{Port: 22}, {Port: 80}, {Port: 8080}, {Port: 502}, {Port: 23}}}
	markCanvasActivityPorts(&cvNew, facets.Ports)

	eq := func(name string, a, b any) {
		t.Helper()
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s mismatch:\n old = %+v\n new = %+v", name, a, b)
		}
	}
	eq("Tactics", dOld.Tactics, dNew.Tactics)
	eq("Attacks", dOld.Attacks, dNew.Attacks)
	eq("CVEs", dOld.CVEs, dNew.CVEs)
	eq("ASNs", dOld.ASNs, dNew.ASNs)
	eq("Cities", dOld.Cities, dNew.Cities)
	eq("ASNOrgs", dOld.ASNOrgs, dNew.ASNOrgs)
	eq("Tools", dOld.Tools, dNew.Tools)
	eq("attacksByService", svcOld, svcNew)
	eq("canvas", cvOld.Listeners, cvNew.Listeners)

	// Sanity: the dataset actually produced non-empty enrichment (otherwise the
	// equality above is vacuous).
	if len(dNew.CVEs) == 0 || len(dNew.Tools) == 0 || len(dNew.ASNs) == 0 || len(dNew.Attacks) == 0 {
		t.Fatalf("facet enrichment unexpectedly empty: cves=%d tools=%d asns=%d attacks=%d",
			len(dNew.CVEs), len(dNew.Tools), len(dNew.ASNs), len(dNew.Attacks))
	}
	// The three CVE sources must all surface.
	wantCVE := map[string]bool{"CVE-2021-44228": true, "CVE-2019-5021": true, "CVE-2017-0144": true}
	for _, b := range dNew.CVEs {
		delete(wantCVE, b.Label)
	}
	if len(wantCVE) != 0 {
		t.Errorf("missing CVEs from facet path: %v", wantCVE)
	}
}
