package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDashboardFacets(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()

	ins := func(id, rule, handler, proto string, sev event.Severity, port int, anom []string, meta map[string]any) {
		t.Helper()
		if err := s.Insert(ctx, &event.Event{
			ID: id, Time: now, Sensor: "s", RuleID: rule, Handler: handler, Proto: proto,
			Severity: sev, Anomalies: anom,
			Source: event.Endpoint{IP: "10.0.0.1"}, Dest: event.Endpoint{IP: "192.0.2.1", Port: port},
			Meta: meta,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// Two events share a full signature (same rule/handler/proto/sev/anoms/meta);
	// one differs only by geo/asn/tools; one has empty meta.
	ins("a", "listener:ssh", "ssh", "tcp", event.SeverityHigh, 22, nil,
		map[string]any{"geo_city": "Oslo", "asn": 13335, "asn_org": "CF", "tools": []string{"nmap", "hydra"}})
	ins("b", "listener:ssh", "ssh", "tcp", event.SeverityHigh, 22, nil,
		map[string]any{"geo_city": "Oslo", "asn": 13335, "asn_org": "CF", "tools": []string{"nmap", "hydra"}})
	ins("c", "cve:CVE-2021-44228", "http", "tcp", event.SeverityCritical, 8080, []string{"cve:CVE-2021-44228"},
		map[string]any{"geo_city": "Berlin", "asn": 3320, "asn_org": "DTAG", "tools": []string{"nmap"}, "anomalies": []string{"cve:CVE-2021-44228"}, "emulated_vuln_cves": []string{"CVE-2017-0144"}})
	ins("d", "listener:raw", "", "tcp", event.SeverityLow, 9999, nil, nil) // empty meta ('' json)

	f, err := s.DashboardFacets(ctx, now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatalf("DashboardFacets: %v", err)
	}

	// Attack signatures: a+b collapse into one row (count 2); c and d are their
	// own rows → 3 signatures.
	if len(f.Attacks) != 3 {
		t.Fatalf("attack signatures = %d; want 3 (%+v)", len(f.Attacks), f.Attacks)
	}
	var sshSig *AttackFacet
	for i := range f.Attacks {
		if f.Attacks[i].RuleID == "listener:ssh" {
			sshSig = &f.Attacks[i]
		}
	}
	if sshSig == nil || sshSig.Count != 2 {
		t.Fatalf("ssh signature count = %v; want 2", sshSig)
	}
	// The CVE signature must carry both the anomaly marker and the emulated CVE.
	var cveSig *AttackFacet
	for i := range f.Attacks {
		if f.Attacks[i].RuleID == "cve:CVE-2021-44228" {
			cveSig = &f.Attacks[i]
		}
	}
	if cveSig == nil {
		t.Fatal("cve signature missing")
	}
	if len(cveSig.Anomalies) != 1 || cveSig.Anomalies[0] != "cve:CVE-2021-44228" {
		t.Errorf("cve sig anomalies = %v", cveSig.Anomalies)
	}
	if len(cveSig.EmulatedCVEs) != 1 || cveSig.EmulatedCVEs[0] != "CVE-2017-0144" {
		t.Errorf("cve sig emulated = %v", cveSig.EmulatedCVEs)
	}

	// Meta dimensions.
	if f.Cities["Oslo"] != 2 || f.Cities["Berlin"] != 1 {
		t.Errorf("cities = %v; want Oslo:2 Berlin:1", f.Cities)
	}
	if f.ASNOrgs["CF"] != 2 || f.ASNOrgs["DTAG"] != 1 {
		t.Errorf("asn_orgs = %v", f.ASNOrgs)
	}
	if f.Tools["nmap"] != 3 || f.Tools["hydra"] != 2 {
		t.Errorf("tools = %v; want nmap:3 hydra:2", f.Tools)
	}
	// ASN facets: AS13335 (count 2) and AS3320 (count 1); the asn:0 event (d) has
	// no asn so it is excluded.
	asnCounts := map[int]int{}
	for _, a := range f.ASNs {
		asnCounts[a.Num] = a.Count
	}
	if asnCounts[13335] != 2 || asnCounts[3320] != 1 {
		t.Errorf("asn facets = %+v; want 13335:2 3320:1", f.ASNs)
	}
	// Ports: 22 (×2), 8080 (×1), 9999 (×1).
	if f.Ports[22] != 2 || f.Ports[8080] != 1 || f.Ports[9999] != 1 {
		t.Errorf("ports = %v", f.Ports)
	}

	// The attack-signature cap is honoured.
	f2, err := s.DashboardFacets(ctx, now.Add(-time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(f2.Attacks) != 1 {
		t.Errorf("limit=1 returned %d signatures; want 1", len(f2.Attacks))
	}
}

func TestParseJSONStrings(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"null", nil},
		{`["a","b"]`, []string{"a", "b"}},
		{`[ "x", "y" ]`, []string{"x", "y"}}, // postgres ::text spacing
		{"not json", nil},
	}
	for _, c := range cases {
		got := ParseJSONStrings(c.in)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("ParseJSONStrings(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}
