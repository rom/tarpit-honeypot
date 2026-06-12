package store

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Negated + multi-value filters (events-page negation, charts include/exclude):
// rule_id / src_ip / asn IN and NOT IN, composed across dimensions, with the
// no-ASN row correctly surviving an ASN exclusion.
func TestQueryIncludeExcludeMulti(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)

	mk := func(id, ip, rule string, asn uint32, off int) {
		e := mkEvent(id, ip, rule, event.SeverityHigh, base.Add(time.Duration(off)*time.Minute))
		e.Meta = map[string]any{"asn": asn, "geo_country": "US"}
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "1.1.1.1", "sniffer:arp_scan", 100, 1)
	mk("b", "2.2.2.2", "sniffer:arp_scan", 200, 2)
	mk("c", "3.3.3.3", "webapp:sqli", 200, 3)
	mk("d", "4.4.4.4", "ssh:bruteforce", 300, 4)
	// One event carrying no ASN meta at all — it must survive ASN exclusion.
	noasn := mkEvent("e", "5.5.5.5", "ssh:bruteforce", event.SeverityHigh, base.Add(5*time.Minute))
	noasn.Meta = map[string]any{"note": "x"}
	if err := s.Insert(ctx, noasn); err != nil {
		t.Fatal(err)
	}

	since := base.Add(-time.Minute)
	ids := func(f Filter) map[string]bool {
		f.Since, f.Limit = since, 100
		evs, err := s.Query(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, ev := range evs {
			got[ev.ID] = true
		}
		return got
	}

	// Negation: everything EXCEPT rule sniffer:arp_scan.
	if got := ids(Filter{ExcludeRuleIDs: []string{"sniffer:arp_scan"}}); got["a"] || got["b"] || !got["c"] || !got["d"] || !got["e"] {
		t.Errorf("exclude rule: got %v", got)
	}
	// Multiple exclusions across dimensions: drop rule arp_scan AND ip 4.4.4.4,
	// leaving c (webapp:sqli) and e (ssh:bruteforce / no ASN).
	if got := ids(Filter{ExcludeRuleIDs: []string{"sniffer:arp_scan"}, ExcludeSourceIPs: []string{"4.4.4.4"}}); got["a"] || got["b"] || !got["c"] || got["d"] || !got["e"] {
		t.Errorf("exclude rule+ip: want c+e, got %v", got)
	}
	// Multi include (OR within a dimension): rule in {webapp:sqli, ssh:bruteforce}.
	if got := ids(Filter{RuleIDs: []string{"webapp:sqli", "ssh:bruteforce"}}); got["a"] || got["b"] || !got["c"] || !got["d"] || !got["e"] {
		t.Errorf("multi include rule: got %v", got)
	}
	// Exclude two ASNs; the row with no ASN (e) must remain.
	if got := ids(Filter{ExcludeASNs: []int{100, 200}}); got["a"] || got["b"] || got["c"] || !got["d"] || !got["e"] {
		t.Errorf("exclude ASNs: got %v", got)
	}
	// Include two ASNs (OR); the no-ASN row must NOT match.
	if got := ids(Filter{ASNs: []int{100, 300}}); !got["a"] || got["b"] || got["c"] || !got["d"] || got["e"] {
		t.Errorf("include ASNs: got %v", got)
	}
	// Multiple source-IP includes (OR).
	if got := ids(Filter{SourceIPs: []string{"1.1.1.1", "3.3.3.3"}}); !got["a"] || got["b"] || !got["c"] || got["d"] || got["e"] {
		t.Errorf("multi include ip: got %v", got)
	}
}
