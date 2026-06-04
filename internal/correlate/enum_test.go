package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func httpEvent(srcIP, path string, t time.Time) *event.Event {
	e := mkEvent(srcIP, 80, t)
	e.Handler = "http"
	e.Meta = map[string]any{"request_line": "GET " + path + " HTTP/1.1"}
	return e
}

func dnsEvent(srcIP, name string, t time.Time) *event.Event {
	e := mkEvent(srcIP, 53, t)
	e.Proto = "udp"
	e.Handler = "dns"
	e.Meta = map[string]any{"qname": name}
	return e
}

func aggregate(out []*event.Event, ruleID string) *event.Event {
	for _, e := range out {
		if e.RuleID == ruleID {
			return e
		}
	}
	return nil
}

func TestPathEnumerationFires(t *testing.T) {
	cor, err := New(config.Correlate{
		PathEnum: config.CorrPathEnum{Enabled: true, DistinctPaths: 5, Window: time.Minute, Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 5; i++ {
		last = cor.Observe(httpEvent("1.2.3.4", fmt.Sprintf("/admin%d", i), now.Add(time.Duration(i)*time.Second)))
	}
	agg := aggregate(last, "correlate:path_enumeration")
	if agg == nil {
		t.Fatalf("path_enumeration did not fire: %v", last)
	}
	if agg.Severity != event.SeverityHigh {
		t.Errorf("severity = %v; want high", agg.Severity)
	}
	// Repeating the SAME path must not advance the distinct count further.
	for i := 0; i < 5; i++ {
		cor.Observe(httpEvent("5.5.5.5", "/same", now.Add(time.Duration(i)*time.Second)))
	}
	out := cor.Observe(httpEvent("5.5.5.5", "/same", now))
	if aggregate(out, "correlate:path_enumeration") != nil {
		t.Errorf("a single repeated path must not trip path_enumeration")
	}
}

func TestDNSEnumerationFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		DNSEnum: config.CorrDNSEnum{Enabled: true, DistinctNames: 4, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 4; i++ {
		last = cor.Observe(dnsEvent("9.9.9.9", fmt.Sprintf("host%d.corp.local", i), now.Add(time.Duration(i)*time.Second)))
	}
	agg := aggregate(last, "correlate:dns_enumeration")
	if agg == nil {
		t.Fatalf("dns_enumeration did not fire: %v", last)
	}
	if agg.Meta["distinct_names"].(int) < 4 {
		t.Errorf("distinct_names = %v; want >= 4", agg.Meta["distinct_names"])
	}
}

func TestBeaconFiresOnRegularInterval(t *testing.T) {
	cor, _ := New(config.Correlate{
		Beacon: config.CorrBeacon{Enabled: true, MinHits: 6, MaxJitterPct: 20, Window: time.Hour, Severity: "high"},
	})
	base := time.Now().UTC()
	var last []*event.Event
	// Six contacts spaced exactly 10s apart — a textbook beacon.
	for i := 0; i < 6; i++ {
		last = cor.Observe(mkEvent("7.7.7.7", 443, base.Add(time.Duration(i)*10*time.Second)))
	}
	agg := aggregate(last, "correlate:beacon")
	if agg == nil {
		t.Fatalf("beacon did not fire on regular interval: %v", last)
	}
	if agg.Meta["interval_s"].(int) != 10 {
		t.Errorf("interval_s = %v; want 10", agg.Meta["interval_s"])
	}
}

// A sleep-with-jitter beacon (Cobalt Strike / Sliver) has per-interval jitter
// that exceeds MaxJitterPct yet still clusters in a tight band — the jittered
// detection path must catch it.
func TestBeaconFiresOnJitteredInterval(t *testing.T) {
	cor, _ := New(config.Correlate{
		Beacon: config.CorrBeacon{Enabled: true, MinHits: 6, MaxJitterPct: 20, Window: time.Hour, Severity: "high"},
	})
	base := time.Now().UTC()
	// ~60s sleep with heavy jitter: intervals 40..80s (stddev jitter >20%, but
	// max/min band ratio = 2.0 <= 3.0). 8 contacts (the jittered path needs >=8).
	offsets := []int{0, 40, 120, 165, 240, 290, 360, 402}
	var all []*event.Event
	for _, off := range offsets {
		all = append(all, cor.Observe(mkEvent("9.9.9.9", 443, base.Add(time.Duration(off)*time.Second)))...)
	}
	agg := aggregate(all, "correlate:beacon")
	if agg == nil {
		t.Fatalf("jittered beacon did not fire: %v", all)
	}
	if agg.Meta["jittered"] != true {
		t.Errorf("expected jittered=true, got %v", agg.Meta["jittered"])
	}
}

func TestBeaconIgnoresIrregularAndBursts(t *testing.T) {
	cor, _ := New(config.Correlate{
		Beacon: config.CorrBeacon{Enabled: true, MinHits: 5, MaxJitterPct: 15, Window: time.Hour, Severity: "high"},
	})
	base := time.Now().UTC()
	// Wildly irregular gaps → high jitter, no beacon.
	offsets := []int{0, 1, 30, 31, 600}
	var last []*event.Event
	for _, off := range offsets {
		last = cor.Observe(mkEvent("8.8.8.8", 443, base.Add(time.Duration(off)*time.Second)))
	}
	if aggregate(last, "correlate:beacon") != nil {
		t.Errorf("irregular timing must not fire a beacon")
	}

	// A sub-second burst (scan) must not be classed as a beacon either.
	cor2, _ := New(config.Correlate{
		Beacon: config.CorrBeacon{Enabled: true, MinHits: 5, MaxJitterPct: 50, Window: time.Hour, Severity: "high"},
	})
	for i := 0; i < 6; i++ {
		last = cor2.Observe(mkEvent("8.8.8.9", 443, base.Add(time.Duration(i)*10*time.Millisecond)))
	}
	if aggregate(last, "correlate:beacon") != nil {
		t.Errorf("sub-second burst must not fire a beacon")
	}
}

func TestHTTPEventPath(t *testing.T) {
	if got := httpEventPath(&event.Event{Meta: map[string]any{"http_path": "/x"}}); got != "/x" {
		t.Errorf("http_path = %q; want /x", got)
	}
	if got := httpEventPath(&event.Event{Meta: map[string]any{"request_line": "POST /y?z=1 HTTP/1.1"}}); got != "/y" {
		t.Errorf("request_line path = %q; want /y", got)
	}
	if got := httpEventPath(&event.Event{Meta: map[string]any{}}); got != "" {
		t.Errorf("no path should yield empty, got %q", got)
	}
}
