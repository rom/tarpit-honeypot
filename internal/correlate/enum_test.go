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
