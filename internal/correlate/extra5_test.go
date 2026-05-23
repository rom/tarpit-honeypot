package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDestructiveActionFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		DestructiveAction: config.CorrDestructiveAction{Enabled: true, Events: 2, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"redis-flush", "memcached-flush"} {
		ev := mkEvent("1.2.3.4", 6379+i, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:destructive_action") == nil {
		t.Fatalf("destructive_action did not fire: %v", last)
	}
	// A non-destructive anomaly must not contribute.
	ev := mkEvent("5.6.7.8", 80, now)
	ev.Anomalies = []string{"http-login-attempt"}
	if aggregate(cor.Observe(ev), "correlate:destructive_action") != nil {
		t.Error("a login attempt should not trip destructive_action")
	}
}

func TestHoneytokenSpreadFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		HoneytokenSpread: config.CorrHoneytokenSpread{Enabled: true, DistinctSources: 3, Window: time.Hour, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent(fmt.Sprintf("198.51.100.%d", 20+i), 80, now.Add(time.Duration(i)*time.Second))
		ev.RuleID = "canary:url:leaked-admin"
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:honeytoken_spread")
	if agg == nil {
		t.Fatalf("honeytoken_spread did not fire: %v", last)
	}
	if agg.Meta["token"] != "url:leaked-admin" || agg.Meta["distinct_sources"].(int) != 3 {
		t.Errorf("honeytoken_spread meta = %v", agg.Meta)
	}
}

func TestToolRotationFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ToolRotation: config.CorrToolRotation{Enabled: true, DistinctTools: 3, Window: time.Hour, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"vulnerability-scanner", "c2-framework", "tool:nuclei"} {
		ev := mkEvent("9.9.9.9", 443, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:tool_rotation")
	if agg == nil {
		t.Fatalf("tool_rotation did not fire: %v", last)
	}
	if agg.Meta["distinct_tools"].(int) != 3 {
		t.Errorf("distinct_tools = %v; want 3", agg.Meta["distinct_tools"])
	}
}
