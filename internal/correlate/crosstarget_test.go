package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestCrossTargetFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		CrossTarget: config.CorrCrossTarget{Enabled: true, DistinctTargets: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()

	// One source hits three target IPs, port 22 on all three (a fleet sweep of
	// the same service) plus 445 on the second — spread over a few seconds.
	feed := func(dst string, port int, dt time.Duration) []*event.Event {
		ev := mkEvent("203.0.113.9", port, now.Add(dt))
		ev.Dest.IP = dst
		return cor.Observe(ev)
	}
	feed("10.0.0.10", 22, 0)
	feed("10.0.0.11", 22, 2*time.Second)
	feed("10.0.0.11", 445, 3*time.Second)
	res := feed("10.0.0.12", 22, 5*time.Second)

	agg := aggregate(res, "correlate:cross_target")
	if agg == nil {
		t.Fatalf("cross_target did not fire: %v", res)
	}
	if agg.Meta["distinct_targets"].(int) != 3 {
		t.Errorf("distinct_targets = %v; want 3", agg.Meta["distinct_targets"])
	}
	// Order is first-seen.
	targets := agg.Meta["targets"].([]string)
	want := []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"}
	for i := range want {
		if i >= len(targets) || targets[i] != want[i] {
			t.Fatalf("targets = %v; want %v (first-seen order)", targets, want)
		}
	}
	// Port 22 hit all three targets -> shared; 445 only one -> not shared.
	shared := agg.Meta["shared_ports"].([]int)
	if len(shared) != 1 || shared[0] != 22 {
		t.Errorf("shared_ports = %v; want [22]", shared)
	}
	// Timeline carries per-target timing + ports, ordered.
	tl := agg.Meta["target_timeline"].([]map[string]any)
	if len(tl) != 3 {
		t.Fatalf("timeline len = %d; want 3", len(tl))
	}
	if tl[0]["first_offset_s"].(int) != 0 || tl[2]["first_offset_s"].(int) != 5 {
		t.Errorf("timeline offsets wrong: %v / %v", tl[0]["first_offset_s"], tl[2]["first_offset_s"])
	}
}

func TestCrossTargetBelowThreshold(t *testing.T) {
	cor, _ := New(config.Correlate{
		CrossTarget: config.CorrCrossTarget{Enabled: true, DistinctTargets: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		ev := mkEvent("203.0.113.9", 22, now.Add(time.Duration(i)*time.Second))
		ev.Dest.IP = fmt.Sprintf("10.0.0.%d", 10+i)
		if aggregate(cor.Observe(ev), "correlate:cross_target") != nil {
			t.Fatal("cross_target fired below DistinctTargets")
		}
	}
}
