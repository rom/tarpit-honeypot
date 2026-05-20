package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestICMPSweepFires(t *testing.T) {
	c, err := New(config.Correlate{
		ICMPSweep: config.CorrICMPSweep{
			Enabled:     true,
			DistinctIPs: 5,
			Window:      30 * time.Second,
			Severity:    "high",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.9"}
	now := time.Now().UTC()
	var fired *event.Event
	for i := 1; i <= 5; i++ {
		ev := &event.Event{
			Source: src,
			Dest:   event.Endpoint{IP: "10.0.0." + itoa(i)},
			Proto:  "icmp",
			Time:   now.Add(time.Duration(i) * time.Second),
			RuleID: "icmp:echo",
		}
		for _, out := range c.Observe(ev) {
			if out.RuleID == "correlate:icmp_sweep" {
				fired = out
			}
		}
	}
	if fired == nil {
		t.Fatal("icmp_sweep did not fire after 5 distinct destinations")
	}
	if got, _ := fired.Meta["distinct_ips"].(int); got != 5 {
		t.Errorf("distinct_ips = %v; want 5", fired.Meta["distinct_ips"])
	}
}

func TestICMPSweepNeedsDistinctIPs(t *testing.T) {
	c, _ := New(config.Correlate{
		ICMPSweep: config.CorrICMPSweep{Enabled: true, DistinctIPs: 5, Window: 30 * time.Second, Severity: "high"},
	})
	src := event.Endpoint{IP: "203.0.113.9"}
	now := time.Now().UTC()
	// 10 pings to the SAME destination must not trip the sweep.
	for i := 0; i < 10; i++ {
		ev := &event.Event{
			Source: src,
			Dest:   event.Endpoint{IP: "10.0.0.1"},
			Proto:  "icmp",
			Time:   now.Add(time.Duration(i) * time.Second),
		}
		for _, out := range c.Observe(ev) {
			if out.RuleID == "correlate:icmp_sweep" {
				t.Fatal("sweep fired on a single destination")
			}
		}
	}
}

func TestICMPSweepDisabledIsNoOp(t *testing.T) {
	c, _ := New(config.Correlate{}) // sweep disabled
	src := event.Endpoint{IP: "203.0.113.9"}
	now := time.Now().UTC()
	for i := 1; i <= 20; i++ {
		ev := &event.Event{
			Source: src,
			Dest:   event.Endpoint{IP: "10.0.0." + itoa(i)},
			Proto:  "icmp",
			Time:   now,
		}
		got := c.Observe(ev)
		if len(got) != 1 {
			t.Fatalf("disabled sweep produced extra events: %d", len(got))
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
