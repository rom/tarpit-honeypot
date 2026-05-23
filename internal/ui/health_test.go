package ui

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestBuildHealthView(t *testing.T) {
	m := &Metrics{Samples: []Sample{
		{Name: "tarpit_uptime_seconds", Value: 90061}, // 1d 1h 1m
		{Name: "tarpit_store_db_bytes", Value: 5 * 1024 * 1024},
		{Name: "tarpit_disk_used_percent", Value: 73},
		{Name: "tarpit_panic_recoveries_total", Value: 0},
		{Name: "tarpit_honeynet_networks", Value: 2},
		{Name: "tarpit_honeynet_hosts", Value: 9},
		{Name: "tarpit_sink_dropped_total", Labels: map[string]string{"channel": "webhook"}, Value: 4},
		{Name: "tarpit_sink_failed_total", Labels: map[string]string{"channel": "webhook"}, Value: 1},
		{Name: "tarpit_sink_retried_total", Labels: map[string]string{"channel": "webhook"}, Value: 7},
	}}
	v := buildHealthView(m, store.Summary{Total: 1234, ByProto: map[string]int{"tcp": 900, "udp": 300}})

	if !v.Available {
		t.Fatal("should be available with a metrics snapshot")
	}
	if v.Uptime != "1d 1h 1m" {
		t.Errorf("uptime = %q; want 1d 1h 1m", v.Uptime)
	}
	if v.DBSize != "5.0 MiB" {
		t.Errorf("db size = %q; want 5.0 MiB", v.DBSize)
	}
	if !v.DiskKnown || v.DiskPct != 73 {
		t.Errorf("disk = %d known=%v; want 73 true", v.DiskPct, v.DiskKnown)
	}
	if v.Events24h != 1234 || v.HoneyHosts != 9 {
		t.Errorf("events/hosts wrong: %+v", v)
	}
	if len(v.Sinks) != 1 || v.Sinks[0].Dropped != 4 || v.DropTotal != 4 || v.FailTotal != 1 {
		t.Errorf("sink stats wrong: %+v", v.Sinks)
	}
	if v.Goroutines < 1 || v.GoVersion == "" {
		t.Errorf("runtime stats not populated: %+v", v)
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "health", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"sensor health", "1d 1h 1m", "5.0 MiB", "73% used", "webhook", "dropped"} {
		if !strings.Contains(html, want) {
			t.Errorf("health page missing %q", want)
		}
	}
	// The drop/fail warning must show.
	if !strings.Contains(html, "events were lost") {
		t.Errorf("expected drop/fail warning")
	}
}

func TestBuildHealthViewNoMetrics(t *testing.T) {
	v := buildHealthView(nil, store.Summary{})
	if v.Available {
		t.Error("should not be available without a metrics snapshot")
	}
	if v.GoVersion == "" {
		t.Error("runtime stats should still populate")
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "health", v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "metrics provider not wired") {
		t.Error("should note metrics unavailable")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 512: "512 B", 2048: "2.0 KiB", 5 * 1024 * 1024: "5.0 MiB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q; want %q", in, got, want)
		}
	}
}
