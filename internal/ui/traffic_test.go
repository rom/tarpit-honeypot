package ui

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

type lineFigData struct {
	Series []struct {
		Name   string    `json:"name"`
		Color  string    `json:"color"`
		Points []chPoint `json:"points"`
	} `json:"series"`
	XType string `json:"xType"`
}

func decodeLineFig(t *testing.T, f chartFig) lineFigData {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(f.B64)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	var d lineFigData
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("json: %v", err)
	}
	return d
}

// seriesByName returns the points of the named series.
func (d lineFigData) seriesByName(t *testing.T, name string) []chPoint {
	t.Helper()
	for _, s := range d.Series {
		if s.Name == name {
			return s.Points
		}
	}
	t.Fatalf("series %q not found", name)
	return nil
}

func threeHourGrid(t0 time.Time) []store.HourBucket {
	return []store.HourBucket{
		{Hour: t0},
		{Hour: t0.Add(time.Hour)},
		{Hour: t0.Add(2 * time.Hour)},
	}
}

func TestTrafficChartsRatesAndUnits(t *testing.T) {
	t0 := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	hours := threeHourGrid(t0)
	// One connection in the first bucket: 360000 B in / 18000 B out over the
	// hour → 100 B/s in (0.8 kb/s), 5 B/s out (0.04 kb/s); 3600 pkts in
	// (1.0 pkt/s), 1800 pkts out (0.5 pkt/s).
	evs := []*event.Event{{
		Time: t0.Add(5 * time.Minute),
		Meta: map[string]any{
			"bytes_in": int64(360000), "bytes_out": int64(18000),
			"pkts_in": int64(3600), "pkts_out": int64(1800),
		},
	}}

	figs := trafficCharts(evs, hours)
	// Two charts now: throughput (in+out) and packet-rate (in+out), each with
	// both directions as series in the SAME graph.
	if len(figs) != 2 {
		t.Fatalf("want 2 figures, got %d", len(figs))
	}
	if !strings.Contains(figs[0].Title, "kb/s") || !strings.Contains(figs[1].Title, "packets/s") {
		t.Errorf("titles: %q / %q", figs[0].Title, figs[1].Title)
	}
	tp := decodeLineFig(t, figs[0]) // throughput
	pk := decodeLineFig(t, figs[1]) // packet rate
	if len(tp.Series) != 2 || len(pk.Series) != 2 {
		t.Fatalf("each chart must carry incoming+outgoing series; got %d / %d", len(tp.Series), len(pk.Series))
	}
	if tp.XType != "time" {
		t.Errorf("xType = %q", tp.XType)
	}
	type check struct {
		fig  lineFigData
		name string
		want float64
	}
	for _, c := range []check{
		{tp, "incoming", 0.8}, {tp, "outgoing", 0.04},
		{pk, "incoming", 1.0}, {pk, "outgoing", 0.5},
	} {
		pts := c.fig.seriesByName(t, c.name)
		if len(pts) != 3 || pts[0].Y != c.want || pts[1].Y != 0 || pts[2].Y != 0 {
			t.Errorf("%s series wrong: %+v (want point0=%v)", c.name, pts, c.want)
		}
		if pts[0].X != float64(t0.UnixMilli()) {
			t.Errorf("%s point0.X = %v, want %v", c.name, pts[0].X, float64(t0.UnixMilli()))
		}
	}
}

func TestTrafficChartsAutoScalesToMbps(t *testing.T) {
	t0 := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	hours := threeHourGrid(t0)
	// 450,000,000 B over the hour = 125,000 B/s = exactly 1 Mb/s.
	evs := []*event.Event{{
		Time: t0.Add(time.Minute),
		Meta: map[string]any{"bytes_in": int64(450000000), "bytes_out": int64(0)},
	}}
	figs := trafficCharts(evs, hours)
	if len(figs) != 2 {
		t.Fatalf("want 2 figures, got %d", len(figs))
	}
	if !strings.Contains(figs[0].Title, "Mb/s") {
		t.Errorf("expected Mb/s unit at 1 Mb/s peak, title = %q", figs[0].Title)
	}
	pts := decodeLineFig(t, figs[0]).seriesByName(t, "incoming")
	if pts[0].Y != 1.0 {
		t.Errorf("incoming throughput = %v Mb/s, want 1.0", pts[0].Y)
	}
}

func TestTrafficChartsEmptyWithoutCounters(t *testing.T) {
	t0 := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	hours := threeHourGrid(t0)
	evs := []*event.Event{{Time: t0.Add(time.Minute), Meta: map[string]any{"foo": "bar"}}}
	if figs := trafficCharts(evs, hours); figs != nil {
		t.Errorf("expected nil when no traffic counters present, got %d figs", len(figs))
	}
}

func TestAttacksByService(t *testing.T) {
	ev := func(handler, sev string, anoms ...string) *event.Event {
		s, _ := event.ParseSeverity(sev)
		return &event.Event{Handler: handler, Severity: s, Anomalies: anoms, Meta: map[string]any{}}
	}
	evs := []*event.Event{
		ev("ssh", "low", "brute-force"),  // attack (anomaly)
		ev("ssh", "high"),                // attack (severity)
		ev("http", "low", "webapp:sqli"), // attack
		ev("http", "low"),                // benign — not counted
		ev("dns", "low"),                 // benign
	}
	sl := attacksByService(evs)
	got := map[string]int{}
	for _, s := range sl {
		got[s.Label] = s.Value
	}
	if got["ssh"] != 2 || got["http"] != 1 {
		t.Errorf("attacks-by-service = %v, want ssh:2 http:1", got)
	}
	if _, ok := got["dns"]; ok {
		t.Error("benign dns event must not count as an attack")
	}
}
