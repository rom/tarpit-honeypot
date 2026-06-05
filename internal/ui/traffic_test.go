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

func decodeLine(t *testing.T, f chartFig) ([]chPoint, string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(f.B64)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	var d lineFigData
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(d.Series) != 1 {
		t.Fatalf("want 1 series, got %d", len(d.Series))
	}
	return d.Series[0].Points, d.XType
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
	if len(figs) != 4 {
		t.Fatalf("want 4 figures, got %d", len(figs))
	}
	wantTitles := []string{
		"Incoming network traffic (kb/s)",
		"Outgoing network traffic (kb/s)",
		"Incoming network traffic (packets/s)",
		"Outgoing network traffic (packets/s)",
	}
	for i, w := range wantTitles {
		if figs[i].Title != w {
			t.Errorf("fig[%d] title = %q, want %q", i, figs[i].Title, w)
		}
		if figs[i].Type != "line" {
			t.Errorf("fig[%d] type = %q, want line", i, figs[i].Type)
		}
	}

	type check struct {
		fig  int
		want float64
	}
	for _, c := range []check{{0, 0.8}, {1, 0.04}, {2, 1.0}, {3, 0.5}} {
		pts, xtype := decodeLine(t, figs[c.fig])
		if len(pts) != 3 {
			t.Fatalf("fig[%d]: want 3 points, got %d", c.fig, len(pts))
		}
		if xtype != "time" {
			t.Errorf("fig[%d]: xType = %q, want time", c.fig, xtype)
		}
		if pts[0].Y != c.want {
			t.Errorf("fig[%d] point0.Y = %v, want %v", c.fig, pts[0].Y, c.want)
		}
		if pts[1].Y != 0 || pts[2].Y != 0 {
			t.Errorf("fig[%d] idle buckets should be 0: %+v", c.fig, pts)
		}
		// x-axis aligned to the bucket grid.
		if pts[0].X != float64(t0.UnixMilli()) {
			t.Errorf("fig[%d] point0.X = %v, want %v", c.fig, pts[0].X, float64(t0.UnixMilli()))
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
	if len(figs) != 4 {
		t.Fatalf("want 4 figures, got %d", len(figs))
	}
	if !strings.Contains(figs[0].Title, "Mb/s") {
		t.Errorf("expected Mb/s unit at 1 Mb/s peak, title = %q", figs[0].Title)
	}
	pts, _ := decodeLine(t, figs[0])
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
