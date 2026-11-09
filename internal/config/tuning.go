package config

import (
	"fmt"
	"time"
)

// Tuning holds performance knobs that are otherwise compile-time constants:
// the SQLite connection pool, the event-sink write-batch buffer, and the web-UI
// snapshot caches. Zero means "use the built-in default" for every field, so an
// absent `tuning:` block — or any unset field — leaves behaviour exactly as
// before; each consumer applies its own default when it reads a zero.
type Tuning struct {
	// StoreMaxOpenConns is the SQLite connection-pool size (database/sql
	// SetMaxOpenConns / SetMaxIdleConns). Default 12. Raise it on a busy sensor
	// with many concurrent UI / aggregation readers.
	StoreMaxOpenConns int `yaml:"store_max_open_conns"`

	// SinkBatch / SinkFlush / SinkHardCap tune the SQLite event sink's write
	// batching: flush at SinkBatch buffered events or after SinkFlush, whichever
	// comes first; above SinkHardCap writes go synchronous to bound memory.
	// Defaults 256 / 500ms / 8192.
	SinkBatch   int           `yaml:"sink_batch"`
	SinkFlush   time.Duration `yaml:"sink_flush"`
	SinkHardCap int           `yaml:"sink_hard_cap"`

	// UIDashboardTTL / UIAggCacheTTL / UIWindowCacheTTL set how long the web-UI
	// snapshot caches (dashboard build, /profiles rollup, shared window-event
	// scan) are served before a background refresh. Longer = less DB load, more
	// staleness. Defaults 20s / 5s / 3s.
	UIDashboardTTL   time.Duration `yaml:"ui_dashboard_ttl"`
	UIAggCacheTTL    time.Duration `yaml:"ui_agg_cache_ttl"`
	UIWindowCacheTTL time.Duration `yaml:"ui_window_cache_ttl"`

	// UIScanLimit caps how many of the newest events a single detail-page render
	// scans within the selected time window (events / attack / correlation /
	// captures / map / timeline / campaign / handler / tunnels / charts). The
	// store is NOT capped — this only bounds the per-render scan for
	// responsiveness. On a busy sensor the default means 7d/14d views show the
	// same newest N as 24h once a day already exceeds N; raise this to render
	// more history per page (at the cost of a slower page build). It also bounds
	// the dashboard's enrichment rollup — the summary aggregates the tactic / geo
	// / ASN / tool charts with SQL GROUP BY passes (store.DashboardFacets), so
	// there it bounds the distinct attack *signatures* returned (count-ordered).
	// Each page keeps its own default as a floor; this only raises them.
	// Default 20000.
	UIScanLimit int `yaml:"ui_scan_limit"`
}

// validate rejects negative knobs (a zero is "default", a positive value is an
// explicit override, a negative value is a mistake) and incoherent combinations.
func (t Tuning) validate() error {
	ints := []struct {
		name string
		v    int
	}{
		{"store_max_open_conns", t.StoreMaxOpenConns},
		{"sink_batch", t.SinkBatch},
		{"sink_hard_cap", t.SinkHardCap},
		{"ui_scan_limit", t.UIScanLimit},
	}
	for _, c := range ints {
		if c.v < 0 {
			return fmt.Errorf("tuning.%s must be >= 0 (0 = default), got %d", c.name, c.v)
		}
	}
	durs := []struct {
		name string
		v    time.Duration
	}{
		{"sink_flush", t.SinkFlush},
		{"ui_dashboard_ttl", t.UIDashboardTTL},
		{"ui_agg_cache_ttl", t.UIAggCacheTTL},
		{"ui_window_cache_ttl", t.UIWindowCacheTTL},
	}
	for _, c := range durs {
		if c.v < 0 {
			return fmt.Errorf("tuning.%s must be >= 0 (0 = default), got %s", c.name, c.v)
		}
	}
	// A hard cap below the batch size would never let a batch form.
	if t.SinkHardCap > 0 && t.SinkBatch > 0 && t.SinkHardCap < t.SinkBatch {
		return fmt.Errorf("tuning.sink_hard_cap (%d) must be >= tuning.sink_batch (%d)", t.SinkHardCap, t.SinkBatch)
	}
	return nil
}
