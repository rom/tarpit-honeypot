package sensor

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

const firstSeenCap = 200000

// observeFirstSeen emits source:first_seen the first time a source produces
// a >= medium-severity detection event in this run (gated so connects /
// low-noise scans don't each fire). Bus-loop-only — no lock on
// seenSources. Returns nil when disabled, already seen, or below the gate.
func (s *Sensor) observeFirstSeen(ev *event.Event) *event.Event {
	if !s.curConfig().Sensor.Alerts.FirstSeen || ev == nil || ev.Source.IP == "" || ev.Severity < event.SeverityMedium {
		return nil
	}
	// Don't fire on our own synthetic / operational events.
	if strings.HasPrefix(ev.RuleID, "source:") || strings.HasPrefix(ev.RuleID, "risk:") || strings.HasPrefix(ev.RuleID, "sensor:") {
		return nil
	}
	if _, ok := s.seenSources[ev.Source.IP]; ok {
		return nil
	}
	if len(s.seenSources) < firstSeenCap {
		s.seenSources[ev.Source.IP] = struct{}{}
	}
	e := &event.Event{
		ID:       event.NewID(),
		Time:     timeNow(),
		Sensor:   s.name,
		RuleID:   "source:first_seen",
		Severity: event.SeverityMedium,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta:     map[string]any{"trigger_rule": ev.RuleID},
	}
	if s.enrich != nil {
		s.enrich.Decorate(e)
	}
	return e
}

// runHealthMonitor periodically checks data_dir disk usage and sink drop
// counts, emitting sensor:health when the disk crosses the warn threshold
// (with hysteresis) or sinks start dropping events. Always on.
func (s *Sensor) runHealthMonitor(ctx context.Context) {
	warnPct := s.curConfig().Sensor.Alerts.DiskWarnPercent
	if warnPct <= 0 {
		warnPct = 90
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	var lastDrops int64
	diskWarned := false
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ticks++
			// Index self-heal: every ~30 min re-create any missing secondary
			// index (one may have failed to build during a full-disk window)
			// and flag persistent gaps — a missing index is why aggregate pages
			// full-scan and time out on a large store.
			// Index self-heal is a SQLite-specific concern (the embedded store's
			// secondary indexes can fail to build during a full-disk window). It is
			// exposed only on that backend, so reach it through an optional
			// interface; the PostgreSQL backend manages indexes in its schema and
			// does not implement it.
			if ih, ok := s.store.(interface {
				EnsureIndexes() int
				MissingIndexes() []string
			}); ok && ticks%30 == 1 {
				ih.EnsureIndexes()
				if miss := ih.MissingIndexes(); len(miss) > 0 {
					slog.Warn("store: secondary indexes missing (pages may full-scan)", "missing", miss)
					s.emitOpEvent("sensor:health", event.SeverityMedium, map[string]any{
						"check": "db_indexes", "missing": miss,
					})
				}
			}
			if used, ok := diskUsedPercent(s.curConfig().Sensor.DataDir); ok {
				switch {
				case used >= warnPct && !diskWarned:
					s.emitOpEvent("sensor:health", event.SeverityHigh, map[string]any{
						"check": "disk", "data_dir_used_percent": used, "threshold": warnPct,
					})
					diskWarned = true
				case used < warnPct-5: // hysteresis so we don't flap
					diskWarned = false
				}
			}
			var drops int64
			for _, st := range s.curRouter().Stats() {
				drops += st.Dropped
			}
			if drops > lastDrops {
				s.emitOpEvent("sensor:health", event.SeverityMedium, map[string]any{
					"check": "sink_drops", "dropped_total": drops, "dropped_new": drops - lastDrops,
				})
				lastDrops = drops
			}
		}
	}
}

// runDigest emits a periodic sensor:digest summarising the window (event
// totals by severity, top rules, and top risk sources). Off when the
// interval is 0 or there's no store to summarise from.
func (s *Sensor) runDigest(ctx context.Context) {
	interval := s.curConfig().Sensor.Alerts.DigestInterval
	if interval <= 0 || s.store == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			sum, err := s.store.Summary(cctx, time.Now().Add(-interval))
			cancel()
			if err != nil {
				continue
			}
			meta := map[string]any{
				"window":      interval.String(),
				"total":       sum.Total,
				"by_severity": sum.BySeverity,
				"top_rules":   sum.ByRule,
			}
			if s.risk != nil {
				meta["top_risk_sources"] = s.risk.Top(10, timeNow())
			}
			s.emitOpEvent("sensor:digest", event.SeverityLow, meta)
		}
	}
}
