package cli

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rom/tarpit-honeypot/internal/safego"
	"github.com/rom/tarpit-honeypot/internal/sensor"
	"github.com/rom/tarpit-honeypot/internal/ui"
	"github.com/rom/tarpit-honeypot/internal/version"
)

var sensorStarted = time.Now()

// buildStatsProvider returns a ui.StatsProvider closure that snapshots the
// router + sensor state into a Prometheus-format Metrics struct.
//
// Exposed metrics:
//
//	tarpit_sink_dropped_total{channel=...}     - events dropped at the
//	  in-channel cap (queue full).
//	tarpit_sink_failed_total{channel=...}      - events that exhausted the
//	  retry backlog and were lost.
//	tarpit_sink_retried_total{channel=...}     - events delivered on retry
//	  after a transient sink error.
//	tarpit_honeynet_hosts                      - count of configured
//	  virtual hosts across all honeynets.
//	tarpit_honeynet_networks                   - count of configured
//	  honeynets.
//	tarpit_store_db_bytes                      - on-disk size of the
//	  SQLite events.db (0 if no store configured).
func buildStatsProvider(s *sensor.Sensor) ui.StatsProvider {
	return func() ui.Metrics {
		out := ui.Metrics{}
		// Per-channel router stats. Three sample names share one HELP/TYPE
		// group per name so prometheus parsers don't complain.
		for chID, st := range s.Router().Stats() {
			out.Samples = append(out.Samples,
				ui.Sample{
					Name:   "tarpit_sink_dropped_total",
					Help:   "Events dropped because the sink in-channel was full",
					Type:   "counter",
					Labels: map[string]string{"channel": chID},
					Value:  float64(st.Dropped),
				},
				ui.Sample{
					Name:   "tarpit_sink_failed_total",
					Help:   "Events that exhausted the retry backlog and were lost",
					Type:   "counter",
					Labels: map[string]string{"channel": chID},
					Value:  float64(st.Failed),
				},
				ui.Sample{
					Name:   "tarpit_sink_retried_total",
					Help:   "Events delivered on retry after a transient sink error",
					Type:   "counter",
					Labels: map[string]string{"channel": chID},
					Value:  float64(st.Retried),
				},
			)
		}
		// Honeynet topology counts.
		if topo := s.Honeynet(); topo != nil {
			out.Samples = append(out.Samples,
				ui.Sample{
					Name:  "tarpit_honeynet_networks",
					Help:  "Number of configured honeynets",
					Type:  "gauge",
					Value: float64(len(topo.Networks())),
				},
				ui.Sample{
					Name:  "tarpit_honeynet_hosts",
					Help:  "Number of configured virtual hosts across all honeynets",
					Type:  "gauge",
					Value: float64(len(topo.HostsInNetwork(""))),
				},
			)
		}
		// SQLite store size.
		if st := s.Store(); st != nil {
			if info, err := os.Stat(filepath.Clean(st.Path())); err == nil {
				out.Samples = append(out.Samples, ui.Sample{
					Name:  "tarpit_store_db_bytes",
					Help:  "On-disk size of the SQLite events.db",
					Type:  "gauge",
					Value: float64(info.Size()),
				})
			}
		}
		// Process metrics.
		out.Samples = append(out.Samples,
			ui.Sample{
				Name:   "tarpit_build_info",
				Help:   "Build info (always 1; labels carry version/commit)",
				Type:   "gauge",
				Labels: map[string]string{"version": version.Version, "commit": version.Commit},
				Value:  1,
			},
			ui.Sample{
				Name:  "tarpit_uptime_seconds",
				Help:  "Process uptime in seconds since first /metrics call",
				Type:  "gauge",
				Value: time.Since(sensorStarted).Seconds(),
			},
			ui.Sample{
				Name:  "tarpit_panic_recoveries_total",
				Help:  "Total recovered panics across all goroutines wrapped by safego",
				Type:  "counter",
				Value: float64(safego.PanicCount()),
			},
		)
		for name, n := range safego.PanicCountByName() {
			out.Samples = append(out.Samples, ui.Sample{
				Name:   "tarpit_panic_recoveries_by_name_total",
				Help:   "Recovered panics partitioned by the safego name",
				Type:   "counter",
				Labels: map[string]string{"name": name},
				Value:  float64(n),
			})
		}
		return out
	}
}
