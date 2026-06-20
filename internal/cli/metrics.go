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
		// SQLite store size — a file-backed metric, so it is exposed only by the
		// SQLite store (via the optional Path() method); the PostgreSQL backend has
		// no local file to stat.
		if fp, ok := s.Store().(interface{ Path() string }); ok {
			if info, err := os.Stat(filepath.Clean(fp.Path())); err == nil {
				out.Samples = append(out.Samples, ui.Sample{
					Name:  "tarpit_store_db_bytes",
					Help:  "On-disk size of the SQLite events.db",
					Type:  "gauge",
					Value: float64(info.Size()),
				})
			}
		}
		// AF_PACKET sniffer L2 frame counters (present only when running).
		if st, ok := s.SnifferStats(); ok {
			for proto, n := range map[string]uint64{
				"all": st.Frames, "arp": st.ARP, "ipv4": st.IPv4, "ipv6": st.IPv6,
				"tcp": st.TCP, "udp": st.UDP, "icmp": st.ICMP, "other": st.Other,
			} {
				out.Samples = append(out.Samples, ui.Sample{
					Name:   "tarpit_sniffer_frames_total",
					Help:   "L2 frames the AF_PACKET sniffer captured, partitioned by protocol",
					Type:   "counter",
					Labels: map[string]string{"proto": proto},
					Value:  float64(n),
				})
			}
		}
		// data_dir filesystem usage (statfs; absent on non-unix).
		if used, ok := s.DiskUsedPercent(); ok {
			out.Samples = append(out.Samples, ui.Sample{
				Name:  "tarpit_disk_used_percent",
				Help:  "data_dir filesystem usage percent",
				Type:  "gauge",
				Value: float64(used),
			})
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
