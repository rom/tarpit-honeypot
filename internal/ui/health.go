package ui

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/store"
)

// Sensor health dashboard. Sources: the stats provider (uptime, DB size,
// per-sink dropped/failed/retried, panic recoveries, disk %, honeynet
// counts), the Go runtime (the UI runs in the sensor process, so memory /
// goroutines / GC are live), and the event store (recent volume).

type healthView struct {
	Available   bool // stats provider wired?
	Version     string
	Commit      string
	Uptime      string
	GoVersion   string
	GOMAXPROCS  int
	NumCPU      int
	Goroutines  int
	MemAllocMB  float64
	MemSysMB    float64
	HeapObjects uint64
	NextGCMB    float64
	GCPauseMs   float64
	NumGC       uint32
	Panics      int
	PanicByName []counter // recovered panics partitioned by safego name
	DBBytes     int64
	DBSize      string
	DiskPct     int
	DiskKnown   bool
	Events24h   int
	ByProto     []counter // 24h event volume by transport
	HoneyNets   int
	HoneyHosts  int
	Sinks       []sinkHealth
	DropTotal   int
	FailTotal   int
	// SnifferActive + Frames are the AF_PACKET L2 frame counters.
	SnifferActive bool
	Frames        []counter
	Charts        []chartFig
}

type sinkHealth struct {
	Channel string
	Dropped int
	Failed  int
	Retried int
}

// buildHealthView turns a metrics snapshot + runtime + event summary into the
// health model. metrics may be nil (stats provider not wired).
func buildHealthView(m *Metrics, sum store.Summary) healthView {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	v := healthView{
		GoVersion:   runtime.Version(),
		GOMAXPROCS:  runtime.GOMAXPROCS(0),
		NumCPU:      runtime.NumCPU(),
		Goroutines:  runtime.NumGoroutine(),
		MemAllocMB:  float64(ms.Alloc) / (1024 * 1024),
		MemSysMB:    float64(ms.Sys) / (1024 * 1024),
		HeapObjects: ms.HeapObjects,
		NextGCMB:    float64(ms.NextGC) / (1024 * 1024),
		GCPauseMs:   float64(ms.PauseTotalNs) / 1e6,
		NumGC:       ms.NumGC,
		Events24h:   sum.Total,
	}
	for _, p := range []string{"tcp", "udp", "icmp", "device"} {
		if c := sum.ByProto[p]; c > 0 {
			v.ByProto = append(v.ByProto, counter{Label: p, Value: c})
		}
	}
	if m == nil {
		return v
	}
	v.Available = true
	frames := map[string]int{}

	sinks := map[string]*sinkHealth{}
	get := func(ch string) *sinkHealth {
		if sinks[ch] == nil {
			sinks[ch] = &sinkHealth{Channel: ch}
		}
		return sinks[ch]
	}
	for _, s := range m.Samples {
		switch s.Name {
		case "tarpit_uptime_seconds":
			v.Uptime = humanDuration(time.Duration(s.Value) * time.Second)
		case "tarpit_store_db_bytes":
			v.DBBytes = int64(s.Value)
		case "tarpit_disk_used_percent":
			v.DiskPct, v.DiskKnown = int(s.Value), true
		case "tarpit_panic_recoveries_total":
			v.Panics = int(s.Value)
		case "tarpit_honeynet_networks":
			v.HoneyNets = int(s.Value)
		case "tarpit_honeynet_hosts":
			v.HoneyHosts = int(s.Value)
		case "tarpit_sink_dropped_total":
			get(s.Labels["channel"]).Dropped = int(s.Value)
			v.DropTotal += int(s.Value)
		case "tarpit_sink_failed_total":
			get(s.Labels["channel"]).Failed = int(s.Value)
			v.FailTotal += int(s.Value)
		case "tarpit_sink_retried_total":
			get(s.Labels["channel"]).Retried = int(s.Value)
		case "tarpit_build_info":
			v.Version, v.Commit = s.Labels["version"], s.Labels["commit"]
		case "tarpit_sniffer_frames_total":
			frames[s.Labels["proto"]] = int(s.Value)
		case "tarpit_panic_recoveries_by_name_total":
			v.PanicByName = append(v.PanicByName, counter{Label: s.Labels["name"], Value: int(s.Value)})
		}
	}
	for _, sh := range sinks {
		v.Sinks = append(v.Sinks, *sh)
	}
	sort.Slice(v.Sinks, func(i, j int) bool { return v.Sinks[i].Channel < v.Sinks[j].Channel })
	sort.Slice(v.PanicByName, func(i, j int) bool { return v.PanicByName[i].Label < v.PanicByName[j].Label })
	if _, ok := frames["all"]; ok {
		v.SnifferActive = true
		v.Frames = []counter{
			{"received", frames["all"]}, {"ARP", frames["arp"]}, {"IPv4", frames["ipv4"]},
			{"IPv6", frames["ipv6"]}, {"TCP", frames["tcp"]}, {"UDP", frames["udp"]},
			{"ICMP", frames["icmp"]}, {"other", frames["other"]},
		}
	}
	v.DBSize = humanBytes(v.DBBytes)
	return v
}

// humanBytes renders a byte count as B / KiB / MiB / GiB / TiB.
func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return itoa(int(n)) + " B"
	}
	div, exp := int64(u), 0
	for n/div >= u && exp < 3 {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// humanDuration renders a duration as e.g. "3d 4h 12m".
func humanDuration(d time.Duration) string {
	if d < time.Second {
		return "0s"
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	h := int(d / time.Hour)
	d -= time.Duration(h) * time.Hour
	m := int(d / time.Minute)
	out := ""
	if days > 0 {
		out += itoa(days) + "d "
	}
	if days > 0 || h > 0 {
		out += itoa(h) + "h "
	}
	out += itoa(m) + "m"
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var m *Metrics
	if s.stats != nil {
		snap := s.stats()
		m = &snap
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sum, _ := s.store.Summary(ctx, time.Now().Add(-24*time.Hour))
	v := buildHealthView(m, sum)
	v.Charts = healthCharts(v)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "health", v); err != nil {
		slog.Warn("ui: render health", "err", err)
	}
}
