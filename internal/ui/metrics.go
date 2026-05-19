package ui

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// handleMetrics renders Prometheus text-format metrics from the registered
// StatsProvider. Returns 503 when no provider is wired (e.g. during boot
// before the sensor finishes constructing).
//
// Format reference:
// https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.stats == nil {
		http.Error(w, "metrics not initialized", http.StatusServiceUnavailable)
		return
	}
	m := s.stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Group samples by metric name so we emit one HELP+TYPE per group.
	byName := map[string][]Sample{}
	var names []string
	for _, s := range m.Samples {
		if _, ok := byName[s.Name]; !ok {
			names = append(names, s.Name)
		}
		byName[s.Name] = append(byName[s.Name], s)
	}
	sort.Strings(names)
	for _, n := range names {
		samples := byName[n]
		// HELP / TYPE come from the first sample.
		first := samples[0]
		if first.Help != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", n, first.Help)
		}
		if first.Type != "" {
			fmt.Fprintf(w, "# TYPE %s %s\n", n, first.Type)
		}
		for _, s := range samples {
			fmt.Fprintf(w, "%s%s %s\n", n, renderLabels(s.Labels), trimZero(s.Value))
		}
	}
}

// renderLabels turns {"channel": "ops"} into `{channel="ops"}`. Sorted by
// key for deterministic output. Quote escaping is intentionally minimal —
// label names come from internal sources, not user input.
func renderLabels(l map[string]string) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		v := strings.ReplaceAll(l[k], `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		v = strings.ReplaceAll(v, "\n", `\n`)
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(v)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// trimZero formats float64 without trailing-zero noise — counters are
// always integer-valued and look weird as "42.000000".
func trimZero(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
