package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// cmdCheckIOCs reads a file of indicators (attacker source IPs and/or CIDR
// ranges) and reports which of them appear in the local event store's historical
// data — a retro-hunt / threat-intel sweep: "has this honeypot ever seen any of
// these hosts?". Indicators match against the event source IP (the attacker).
//
// Accepted file shapes (auto-detected):
//   - one IP or CIDR per line (blank lines and #/// comments ignored);
//   - several comma-separated IPs/CIDRs per line;
//   - JSON: an array of strings, an array of objects with a value/ip field
//     (so `export-iocs --format json` round-trips), or an object with an
//     iocs/indicators/ips/values/addresses array.
func cmdCheckIOCs(args []string) error {
	fs := flag.NewFlagSet("check-iocs", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	file := fs.String("file", "", "path to the IOC file to check (IPs / CIDRs, one or comma-separated per line, or JSON)")
	format := fs.String("format", "text", "output format: text | json")
	since := fs.Duration("since", 0, "only match events newer than this (e.g. 720h); default 0 = all history")
	failOnHit := fs.Bool("fail-on-hit", false, "exit non-zero (2) when at least one indicator matched")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("check-iocs requires --file <path>")
	}
	switch *format {
	case "text", "json":
	default:
		return fmt.Errorf("--format must be text or json (got %q)", *format)
	}

	ips, cidrs, bad, err := parseIOCFile(*file)
	if err != nil {
		return err
	}
	if len(ips) == 0 && len(cidrs) == 0 {
		return fmt.Errorf("no valid IP or CIDR indicators found in %s", *file)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(cfg.Sensor.DataDir, "events.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("check-iocs needs the sqlite event store (%s): %w", dbPath, err)
	}
	st, err := store.Open(cfg.Sensor.DataDir, 0)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sinceTime := time.Time{} // zero = all history
	if *since > 0 {
		sinceTime = time.Now().Add(-*since)
	}

	hits, err := matchIOCs(ctx, st, ips, cidrs, sinceTime)
	if err != nil {
		return err
	}
	// Highest threat score first, then event volume.
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Agg.Weight != hits[j].Agg.Weight {
			return hits[i].Agg.Weight > hits[j].Agg.Weight
		}
		return hits[i].Agg.Count > hits[j].Agg.Count
	})

	if *format == "json" {
		if err := writeCheckIOCsJSON(*file, len(ips), len(cidrs), bad, sinceTime, hits); err != nil {
			return err
		}
	} else {
		printCheckIOCsText(*file, dbPath, len(ips), len(cidrs), bad, sinceTime, hits)
	}

	if *failOnHit && len(hits) > 0 {
		_ = st.Close()
		os.Exit(2)
	}
	return nil
}

// iocHit is one source IP that matched an indicator and was seen in the store.
type iocHit struct {
	Indicator string                // the exact IP, or the CIDR string that contained the match
	ViaCIDR   bool                  // true when matched through a CIDR rather than an exact IP
	Agg       store.SourceAggregate // per-source rollup from the event store
}

// matchIOCs resolves exact-IP and CIDR indicators against the store's source
// IPs. Exact IPs are looked up directly (indexed IN query); CIDRs are matched by
// enumerating the store's distinct source IPs and testing membership in Go
// (SQLite can't do CIDR), then aggregating the matched subset. Each source IP is
// reported once, preferring an exact-IP attribution over a CIDR one.
func matchIOCs(ctx context.Context, st *store.Store, ips []string, cidrs []*net.IPNet, since time.Time) ([]iocHit, error) {
	var hits []iocHit
	matched := map[string]bool{}

	// Exact IPs.
	if len(ips) > 0 {
		aggs, err := st.AggregateSourceIPs(ctx, ips, since)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if a, ok := aggs[ip]; ok {
				hits = append(hits, iocHit{Indicator: ip, Agg: a})
				matched[ip] = true
			}
		}
	}

	// CIDR ranges: enumerate distinct source IPs once, test membership in Go.
	if len(cidrs) > 0 {
		distinct, err := st.DistinctSourceIPs(ctx, since)
		if err != nil {
			return nil, err
		}
		inCIDR := map[string]string{} // store src_ip -> matching CIDR string
		var toAgg []string
		for _, raw := range distinct {
			if matched[raw] {
				continue // already attributed to an exact IP
			}
			ip := net.ParseIP(raw)
			if ip == nil {
				continue
			}
			for _, n := range cidrs {
				if n.Contains(ip) {
					inCIDR[raw] = n.String()
					toAgg = append(toAgg, raw)
					break
				}
			}
		}
		if len(toAgg) > 0 {
			aggs, err := st.AggregateSourceIPs(ctx, toAgg, since)
			if err != nil {
				return nil, err
			}
			for _, raw := range toAgg {
				if a, ok := aggs[raw]; ok {
					hits = append(hits, iocHit{Indicator: inCIDR[raw], ViaCIDR: true, Agg: a})
					matched[raw] = true
				}
			}
		}
	}
	return hits, nil
}

// parseIOCFile reads an IOC file and returns the distinct exact IPs (canonical
// form), the CIDR networks, and any tokens that parsed as neither. It accepts
// line-based (one/many per line) and JSON inputs; see cmdCheckIOCs for the
// recognized shapes.
func parseIOCFile(path string) (ips []string, cidrs []*net.IPNet, bad []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var tokens []string
	if t := bytes.TrimSpace(data); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		tokens, err = extractJSONIOCTokens(t)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse JSON IOC file %s: %w", path, err)
		}
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			for _, tok := range strings.Split(line, ",") {
				if tok = strings.TrimSpace(tok); tok != "" {
					tokens = append(tokens, tok)
				}
			}
		}
	}

	seen := map[string]bool{}
	for _, tok := range tokens {
		if strings.Contains(tok, "/") {
			_, n, e := net.ParseCIDR(tok)
			if e != nil {
				bad = append(bad, tok)
				continue
			}
			cidrs = append(cidrs, n)
			continue
		}
		ip := net.ParseIP(tok)
		if ip == nil {
			bad = append(bad, tok)
			continue
		}
		canon := ip.String()
		if !seen[canon] {
			seen[canon] = true
			ips = append(ips, canon)
		}
	}
	return ips, cidrs, bad, nil
}

// extractJSONIOCTokens pulls indicator strings out of the supported JSON shapes.
func extractJSONIOCTokens(data []byte) ([]string, error) {
	// Array of bare strings.
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	// Array of objects carrying a value/ip/indicator/cidr field (export-iocs
	// JSON is [{"Kind","Value","Reason"}, ...]).
	var objs []map[string]any
	if err := json.Unmarshal(data, &objs); err == nil {
		return iocTokensFromObjs(objs), nil
	}
	// Object wrapping an indicator array under a known key.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	for k, raw := range obj {
		switch strings.ToLower(k) {
		case "iocs", "indicators", "ips", "values", "addresses":
			var a []string
			if json.Unmarshal(raw, &a) == nil {
				return a, nil
			}
			var o []map[string]any
			if json.Unmarshal(raw, &o) == nil {
				return iocTokensFromObjs(o), nil
			}
		}
	}
	return nil, fmt.Errorf("no recognizable indicators (expected a JSON array of strings/objects, or an object with an iocs/indicators/ips/values/addresses array)")
}

// iocTokensFromObjs extracts the first indicator-bearing field from each object.
func iocTokensFromObjs(objs []map[string]any) []string {
	var out []string
	for _, o := range objs {
		for k, v := range o {
			switch strings.ToLower(k) {
			case "value", "ip", "indicator", "cidr", "addr", "address":
				if s, ok := v.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func printCheckIOCsText(file, dbPath string, nIPs, nCIDRs int, bad []string, since time.Time, hits []iocHit) {
	window := "all history"
	if !since.IsZero() {
		window = "since " + since.UTC().Format(time.RFC3339)
	}
	fmt.Printf("IOC check: %d IP(s) + %d CIDR(s) from %s against %s (%s)\n",
		nIPs, nCIDRs, file, dbPath, window)
	if len(bad) > 0 {
		fmt.Printf("  skipped %d unparseable indicator(s): %s\n", len(bad), strings.Join(clipList(bad, 10), ", "))
	}
	if len(hits) == 0 {
		fmt.Println("\nNo hits — none of the indicators appear in the event store.")
		return
	}
	var totalEvents int
	for _, h := range hits {
		totalEvents += h.Agg.Count
	}
	fmt.Printf("\nHITS: %d source IP(s) matched, %d event(s) total\n\n", len(hits), totalEvents)
	for _, h := range hits {
		via := ""
		if h.ViaCIDR {
			via = "  (in " + h.Indicator + ")"
		}
		fmt.Printf("  %-39s %6d events  first %s  last %s  max=%s  rules=%d  score=%d%s\n",
			h.Agg.IP, h.Agg.Count,
			h.Agg.FirstSeen.Format("2006-01-02"), h.Agg.LastSeen.Format("2006-01-02"),
			h.Agg.MaxSeverity, h.Agg.DistinctRules, h.Agg.Weight, via)
	}
	fmt.Printf("\nTip: drill into any hit with `tarpit-honeypot list-events --source <ip>`.\n")
}

func writeCheckIOCsJSON(file string, nIPs, nCIDRs int, bad []string, since time.Time, hits []iocHit) error {
	type hitJSON struct {
		Indicator     string `json:"indicator"`
		SourceIP      string `json:"source_ip"`
		ViaCIDR       bool   `json:"via_cidr"`
		Events        int    `json:"events"`
		FirstSeen     string `json:"first_seen"`
		LastSeen      string `json:"last_seen"`
		MaxSeverity   string `json:"max_severity"`
		DistinctRules int    `json:"distinct_rules"`
		ThreatScore   int    `json:"threat_score"`
	}
	out := struct {
		File         string    `json:"file"`
		CheckedIPs   int       `json:"checked_ips"`
		CheckedCIDRs int       `json:"checked_cidrs"`
		Unparseable  []string  `json:"unparseable,omitempty"`
		Since        string    `json:"since,omitempty"`
		HitCount     int       `json:"hit_count"`
		Hits         []hitJSON `json:"hits"`
	}{File: file, CheckedIPs: nIPs, CheckedCIDRs: nCIDRs, Unparseable: bad, HitCount: len(hits)}
	if !since.IsZero() {
		out.Since = since.UTC().Format(time.RFC3339)
	}
	for _, h := range hits {
		out.Hits = append(out.Hits, hitJSON{
			Indicator: h.Indicator, SourceIP: h.Agg.IP, ViaCIDR: h.ViaCIDR,
			Events:    h.Agg.Count,
			FirstSeen: h.Agg.FirstSeen.Format(time.RFC3339), LastSeen: h.Agg.LastSeen.Format(time.RFC3339),
			MaxSeverity: h.Agg.MaxSeverity.String(), DistinctRules: h.Agg.DistinctRules, ThreatScore: h.Agg.Weight,
		})
	}
	return writeJSON(out)
}

// clipList returns at most n items, appending an ellipsis marker when truncated.
func clipList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("…(+%d more)", len(s)-n))
}
