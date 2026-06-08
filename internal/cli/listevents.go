package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func cmdListEvents(args []string) error {
	fs := flag.NewFlagSet("list-events", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	since := fs.Duration("since", 24*time.Hour, "only show events newer than this")
	source := fs.String("source", "", "filter by source IP (exact match)")
	target := fs.String("target", "", "filter by destination/server IP hit (exact match) — the multi-IP pivot")
	handler := fs.String("handler", "", "filter by protocol handler (e.g. ssh, http, snmptrap)")
	port := fs.Int("port", 0, "filter by destination port")
	rule := fs.String("rule", "", "filter by rule id (exact match)")
	fleetOnly := fs.Bool("fleet", false, "show only cross-sensor fleet:* findings")
	limit := fs.Int("limit", 100, "maximum events to print")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	q := listQuery{since: *since, source: *source, target: *target, handler: *handler, port: *port, rule: *rule, fleetOnly: *fleetOnly, limit: *limit}

	// Prefer SQLite if it was ever populated; fall back to the jsonlog scan
	// so the command works even with a tripwire-only config.
	dbPath := filepath.Join(cfg.Sensor.DataDir, "events.db")
	if _, err := os.Stat(dbPath); err == nil {
		return listFromStore(cfg.Sensor.DataDir, q)
	}
	return listFromJSONL(cfg.Sensor.DataDir, q)
}

// listQuery bundles the list-events filters threaded to both backends.
type listQuery struct {
	since                         time.Duration
	source, target, handler, rule string
	port                          int
	fleetOnly                     bool
	limit                         int
}

func listFromStore(dataDir string, q listQuery) error {
	st, err := store.Open(dataDir, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The fleet:* prefix filter is applied in-memory (the store filters rule
	// ids by exact match), so query a wider window and keep the matches.
	queryLimit := q.limit
	if q.fleetOnly {
		queryLimit = 100000
	}
	evs, err := st.Query(ctx, store.Filter{
		Since:    time.Now().Add(-q.since),
		SourceIP: q.source,
		DstIP:    q.target,
		Handler:  q.handler,
		DstPort:  q.port,
		RuleID:   q.rule,
		Limit:    queryLimit,
	})
	if err != nil {
		return err
	}
	printed := 0
	for _, ev := range evs {
		if q.fleetOnly && !strings.HasPrefix(ev.RuleID, "fleet:") {
			continue
		}
		printEvent(ev)
		if printed++; printed >= q.limit {
			break
		}
	}
	return nil
}

func listFromJSONL(dataDir string, q listQuery) error {
	dir := filepath.Join(dataDir, "events")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	type fi struct {
		path string
		mod  time.Time
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{filepath.Join(dir, e.Name()), info.ModTime()})
	}
	sort.Slice(files, func(i, k int) bool { return files[i].mod.Before(files[k].mod) })
	cutoff := time.Now().Add(-q.since)
	printed := 0
	for _, f := range files {
		fh, err := os.Open(f.path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			if printed >= q.limit {
				_ = fh.Close()
				return nil
			}
			var ev event.Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				continue
			}
			if ev.Time.Before(cutoff) {
				continue
			}
			if q.source != "" && ev.Source.IP != q.source {
				continue
			}
			if q.target != "" && ev.Dest.IP != q.target {
				continue
			}
			if q.handler != "" && ev.Handler != q.handler {
				continue
			}
			if q.port != 0 && ev.Dest.Port != q.port {
				continue
			}
			if q.rule != "" && ev.RuleID != q.rule {
				continue
			}
			if q.fleetOnly && !strings.HasPrefix(ev.RuleID, "fleet:") {
				continue
			}
			printEvent(&ev)
			printed++
		}
		_ = fh.Close()
	}
	return nil
}

func printEvent(ev *event.Event) {
	fmt.Printf("%s  %-8s  %-30s  %s -> %s:%d  (%s)\n",
		ev.Time.Format(time.RFC3339), ev.Severity, ev.RuleID,
		ev.Source.IP, ev.Dest.IP, ev.Dest.Port, ev.ID)
}
