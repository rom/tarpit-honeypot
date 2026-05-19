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
	rule := fs.String("rule", "", "filter by rule id (exact match)")
	limit := fs.Int("limit", 100, "maximum events to print")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	// Prefer SQLite if it was ever populated; fall back to the jsonlog scan
	// so the command works even with a tripwire-only config.
	dbPath := filepath.Join(cfg.Sensor.DataDir, "events.db")
	if _, err := os.Stat(dbPath); err == nil {
		return listFromStore(cfg.Sensor.DataDir, *since, *source, *rule, *limit)
	}
	return listFromJSONL(cfg.Sensor.DataDir, *since, *source, *rule, *limit)
}

func listFromStore(dataDir string, since time.Duration, source, rule string, limit int) error {
	st, err := store.Open(dataDir, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	evs, err := st.Query(ctx, store.Filter{
		Since:    time.Now().Add(-since),
		SourceIP: source,
		RuleID:   rule,
		Limit:    limit,
	})
	if err != nil {
		return err
	}
	for _, ev := range evs {
		printEvent(ev)
	}
	return nil
}

func listFromJSONL(dataDir string, since time.Duration, source, rule string, limit int) error {
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
	cutoff := time.Now().Add(-since)
	printed := 0
	for _, f := range files {
		fh, err := os.Open(f.path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			if printed >= limit {
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
			if source != "" && ev.Source.IP != source {
				continue
			}
			if rule != "" && ev.RuleID != rule {
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
