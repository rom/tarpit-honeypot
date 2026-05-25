package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/intel"
	"github.com/rom/tarpit-honeypot/internal/stix"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// cmdExportIOCs derives the fleet's indicators from the stored fleet:* findings
// and prints them — STIX 2.1, CSV, a plain value list, or JSON — for piping into
// a TIP / SIEM / blocklist. Offline counterpart to the live /intel feed: it
// reads the local event store, so it works on any node that persists events.
func cmdExportIOCs(args []string) error {
	fs := flag.NewFlagSet("export-iocs", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	since := fs.Duration("since", 7*24*time.Hour, "derive IOCs from fleet findings newer than this")
	format := fs.String("format", "stix", "output format: stix | csv | txt | json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *format {
	case "stix", "csv", "txt", "json":
	default:
		return fmt.Errorf("--format must be stix, csv, txt, or json (got %q)", *format)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(cfg.Sensor.DataDir, "events.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("export-iocs needs the sqlite event store (%s): %w", dbPath, err)
	}
	st, err := store.Open(cfg.Sensor.DataDir, 0)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	evs, err := st.Query(ctx, store.Filter{Since: time.Now().Add(-*since), Limit: 100000})
	if err != nil {
		return err
	}
	// Replay the stored fleet:* findings through a (non-expiring) intel store to
	// derive the indicator sets, exactly as a live aggregator does.
	is := intel.NewStore(10*365*24*time.Hour, 1_000_000)
	for _, ev := range evs {
		if strings.HasPrefix(ev.RuleID, "fleet:") {
			is.Observe(ev)
		}
	}
	iocs := is.IOCs()

	switch *format {
	case "stix":
		return writeJSON(stix.NewBundle(stix.Indicators(iocs, time.Now().UTC())))
	case "json":
		return writeJSON(iocs)
	case "csv":
		fmt.Println("kind,value,reason")
		for _, ioc := range iocs {
			fmt.Printf("%s,%s,%s\n", ioc.Kind, csvField(ioc.Value), ioc.Reason)
		}
	case "txt":
		for _, ioc := range iocs {
			fmt.Println(ioc.Value)
		}
	}
	return nil
}

// csvField quotes a value that contains a comma or quote.
func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
