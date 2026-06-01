package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/mitre"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// cmdExportNavigator writes a MITRE ATT&CK Navigator layer (JSON) to stdout
// (or -o file). By default it emits the sensor's *static* coverage — every
// technique it can attribute, scored 1. With --observed it queries the local
// event store and emits an *observed* layer scored by per-technique hit count,
// so an analyst gets a heatmap of what actually fired. Load the output at
// https://mitre-attack.github.io/attack-navigator/.
func cmdExportNavigator(args []string) error {
	fs := flag.NewFlagSet("export-navigator", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file (for --observed)")
	observed := fs.Bool("observed", false, "score by observed event counts from the local store (default: static coverage)")
	since := fs.Duration("since", 30*24*time.Hour, "for --observed, look back this far")
	out := fs.String("o", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var counts map[string]int
	if *observed {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		st, err := store.Open(cfg.Sensor.DataDir, 0)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer st.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs, err := st.Query(ctx, store.Filter{Since: time.Now().Add(-*since), Limit: 1_000_000})
		if err != nil {
			return fmt.Errorf("query events: %w", err)
		}
		counts = map[string]int{}
		for _, ev := range evs {
			for _, t := range ev.MitreTechniques {
				counts[t]++
			}
		}
	}

	b, err := mitre.NavigatorJSON(counts)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(b))
	return nil
}
