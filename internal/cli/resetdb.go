package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdResetDB empties the local databases / artifact stores under the
// sensor's data_dir. By default it clears just the event store (events.db +
// the JSON event logs); flags add the device inventory, pcaps, payloads,
// recorded sessions, and persisted correlator state. The sensor identity
// (.deployment-id) and TLS certs are always preserved.
//
// It is destructive, so it dry-runs unless `--yes`/`-y` is given. Stop the
// sensor before running it (deleting an open SQLite file is unsafe).
func cmdResetDB(args []string) error {
	fs := flag.NewFlagSet("reset-db", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	dataDir := fs.String("data-dir", "", "data directory (overrides config; lets reset-db run without loading a full config)")
	all := fs.Bool("all", false, "clear everything: events + devices + captures + payloads + sessions + correlator state")
	devices := fs.Bool("devices", false, "clear the learned-device inventory (devices.json)")
	captures := fs.Bool("captures", false, "clear per-connection pcaps (captures/)")
	payloads := fs.Bool("payloads", false, "clear harvested payloads (payloads/)")
	sessions := fs.Bool("sessions", false, "clear recorded sessions (sessions/)")
	state := fs.Bool("state", false, "clear persisted correlator state")
	yes := fs.Bool("yes", false, "actually delete (without this it is a dry-run)")
	fs.BoolVar(yes, "y", false, "alias for --yes")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}

	dir := *dataDir
	if dir == "" {
		cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
		if err != nil {
			return fmt.Errorf("reset-db: %w (or pass --data-dir to skip config loading)", err)
		}
		dir = cfg.Sensor.DataDir
	}
	if dir == "" || dir == "/" {
		return fmt.Errorf("reset-db: refusing to operate on data_dir %q", dir)
	}

	type target struct {
		path  string
		isDir bool
	}
	var targets []target
	addFile := func(name string) { targets = append(targets, target{filepath.Join(dir, name), false}) }
	addDir := func(name string) { targets = append(targets, target{filepath.Join(dir, name), true}) }

	// Default to the event store unless specific categories were requested.
	specific := *devices || *captures || *payloads || *sessions || *state
	if *all || !specific {
		addFile("events.db")
		addFile("events.db-shm")
		addFile("events.db-wal")
		addDir("events")
	}
	if *all || *devices {
		addFile("devices.json")
	}
	if *all || *captures {
		addDir("captures")
	}
	if *all || *payloads {
		addDir("payloads")
	}
	if *all || *sessions {
		addDir("sessions")
	}
	if *all || *state {
		addFile("correlate-state.json")
	}

	if !*yes {
		fmt.Println("reset-db DRY RUN — would clear (re-run with --yes / -y to apply):")
		for _, t := range targets {
			fmt.Printf("  %-9s %s\n", existMark(t.path), t.path)
		}
		fmt.Println("\nStop the sensor first. Identity (.deployment-id) and TLS certs are preserved.")
		return nil
	}

	cleared := 0
	for _, t := range targets {
		if t.isDir {
			n, err := emptyDirContents(t.path)
			if err != nil {
				return fmt.Errorf("reset-db: clear %s: %w", t.path, err)
			}
			cleared += n
			continue
		}
		err := os.Remove(t.path)
		if err == nil {
			cleared++
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("reset-db: remove %s: %w", t.path, err)
		}
	}
	fmt.Printf("reset-db: cleared %d item(s) under %s\n", cleared, dir)
	return nil
}

// emptyDirContents removes the entries inside dir (keeping dir itself),
// returning how many top-level entries were removed.
func emptyDirContents(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func existMark(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "[absent]"
	}
	return "[present]"
}
