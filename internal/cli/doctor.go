package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdDoctor is a preflight / liveness self-check: it loads the effective config
// and reports whether the things a running sensor depends on are actually in
// place — the data dir is writable, the event store exists, configured
// enrichment files are present, and (when run against a live instance) each
// configured TCP listener is actually accepting connections. It closes the gap
// between "validate-config passed" and "the service is really serving".
//
//	tarpit-honeypot doctor            # offline checks + probe localhost listeners
//	tarpit-honeypot doctor --no-probe # skip the listener connection probes
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	noProbe := fs.Bool("no-probe", false, "do not try to connect to the configured listeners")
	timeout := fs.Duration("timeout", time.Second, "per-listener connect timeout")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
	if err != nil {
		fmt.Printf("✗ config: %v\n", err)
		return err
	}
	fail := 0
	warn := 0
	ok := func(msg string) { fmt.Printf("✓ %s\n", msg) }
	bad := func(msg string) { fmt.Printf("✗ %s\n", msg); fail++ }
	warnf := func(msg string) { fmt.Printf("⚠ %s\n", msg); warn++ }

	ok(fmt.Sprintf("config: %d listeners, %d channels, %d routes", len(cfg.Listeners), len(cfg.Channels), len(cfg.Routes)))

	// Data dir writable.
	dd := cfg.Sensor.DataDir
	if dd == "" {
		warnf("sensor.data_dir is empty")
	} else if err := checkWritable(dd); err != nil {
		bad(fmt.Sprintf("data_dir %s not writable: %v", dd, err))
	} else {
		ok("data_dir writable: " + dd)
		if st, err := os.Stat(filepath.Join(dd, "events.db")); err == nil {
			ok(fmt.Sprintf("event store present: events.db (%d KiB)", st.Size()/1024))
		} else {
			warnf("event store events.db not present yet (created on first run)")
		}
	}

	// Configured enrichment files that are named but missing (run-safe but
	// silently unenriched, which surprises operators).
	for _, chk := range enrichmentPaths(cfg) {
		if chk.path == "" {
			continue
		}
		if _, err := os.Stat(chk.path); err != nil {
			warnf(fmt.Sprintf("%s not found: %s (enrichment skipped)", chk.label, chk.path))
		} else {
			ok(fmt.Sprintf("%s present: %s", chk.label, chk.path))
		}
	}

	// Listener liveness — only meaningful against a running instance.
	if !*noProbe {
		live, down := probeListeners(cfg, *timeout)
		if len(down) == 0 {
			ok(fmt.Sprintf("listeners: %d TCP probed, all accepting", live))
		} else {
			warnf(fmt.Sprintf("listeners: %d accepting, %d not (is the sensor running? run `doctor` after `run`): %v", live, len(down), down))
		}
	}

	fmt.Println()
	switch {
	case fail > 0:
		fmt.Printf("doctor: %d problem(s), %d warning(s)\n", fail, warn)
		return fmt.Errorf("doctor found %d problem(s)", fail)
	case warn > 0:
		fmt.Printf("doctor: OK with %d warning(s)\n", warn)
	default:
		fmt.Println("doctor: all checks passed")
	}
	return nil
}

func checkWritable(dir string) error {
	if st, err := os.Stat(dir); err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("not a directory")
	}
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

type pathCheck struct{ label, path string }

func enrichmentPaths(cfg *config.Config) []pathCheck {
	s := cfg.Sensor
	out := []pathCheck{
		{"OUI table", s.OUIFile},
		{"GeoIP city DB", s.GeoIP.CityDB},
		{"GeoIP ASN DB", s.GeoIP.ASNDB},
		{"Tor exit list", s.Tor.ExitFile},
	}
	for _, l := range s.ThreatIntel.Lists {
		out = append(out, pathCheck{"threat-intel list " + l.Label, l.File})
	}
	return out
}

// probeListeners dials each TCP listener's bound port on a loopback/local
// address with a short timeout. Returns the count accepting and the list of
// id:port that refused (so a crash-looped or unbound listener is obvious).
func probeListeners(cfg *config.Config, timeout time.Duration) (live int, down []string) {
	for _, l := range cfg.Listeners {
		if l.Proto == "udp" { // connectionless — a dial can't confirm a listener
			continue
		}
		host, portStr, err := net.SplitHostPort(l.Bind)
		if err != nil {
			continue
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), timeout)
		if err != nil {
			down = append(down, l.ID+":"+portStr)
			continue
		}
		_ = c.Close()
		live++
	}
	return live, down
}
