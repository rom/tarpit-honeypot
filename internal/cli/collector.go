package cli

import (
	"flag"
	"fmt"
	"log/slog"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdCollector runs the sensor as a turnkey fleet **collector** (aggregator):
// it stands up the authenticated ingest endpoint that child sensors forward
// to, runs the cross-sensor fleet correlator over the merged stream, and (when
// fleet is serving) exposes the downward intel feed + STIX/TAXII export — all
// without binding any honeypot listeners of its own. A collector deceives
// nothing; it concentrates and correlates what the leaf sensors saw.
//
// It is the same engine as `run` with an aggregator-shaped config: the only
// difference is the collector preset applied below, so every other knob
// (storage, web UI, channels, sandbox, privilege drop) behaves identically.
// Point child sensors' forward.url at this node's ingest bind.
func cmdCollector(args []string) error {
	fs := flag.NewFlagSet("collector", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	dryRun := fs.Bool("dry-run", false, "load + validate the collector config and exit without binding the ingest endpoint")
	bind := fs.String("bind", "", "override the ingest bind address (host:port); default keeps the config value or :8443")
	keepListeners := fs.Bool("keep-listeners", false, "do not strip honeypot listeners (run as a combined sensor+collector)")

	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}

	logCloser, err := f.log.apply()
	if err != nil {
		return err
	}
	if logCloser != nil {
		defer logCloser.Close()
	}

	cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
	if err != nil {
		return err
	}
	f.applyIfaceOverride(cfg)

	if err := applyCollectorPreset(cfg, *bind, *keepListeners); err != nil {
		return err
	}
	// Re-validate the shaped config so a bad preset/override surfaces as a
	// clear error rather than a runtime failure.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("collector config invalid after preset: %w", err)
	}

	slog.Info("starting in collector mode",
		"ingest_bind", cfg.Ingest.Bind,
		"token_env", cfg.Ingest.TokenEnv,
		"fleet", true,
		"honeypot_listeners", len(cfg.Listeners),
	)
	return runWithConfig(cfg, f, *dryRun)
}

// applyCollectorPreset shapes a loaded config into aggregator posture:
// force-enable the ingest endpoint and fleet correlator, default a bind /
// token-env if the operator didn't set them, and (unless keepListeners) drop
// the honeypot surface so the node only collects and correlates.
func applyCollectorPreset(cfg *config.Config, bindOverride string, keepListeners bool) error {
	cfg.Ingest.Enabled = true
	if bindOverride != "" {
		cfg.Ingest.Bind = bindOverride
	}
	if cfg.Ingest.Bind == "" {
		cfg.Ingest.Bind = ":8443"
	}
	if cfg.Ingest.TokenEnv == "" {
		cfg.Ingest.TokenEnv = "TARPIT_INGEST_TOKEN"
	}

	// Force the cross-sensor correlator on — it's the whole point of a
	// collector, and it only auto-enables off ingest otherwise.
	on := true
	cfg.Fleet.Enabled = &on

	if !keepListeners {
		// A collector impersonates nothing: no TCP/UDP honeypots, no decoy
		// honeynets. This also frees those ports on the aggregator host.
		cfg.Listeners = nil
		cfg.Honeynets = nil
	}
	return nil
}
