package cli

import (
	"flag"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/detect"
)

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	diffPath := fs.String("diff", "", "compare against this other config file and classify changes as hot-reloadable vs restart-required")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	// Validate the effective config (base file(s) + conf.d + env + --set);
	// multiple -c are combined exactly as `run` would combine them.
	cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
	if err != nil {
		return err
	}
	f.applyIfaceOverride(cfg)
	fmt.Printf("config OK: %d listeners, %d channels, %d routes, %d canaries, %d url canaries, %d dns canaries\n",
		len(cfg.Listeners), len(cfg.Channels), len(cfg.Routes),
		len(cfg.Canaries), len(cfg.URLCanaries), len(cfg.DNSCanaries))
	// Surface TLS-cert ↔ deployment-domain coherence warnings (the same the
	// sensor logs at startup + shows on the config page) so a mismatch is caught
	// before deploy, not after.
	if warns := cfg.TLSCoherenceWarnings(); len(warns) > 0 {
		fmt.Printf("\nTLS ↔ domain coherence warnings (%d):\n", len(warns))
		for _, w := range warns {
			fmt.Println("  ⚠ " + w)
		}
	}
	// Operator detection rules: load + report so a malformed rule (bad regex,
	// unknown modifier, missing id) is caught before deploy.
	if cfg.Detection.RulesDir != "" {
		eng, derrs := detect.Load(cfg.Detection.RulesDir)
		fmt.Printf("\ndetection rules: %d loaded from %s\n", eng.Count(), cfg.Detection.RulesDir)
		for _, de := range derrs {
			fmt.Println("  ⚠ " + de.Error())
		}
		if len(derrs) > 0 {
			return fmt.Errorf("%d detection-rule error(s)", len(derrs))
		}
	}
	if *diffPath == "" {
		return nil
	}
	other, err := config.Load(*diffPath)
	if err != nil {
		return fmt.Errorf("diff target %s: %w", *diffPath, err)
	}
	diff := config.DiffConfigs(cfg, other)
	if !diff.HasChanges() {
		fmt.Printf("\nno effective differences between %v and %s\n", f.paths(), *diffPath)
		return nil
	}
	fmt.Printf("\nchanges that would hot-reload on SIGHUP (%d):\n", len(diff.HotReloadable))
	for _, c := range diff.HotReloadable {
		fmt.Println("  " + c.String())
	}
	fmt.Printf("\nchanges that require restart (%d):\n", len(diff.RestartNeeded))
	for _, c := range diff.RestartNeeded {
		fmt.Println("  " + c.String())
	}
	return nil
}
