package cli

import (
	"flag"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	diffPath := fs.String("diff", "", "compare against this other config file and classify changes as hot-reloadable vs restart-required")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("config OK: %d listeners, %d channels, %d routes, %d canaries, %d url canaries, %d dns canaries\n",
		len(cfg.Listeners), len(cfg.Channels), len(cfg.Routes),
		len(cfg.Canaries), len(cfg.URLCanaries), len(cfg.DNSCanaries))
	if *diffPath == "" {
		return nil
	}
	other, err := config.Load(*diffPath)
	if err != nil {
		return fmt.Errorf("diff target %s: %w", *diffPath, err)
	}
	diff := config.DiffConfigs(cfg, other)
	if !diff.HasChanges() {
		fmt.Printf("\nno effective differences between %s and %s\n", *cfgPath, *diffPath)
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
