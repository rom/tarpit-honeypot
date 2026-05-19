package cli

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdShowConfig prints the post-defaults, post-validation effective config.
// Useful for confirming what the sensor will actually run with — secrets
// referenced via *_env fields are NOT expanded (the env var name is shown
// instead) so the output is safe to share in tickets and chat.
func cmdShowConfig(args []string) error {
	fs := flag.NewFlagSet("show-config", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# effective config: %d listeners, %d channels, %d routes, %d canaries, %d url canaries, %d dns canaries\n",
		len(cfg.Listeners), len(cfg.Channels), len(cfg.Routes),
		len(cfg.Canaries), len(cfg.URLCanaries), len(cfg.DNSCanaries))
	return nil
}
