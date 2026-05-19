package cli

import (
	"flag"
	"fmt"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("config OK: %d listeners, %d channels, %d routes\n",
		len(cfg.Listeners), len(cfg.Channels), len(cfg.Routes))
	return nil
}
