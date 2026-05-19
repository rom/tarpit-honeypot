package cli

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/sensor"
)

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/tarpit-honeypot/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	s, err := sensor.New(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("tarpit-honeypot starting", "sensor", s.Name(), "listeners", len(cfg.Listeners), "channels", len(cfg.Channels))
	if err := s.Run(ctx); err != nil {
		return err
	}
	slog.Info("tarpit-honeypot stopped")
	return nil
}
