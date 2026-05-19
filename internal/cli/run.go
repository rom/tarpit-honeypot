package cli

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/privdrop"
	"github.com/rom/tarpit-honeypot/internal/sensor"
	"github.com/rom/tarpit-honeypot/internal/ui"
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

	// Privilege drop happens AFTER sensor.New (which opens data_dir and
	// the store) but BEFORE any listener binds occur (listeners bind in
	// Run()). Privileged bind-to-low-ports must come from systemd
	// AmbientCapabilities or external setcap; Drop only changes uid/gid.
	if err := privdrop.Drop(cfg.Sensor.DropUser, cfg.Sensor.DropGroup); err != nil {
		return err
	}

	rootCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	// Sensor.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Run(rootCtx); err != nil {
			slog.Error("sensor stopped", "err", err)
		}
	}()

	// Web UI (if enabled).
	if cfg.UI.Enabled {
		srv, err := ui.New(cfg.UI, s.Store())
		if err != nil {
			cancel()
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.ListenAndServe(rootCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("ui stopped", "err", err)
			}
		}()
	}

	// SIGHUP -> reload.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-rootCtx.Done():
				signal.Stop(hupCh)
				return
			case <-hupCh:
				slog.Info("SIGHUP received; reloading config", "path", *cfgPath)
				newCfg, err := config.Load(*cfgPath)
				if err != nil {
					slog.Error("reload: config invalid; keeping running config", "err", err)
					continue
				}
				if err := s.Reload(newCfg); err != nil {
					slog.Error("reload failed", "err", err)
				}
			}
		}
	}()

	slog.Info("tarpit-honeypot starting",
		"sensor", s.Name(),
		"listeners", len(cfg.Listeners),
		"canaries", len(cfg.Canaries),
		"channels", len(cfg.Channels),
		"ui", cfg.UI.Enabled,
	)
	wg.Wait()
	slog.Info("tarpit-honeypot stopped")
	return nil
}
