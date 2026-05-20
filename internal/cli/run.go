package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/privdrop"
	"github.com/rom/tarpit-honeypot/internal/sandbox"
	"github.com/rom/tarpit-honeypot/internal/sensor"
	"github.com/rom/tarpit-honeypot/internal/ui"
)

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	dryRun := fs.Bool("dry-run", false, "load and validate the config, build sensor, but exit without binding any listeners")

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

	cfg, err := config.LoadManyWithOverrides(f.paths(), f.sets)
	if err != nil {
		return err
	}
	f.applyIfaceOverride(cfg)

	s, err := sensor.New(cfg)
	if err != nil {
		return err
	}

	if *dryRun {
		slog.Info("dry-run OK: config valid, sensor constructed, listeners not bound",
			"listeners", len(cfg.Listeners),
			"channels", len(cfg.Channels),
			"honeynets", len(cfg.Honeynets),
		)
		return nil
	}

	if err := privdrop.Drop(cfg.Sensor.DropUser, cfg.Sensor.DropGroup); err != nil {
		return err
	}

	// Self-confine after privileged setup + privilege drop: seccomp
	// denies shell-spawn / module-load / debug syscalls, Landlock makes
	// everything but data_dir read-only. Best-effort (Linux-only).
	if sb := cfg.Sensor.Sandbox; sb.Seccomp || sb.Landlock {
		if err := sandbox.Apply(sandbox.Config{
			Seccomp:    sb.Seccomp,
			Landlock:   sb.Landlock,
			DataDir:    cfg.Sensor.DataDir,
			ReadPaths:  sb.ReadPaths,
			WritePaths: sb.WritePaths,
		}, slog.Default()); err != nil {
			slog.Warn("sandbox: confinement incomplete", "err", err)
		}
	}

	rootCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Run(rootCtx); err != nil {
			slog.Error("sensor stopped", "err", err)
		}
	}()

	if cfg.UI.Enabled {
		srv, err := ui.New(cfg.UI, s.Store())
		if err != nil {
			cancel()
			wg.Wait()
			return err
		}
		srv.SetStatsProvider(buildStatsProvider(s))
		srv.SetConfig(cfg)
		srv.SetTopology(s.Honeynet())
		srv.SetDataDir(cfg.Sensor.DataDir)
		if dr := s.Devices(); dr != nil {
			srv.SetHostsProvider(func() []ui.HostView {
				devs := dr.List()
				out := make([]ui.HostView, 0, len(devs))
				for _, d := range devs {
					out = append(out, ui.HostView{
						IP: d.IP, MAC: d.MAC, Hostname: d.Hostname, Vendor: d.Vendor,
						Source: string(d.Source), Allowed: dr.IsAllowed(d),
						FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Count: d.Count,
					})
				}
				return out
			})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.ListenAndServe(rootCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("ui stopped", "err", err)
			}
		}()
	}

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
				slog.Info("SIGHUP received; reloading config", "paths", f.paths())
				newCfg, err := config.LoadManyWithOverrides(f.paths(), f.sets)
				if err != nil {
					slog.Error("reload: config invalid; keeping running config", "err", err)
					continue
				}
				f.applyIfaceOverride(newCfg)
				diff := config.DiffConfigs(s.Config(), newCfg)
				if !diff.HasChanges() {
					slog.Info("reload: no effective changes")
					continue
				}
				slog.Info("reload: change summary",
					"hot_reloadable", len(diff.HotReloadable),
					"restart_needed", len(diff.RestartNeeded),
				)
				for _, c := range diff.HotReloadable {
					slog.Info("reload diff", "kind", "hot", "change", c.String())
				}
				for _, c := range diff.RestartNeeded {
					slog.Info("reload diff", "kind", "restart-or-listener-swap", "change", c.String())
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
	_ = fmt.Sprintf
	return nil
}
