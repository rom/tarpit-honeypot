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
	"os/user"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/egress"
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

	cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
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

	// Install the OS-level egress firewall while still privileged (needs
	// CAP_NET_ADMIN) and before the seccomp sandbox blocks exec — scoped to the
	// uid the sensor will run as. The in-process allowlist (built in New) is the
	// source of truth; the firewall is the hard backstop.
	if cfg.Sensor.Egress.Enforce {
		if p := egress.Default(); p != nil {
			uid := egressUID(cfg.Sensor.DropUser)
			fc := egress.FirewallConfig{UID: uid, Entries: p.Entries(), Resolvers: egress.SystemResolvers()}
			ictx, icancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := egress.InstallFirewall(ictx, fc)
			icancel()
			if err != nil {
				slog.Warn("egress firewall not installed (in-process guard still active)", "err", err)
			} else {
				slog.Info("egress firewall installed", "uid", uid, "allowlist", len(fc.Entries))
				defer func() {
					rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := egress.RemoveFirewall(rctx, ""); err != nil {
						slog.Warn("egress firewall cleanup failed (uid-scoped table left for next start)", "err", err)
					}
					rcancel()
				}()
			}
		}
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
		srv.SetConfigPaths(f.paths())
		srv.SetTopology(s.Honeynet())
		srv.SetDataDir(cfg.Sensor.DataDir)
		if dr := s.Devices(); dr != nil {
			srv.SetHostsProvider(func() []ui.HostView {
				devs := dr.List()
				out := make([]ui.HostView, 0, len(devs))
				for _, d := range devs {
					key := d.MAC
					if key == "" {
						key = d.IP
					}
					out = append(out, ui.HostView{
						Key: key, IP: d.IP, MAC: d.MAC, Hostname: d.Hostname, Vendor: d.Vendor,
						Source: string(d.Source), Allowed: dr.IsAllowed(d),
						FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Count: d.Count,
						Ports: d.Ports, Services: d.Services, Attrs: d.Attrs,
					})
				}
				return out
			})
			srv.SetHostsSummaryProvider(func() ui.HostsSummary {
				st := dr.Stats()
				sum := ui.HostsSummary{Total: st.Total, Allowed: st.Allowed, Rogue: st.Rogue}
				sum.BySource = labeledCounts(st.BySource)
				sum.ByClass = labeledCounts(st.ByClass)
				for _, c := range dr.Conflicts() {
					sum.Conflicts = append(sum.Conflicts, ui.HostConflict{IP: c.IP, MACs: c.MACs})
				}
				return sum
			})
			srv.SetDeviceActions(dr)
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
				// Always re-read enrichment files: their contents may have
				// changed (the enrichment installer refreshed them) even when
				// the config text is identical.
				if err := s.ReloadEnrichment(); err != nil {
					slog.Warn("reload: enrichment re-read failed; keeping previous", "err", err)
				}
				newCfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
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

// labeledCounts converts a name->count map into a slice sorted by name,
// for the device-summary breakdown bars in the web UI.
func labeledCounts(m map[string]int) []ui.LabeledCount {
	out := make([]ui.LabeledCount, 0, len(m))
	for k, v := range m {
		out = append(out, ui.LabeledCount{Label: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// egressUID resolves the uid the sensor will run as (drop_user, else current),
// so the egress firewall can be scoped to exactly the sensor's own traffic.
func egressUID(dropUser string) int {
	if dropUser != "" {
		if u, err := user.Lookup(dropUser); err == nil {
			if id, err := strconv.Atoi(u.Uid); err == nil {
				return id
			}
		}
	}
	return os.Getuid()
}
