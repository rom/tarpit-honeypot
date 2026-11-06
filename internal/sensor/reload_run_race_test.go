package sensor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// TestRunReloadRaceFree drives a live Run() concurrently with a tight,
// SIGHUP-style Reload() loop. Run's startup reads the running config in many
// places (listeners, canaries, DNS, sniffer, honeynets, devices, the
// correlator-save and retention runners) and records rootCtx; Reload hot-swaps
// cfg/router/correlator/sinks under stateMu and reads rootCtx to re-parent the
// new router + KEV sync.
//
// Before the fix Run read s.cfg and s.rootCtx directly (unlocked) during
// startup, which races Reload's guarded writes when a reload lands while the
// sensor is still booting. The -race detector (CI runs it) flags that. The
// Reload loop below waits until Run has installed rootCtx — so Reload's
// router.Start never sees a nil ctx — and then hammers reloads so its writes
// overlap Run's still-executing startup reads. On the fixed code every access
// to cfg/rootCtx goes through stateMu, so this runs clean under -race.
func TestRunReloadRaceFree(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	_ = os.WriteFile(filepath.Join(dir, "canary.txt"), []byte("bait"), 0o600)

	mkCfg := func(sev string) *config.Config {
		// The two variants differ only in a hot-reloadable channel field; the
		// listener set is identical, so Reload performs no listener churn and the
		// test stays focused on the cfg/router/correlator/sinks swap.
		body := fmt.Sprintf(`
sensor:
  data_dir: %s
  disk: { retention_days: 7 }
listeners:
  - { id: web, proto: tcp, bind: 127.0.0.1:%d, mode: banner, handler: http, severity: medium }
channels:
  - { id: out, type: stdout, min_severity: %s }
canaries:
  - { id: loot, path: %s/canary.txt, events: [write], severity: critical }
devices:
  enabled: true
  learn: true
correlate:
  port_scan: { enabled: true, distinct_ports: 3, window: 30s, severity: high }
`, dir, port, sev, dir)
		p := filepath.Join(dir, "cfg-"+sev+".yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(p)
		if err != nil {
			t.Fatalf("load cfg %s: %v", sev, err)
		}
		return c
	}
	cfgLow := mkCfg("low")
	cfgMed := mkCfg("medium")

	s, err := New(cfgLow)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx) }()

	stopReload := make(chan struct{})
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		// Wait for Run to install rootCtx (its first action, under stateMu) so a
		// reload's router.Start can't see a nil parent context. curRootCtx reads
		// it through the lock, so this wait is itself race-free.
		for s.curRootCtx() == nil {
			select {
			case <-stopReload:
				return
			default:
				runtime.Gosched()
			}
		}
		for i := 0; ; i++ {
			select {
			case <-stopReload:
				return
			default:
			}
			c := cfgLow
			if i%2 == 0 {
				c = cfgMed
			}
			_ = s.Reload(c)
		}
	}()

	// Give Run time to finish booting while the reload loop hammers it.
	time.Sleep(150 * time.Millisecond)

	// Stop reloads BEFORE shutdown: Run's shutdown stops the current router, and
	// a reload racing that teardown would double-close a worker channel. Drain
	// the reload goroutine first, then cancel and wait for a clean return.
	close(stopReload)
	<-reloadDone
	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of context cancel")
	}
}
