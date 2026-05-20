package sensor

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func loadReloadTestCfg(t *testing.T, dir, chanSeverity string) *config.Config {
	t.Helper()
	body := `
sensor:
  data_dir: ` + dir + `
listeners:
  - { id: a, proto: tcp, bind: 127.0.0.1:65111, mode: drop, handler: raw }
channels:
  - { id: out, type: stdout, min_severity: ` + chanSeverity + ` }
correlate:
  port_scan: { enabled: true, distinct_ports: 5, window: 30s, severity: high }
`
	p := filepath.Join(dir, "cfg-"+chanSeverity+".yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load test cfg: %v", err)
	}
	return cfg
}

// TestReloadRaceFree exercises a concurrent SIGHUP-style Reload() against
// the bus-loop/accessor reads of the hot-swapped state. Run under -race
// (CI does), this fails on the pre-fix unlocked pointer swap and passes
// once cfg/router/correlator/sinks are guarded by stateMu.
func TestReloadRaceFree(t *testing.T) {
	dir := t.TempDir()
	cfg1 := loadReloadTestCfg(t, dir, "low")
	cfg2 := loadReloadTestCfg(t, dir, "medium") // differs only in a hot-reloadable field
	s, err := New(cfg1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.rootCtx = context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c := cfg1
			if i%2 == 0 {
				c = cfg2
			}
			_ = s.Reload(c)
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = s.Config()
				_ = s.Router()
				_ = s.Correlator()
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}
