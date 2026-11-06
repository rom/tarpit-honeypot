package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/sensor"
)

// newMinimalSensor builds a sensor from a minimal on-disk config (data_dir +
// one sqlite channel) for exercising the UI provider builders.
func newMinimalSensor(t *testing.T) *sensor.Sensor {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf("sensor:\n  data_dir: %s\nchannels:\n  - { id: db, type: sqlite }\n", dir)
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	s, err := sensor.New(cfg)
	if err != nil {
		t.Fatalf("sensor.New: %v", err)
	}
	return s
}

// TestBuildCoverageProvider exercises the /coverage capability snapshot the run
// command wires into the UI (also covering the shared sensor accessors).
func TestBuildCoverageProvider(t *testing.T) {
	s := newMinimalSensor(t)

	v := buildCoverageProvider(s)()
	if v.Counts.TCPHandlers == 0 || v.Counts.UDPHandlers == 0 {
		t.Errorf("handler counts zero: %+v", v.Counts)
	}
	if v.Counts.CVETotal == 0 || len(v.Services) == 0 {
		t.Errorf("empty CVE coverage: total=%d services=%d", v.Counts.CVETotal, len(v.Services))
	}
	if v.Counts.Techniques == 0 || v.Counts.Tactics == 0 || v.Counts.Archetypes == 0 {
		t.Errorf("techniques/tactics/archetypes zero: %+v", v.Counts)
	}
	// Services are sorted by total desc; the first should carry the most CVEs.
	if len(v.Services) >= 2 {
		a := v.Services[0].Detectable + v.Services[0].Advisory
		b := v.Services[1].Detectable + v.Services[1].Advisory
		if a < b {
			t.Errorf("services not sorted by total desc: %d < %d", a, b)
		}
	}
	// KEV overlay is disabled on this minimal config.
	if v.Counts.KEVActive {
		t.Error("KEV overlay should be inactive without kev config")
	}
}

// TestBuildStatsProvider exercises the Prometheus-style stats snapshot builder.
func TestBuildStatsProvider(t *testing.T) {
	s := newMinimalSensor(t)
	sp := buildStatsProvider(s)
	if sp == nil {
		t.Fatal("nil stats provider")
	}
	_ = sp() // snapshot on a fresh sensor must not panic
}
