package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Multiple -c files should combine: every listener/honeynet across all
// files is kept; scalar sensor config takes the later file's value.
func TestLoadManyCombinesListsAndOverridesScalars(t *testing.T) {
	dir := t.TempDir()
	a := writeCfg(t, dir, "a.yaml", `
sensor:
  name: base
  data_dir: /tmp/x
listeners:
  - { id: ssh, proto: tcp, bind: 0.0.0.0:22, mode: banner, handler: ssh }
`)
	b := writeCfg(t, dir, "b.yaml", `
sensor:
  name: override
listeners:
  - { id: http, proto: tcp, bind: 0.0.0.0:80, mode: banner, handler: http }
honeynets:
  - { id: ot, cidr: 10.0.0.0/24 }
`)

	cfg, err := LoadManyWithOverrides([]string{a, b}, nil)
	if err != nil {
		t.Fatalf("LoadMany: %v", err)
	}
	if len(cfg.Listeners) != 2 {
		t.Errorf("listeners = %d; want 2 (combined)", len(cfg.Listeners))
	}
	if len(cfg.Honeynets) != 1 {
		t.Errorf("honeynets = %d; want 1", len(cfg.Honeynets))
	}
	// Later file wins for scalar leaves.
	if cfg.Sensor.Name != "override" {
		t.Errorf("sensor.name = %q; want override (later file wins)", cfg.Sensor.Name)
	}
	// Earlier file's scalar that the later file didn't set is retained.
	if cfg.Sensor.DataDir != "/tmp/x" {
		t.Errorf("sensor.data_dir = %q; want /tmp/x (kept from first file)", cfg.Sensor.DataDir)
	}
}

func TestLoadManySingleEqualsLoadWithOverrides(t *testing.T) {
	dir := t.TempDir()
	a := writeCfg(t, dir, "a.yaml", `
sensor: { data_dir: /tmp/x }
listeners:
  - { id: ssh, proto: tcp, bind: 0.0.0.0:22, mode: banner, handler: ssh }
`)
	one, err := LoadManyWithOverrides([]string{a}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Listeners) != 1 {
		t.Errorf("single-file LoadMany listeners = %d; want 1", len(one.Listeners))
	}
}

func TestCombineMapsAppendsLists(t *testing.T) {
	a := map[string]any{"l": []any{1, 2}, "m": map[string]any{"x": 1}}
	b := map[string]any{"l": []any{3}, "m": map[string]any{"y": 2}}
	out := combineMaps(a, b)
	if got := out["l"].([]any); len(got) != 3 {
		t.Errorf("list not appended: %v", got)
	}
	m := out["m"].(map[string]any)
	if m["x"] != 1 || m["y"] != 2 {
		t.Errorf("maps not deep-merged: %v", m)
	}
}
