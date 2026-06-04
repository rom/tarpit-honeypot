package cli

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestApplyCollectorPreset(t *testing.T) {
	cfg := &config.Config{
		Listeners: []config.Listener{{ID: "ssh", Proto: "tcp", Bind: ":22", Handler: "ssh"}},
		Honeynets: []config.Honeynet{{ID: "net1"}},
	}
	if err := applyCollectorPreset(cfg, "", false); err != nil {
		t.Fatal(err)
	}
	if !cfg.Ingest.Enabled {
		t.Error("ingest should be enabled")
	}
	if cfg.Ingest.Bind != ":8443" {
		t.Errorf("bind = %q, want :8443 default", cfg.Ingest.Bind)
	}
	if cfg.Ingest.TokenEnv != "TARPIT_INGEST_TOKEN" {
		t.Errorf("token_env = %q, want default", cfg.Ingest.TokenEnv)
	}
	if cfg.Fleet.Enabled == nil || !*cfg.Fleet.Enabled {
		t.Error("fleet should be force-enabled")
	}
	if len(cfg.Listeners) != 0 || len(cfg.Honeynets) != 0 {
		t.Errorf("honeypot surface should be stripped: %d listeners, %d honeynets",
			len(cfg.Listeners), len(cfg.Honeynets))
	}
}

func TestApplyCollectorPresetKeepsExistingBindAndToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Ingest.Bind = ":9999"
	cfg.Ingest.TokenEnv = "MY_TOKEN"
	if err := applyCollectorPreset(cfg, "", false); err != nil {
		t.Fatal(err)
	}
	if cfg.Ingest.Bind != ":9999" {
		t.Errorf("bind override clobbered config: %q", cfg.Ingest.Bind)
	}
	if cfg.Ingest.TokenEnv != "MY_TOKEN" {
		t.Errorf("token_env clobbered: %q", cfg.Ingest.TokenEnv)
	}
	// CLI --bind override wins.
	_ = applyCollectorPreset(cfg, ":7000", false)
	if cfg.Ingest.Bind != ":7000" {
		t.Errorf("--bind override not applied: %q", cfg.Ingest.Bind)
	}
}

func TestApplyCollectorPresetKeepListeners(t *testing.T) {
	cfg := &config.Config{
		Listeners: []config.Listener{{ID: "ssh", Proto: "tcp", Bind: ":22", Handler: "ssh"}},
	}
	if err := applyCollectorPreset(cfg, "", true); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Listeners) != 1 {
		t.Error("keepListeners should preserve honeypot listeners")
	}
	if !cfg.Ingest.Enabled {
		t.Error("ingest still enabled in combined mode")
	}
}
