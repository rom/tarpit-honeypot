package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The sensor.enrichment block parses both the inline abuse.ch key and the
// env-var-name indirection. (The sensor doesn't consume these at runtime;
// scripts/fetch-enrichment.sh reads them.)
func TestEnrichmentConfigParses(t *testing.T) {
	var c Config
	body := `
sensor:
  enrichment:
    abuse_ch_auth_key: "inline-secret"
    abuse_ch_auth_key_env: ABUSE_CH_AUTH_KEY
`
	if err := yaml.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Sensor.Enrichment.AbuseCHAuthKey != "inline-secret" {
		t.Errorf("abuse_ch_auth_key = %q; want inline-secret", c.Sensor.Enrichment.AbuseCHAuthKey)
	}
	if c.Sensor.Enrichment.AbuseCHAuthKeyEnv != "ABUSE_CH_AUTH_KEY" {
		t.Errorf("abuse_ch_auth_key_env = %q; want ABUSE_CH_AUTH_KEY", c.Sensor.Enrichment.AbuseCHAuthKeyEnv)
	}

	// Absent block leaves both empty (and doesn't error).
	var empty Config
	if err := yaml.Unmarshal([]byte("sensor:\n  oui_file: /x\n"), &empty); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if empty.Sensor.Enrichment.AbuseCHAuthKey != "" || empty.Sensor.Enrichment.AbuseCHAuthKeyEnv != "" {
		t.Errorf("absent enrichment block should leave fields empty, got %+v", empty.Sensor.Enrichment)
	}
}
