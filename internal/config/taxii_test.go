package config

import (
	"strings"
	"testing"
)

// mkTAXIICfg builds a minimal otherwise-valid config so Validate reaches the
// taxii/misp branches, then applies the mutation.
func mkTAXIICfg(mut func(*Config)) *Config {
	c := &Config{
		Sensor:    Sensor{Name: "t", DataDir: "/tmp/x"},
		Listeners: []Listener{{ID: "l", Proto: "tcp", Bind: "0.0.0.0:9", Mode: "banner", Handler: "raw", Banner: "x"}},
		Channels:  []Channel{{ID: "log", Type: "stdout"}},
	}
	mut(c)
	c.applyDefaults()
	return c
}

func TestTAXIIDefaultsAndFleetAutoEnable(t *testing.T) {
	// Enabling taxii fills a default bind and auto-enables single-node fleet
	// correlation (its IOC source), so a standalone sensor can be polled.
	c := mkTAXIICfg(func(c *Config) { c.TAXII.Enabled = true; c.TAXII.TokenEnv = "TOK" })
	if c.TAXII.Bind != "127.0.0.1:8471" {
		t.Errorf("taxii bind default = %q, want 127.0.0.1:8471", c.TAXII.Bind)
	}
	if c.Fleet.Enabled == nil || !*c.Fleet.Enabled {
		t.Errorf("taxii should auto-enable fleet correlation, got %v", c.Fleet.Enabled)
	}

	// MISP push does the same (its IOC source is the same intel store).
	m := mkTAXIICfg(func(c *Config) { c.MISP.Enabled = true; c.MISP.URL = "https://m"; c.MISP.KeyEnv = "K" })
	if m.Fleet.Enabled == nil || !*m.Fleet.Enabled {
		t.Errorf("misp should auto-enable fleet correlation, got %v", m.Fleet.Enabled)
	}

	// An explicit fleet.enabled is never overridden by the auto-enable.
	off := false
	ex := mkTAXIICfg(func(c *Config) {
		c.TAXII.Enabled = true
		c.TAXII.TokenEnv = "TOK"
		c.Fleet.Enabled = &off
	})
	if ex.Fleet.Enabled == nil || *ex.Fleet.Enabled {
		t.Errorf("explicit fleet.enabled=false must be preserved, got %v", ex.Fleet.Enabled)
	}
}

func TestTAXIIValidation(t *testing.T) {
	// A token is mandatory — an empty token 401s every route, so reject at load.
	err := mkTAXIICfg(func(c *Config) { c.TAXII.Enabled = true }).Validate()
	if err == nil || !strings.Contains(err.Error(), "token_env") {
		t.Errorf("taxii without token_env should error on token_env, got: %v", err)
	}

	// tls_cert / tls_key must be set together.
	err = mkTAXIICfg(func(c *Config) {
		c.TAXII.Enabled = true
		c.TAXII.TokenEnv = "TOK"
		c.TAXII.TLSCert = "cert.pem"
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "tls_cert and tls_key") {
		t.Errorf("taxii with only tls_cert should error, got: %v", err)
	}

	// Fully specified: valid.
	if err := mkTAXIICfg(func(c *Config) {
		c.TAXII.Enabled = true
		c.TAXII.Bind = "0.0.0.0:8471"
		c.TAXII.TokenEnv = "TOK"
	}).Validate(); err != nil {
		t.Errorf("well-formed taxii config should validate, got: %v", err)
	}
}
