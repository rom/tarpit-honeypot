package config

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Regression for the "validate-config passes but run crashes" class: an
// enabled subsystem whose severity is left blank must be defaulted by
// applyDefaults to a value the runtime can parse (the icmp_sweep + dns
// amplifier paths parse severity at construction, not just at validate).
func TestApplyDefaultsFillsEnabledSeverities(t *testing.T) {
	c := &Config{Sensor: Sensor{DataDir: "/tmp/x"}}
	c.Correlate.PortScan.Enabled = true
	c.Correlate.BruteForce.Enabled = true
	c.Correlate.SlowScan.Enabled = true
	c.Correlate.PasswordSpray.Enabled = true
	c.Correlate.CredReuse.Enabled = true
	c.Correlate.ICMPSweep.Enabled = true
	c.DNS.AmplifierDetection.Enabled = true
	c.applyDefaults()

	check := func(name, sev string) {
		if sev == "" {
			t.Errorf("%s: severity empty after applyDefaults", name)
			return
		}
		if _, err := event.ParseSeverity(sev); err != nil {
			t.Errorf("%s: severity %q does not parse: %v", name, sev, err)
		}
	}
	check("port_scan", c.Correlate.PortScan.Severity)
	check("brute_force", c.Correlate.BruteForce.Severity)
	check("slow_scan", c.Correlate.SlowScan.Severity)
	check("password_spray", c.Correlate.PasswordSpray.Severity)
	check("credential_reuse", c.Correlate.CredReuse.Severity)
	check("icmp_sweep", c.Correlate.ICMPSweep.Severity)
	check("dns.amplifier_detection", c.DNS.AmplifierDetection.Severity)
}

// An enabled icmp_sweep with no severity must validate (it's defaulted),
// and a bad severity must be rejected at validate time (not run time).
func TestICMPSweepSeverityValidation(t *testing.T) {
	ok := &Config{Sensor: Sensor{DataDir: "/tmp/x"}, Channels: []Channel{{ID: "c", Type: "stdout"}}}
	ok.Correlate.ICMPSweep.Enabled = true
	ok.applyDefaults()
	if err := ok.Validate(); err != nil {
		t.Errorf("icmp_sweep with defaulted severity should validate: %v", err)
	}

	bad := &Config{Sensor: Sensor{DataDir: "/tmp/x"}, Channels: []Channel{{ID: "c", Type: "stdout"}}}
	bad.Correlate.ICMPSweep.Enabled = true
	bad.Correlate.ICMPSweep.Severity = "hgih" // typo
	bad.applyDefaults()
	if err := bad.Validate(); err == nil {
		t.Error("a typo'd icmp_sweep severity must be rejected at validate time")
	}
}
