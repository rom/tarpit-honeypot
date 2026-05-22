package config

import (
	"strings"
	"testing"
)

func TestInteractionDefaults(t *testing.T) {
	var in Interaction
	in.ApplyDefaults()
	if in.Mode != InteractionLow || in.HTTP2ProbeCapture != HTTP2CaptureDisabled ||
		in.SSHKexDepth != SSHKexInitOnly || in.BrowserTraps != BrowserTrapsOff {
		t.Fatalf("defaults not low-interaction: %+v", in)
	}
	if in.Experimental() {
		t.Error("default must not be experimental")
	}
}

func TestInteractionValidateGuardrails(t *testing.T) {
	low := func() Interaction { i := Interaction{}; i.ApplyDefaults(); return i }

	if err := low().validate(); err != nil {
		t.Fatalf("low defaults should validate: %v", err)
	}

	// Experimental knobs are forbidden in low mode.
	bad := low()
	bad.SSHKexDepth = SSHKexExtendedExp
	if err := bad.validate(); err == nil {
		t.Error("extended ssh kex must be rejected in low mode")
	}
	bad = low()
	bad.HTTP2ProbeCapture = HTTP2CaptureHeaders
	if err := bad.validate(); err == nil {
		t.Error("headers_only http2 must be rejected in low mode")
	}

	// Allowed in medium_experimental.
	ok := Interaction{Mode: InteractionMediumExp, HTTP2ProbeCapture: HTTP2CaptureHeaders, SSHKexDepth: SSHKexExtendedExp, BrowserTraps: BrowserTrapsOff}
	if err := ok.validate(); err != nil {
		t.Errorf("medium_experimental with experimental knobs should validate: %v", err)
	}

	// browser_traps can only be off.
	bt := low()
	bt.BrowserTraps = "on"
	if err := bt.validate(); err == nil {
		t.Error("browser_traps must be locked to off")
	}

	// Unknown mode rejected.
	if (Interaction{Mode: "high"}).validate() == nil {
		t.Error("unknown mode must be rejected")
	}
}

func TestUnavailableCapabilities(t *testing.T) {
	statusOf := func(caps []Capability, name string) string {
		for _, c := range caps {
			if c.Name == name {
				return c.Status
			}
		}
		return ""
	}

	low := Interaction{}
	low.ApplyDefaults()
	lc := low.UnavailableCapabilities()
	if statusOf(lc, "ssh-kex-extended") != CapLocked {
		t.Error("ssh-kex-extended should be locked in low mode")
	}
	if statusOf(lc, "browser-traps") != CapUnavailable {
		t.Error("browser-traps should be unavailable")
	}
	if statusOf(lc, "smb-ntlmv2-capture") != CapUnavailable {
		t.Error("smb-ntlmv2-capture should be unavailable")
	}

	med := Interaction{Mode: InteractionMediumExp, SSHKexDepth: SSHKexExtendedExp}
	med.ApplyDefaults()
	if statusOf(med.UnavailableCapabilities(), "ssh-kex-extended") != CapExperimental {
		t.Error("ssh-kex-extended should be experimental when enabled in medium mode")
	}
}

func TestInteractionValidateViaConfig(t *testing.T) {
	// The guardrail must fire through the full Config.Validate path.
	c := &Config{}
	c.Interaction = Interaction{Mode: InteractionLow, HTTP2ProbeCapture: HTTP2CaptureHeaders}
	c.applyDefaults()
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "http2_probe_capture") {
		t.Fatalf("expected http2 guardrail error from Config.Validate, got %v", err)
	}
}
