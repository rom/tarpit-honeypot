package config

import "fmt"

// Interaction declares the honeypot's interaction depth and gates the
// experimental / high-interaction capture features behind explicit flags.
// Its purpose is honesty: the docs note that some signals are infeasible in a
// low-interaction emulator, and this section makes that a hard guardrail so an
// operator never assumes a capability exists when it can't actually be
// produced. `list-unavailable-capabilities` prints the resulting matrix.
//
// Default is fully low-interaction. The "*_experimental" values are only
// permitted when mode is medium_experimental; setting one in low mode is a
// config error (not a silent downgrade), so the intent is explicit.
type Interaction struct {
	// Mode is the overall interaction depth:
	//   low                 — the safe default; every emitted capture is
	//                         something a low-interaction emulator can really
	//                         produce.
	//   medium_experimental — unlocks the experimental capture knobs below.
	//                         Best-effort and possibly incomplete; the sensor
	//                         is still never a real browser / OS / crypto stack.
	Mode string `yaml:"mode"`
	// HTTP2ProbeCapture: disabled | headers_only. headers_only requires
	// medium_experimental. Full HTTP/2 frame / HPACK / multiplexed-stream
	// reconstruction is NOT implemented in any mode (future-proof knob).
	HTTP2ProbeCapture string `yaml:"http2_probe_capture"`
	// SSHKexDepth: kexinit_only | extended_experimental. kexinit_only (the
	// default) captures the client KEXINIT for HASSH; extended_experimental
	// requires medium_experimental and is a placeholder for deeper, best-
	// effort KEX capture.
	SSHKexDepth string `yaml:"ssh_kex_depth"`
	// BrowserTraps: off. Locked off — no real browser is ever driven, so
	// JS / canvas / beacon traps cannot execute. Present so the knob is
	// explicit rather than assumed.
	BrowserTraps string `yaml:"browser_traps"`
}

// Interaction mode + knob values.
const (
	InteractionLow       = "low"
	InteractionMediumExp = "medium_experimental"
	HTTP2CaptureDisabled = "disabled"
	HTTP2CaptureHeaders  = "headers_only"
	SSHKexInitOnly       = "kexinit_only"
	SSHKexExtendedExp    = "extended_experimental"
	BrowserTrapsOff      = "off"
)

// ApplyDefaults fills the zero values with the low-interaction defaults.
func (in *Interaction) ApplyDefaults() {
	if in.Mode == "" {
		in.Mode = InteractionLow
	}
	if in.HTTP2ProbeCapture == "" {
		in.HTTP2ProbeCapture = HTTP2CaptureDisabled
	}
	if in.SSHKexDepth == "" {
		in.SSHKexDepth = SSHKexInitOnly
	}
	if in.BrowserTraps == "" {
		in.BrowserTraps = BrowserTrapsOff
	}
}

// Experimental reports whether the medium_experimental mode is selected.
func (in Interaction) Experimental() bool { return in.Mode == InteractionMediumExp }

// validate checks the enum values and enforces the low-mode guardrail: the
// experimental values may only be set when mode is medium_experimental.
func (in Interaction) validate() error {
	switch in.Mode {
	case InteractionLow, InteractionMediumExp:
	default:
		return fmt.Errorf("interaction.mode must be %q or %q (got %q)", InteractionLow, InteractionMediumExp, in.Mode)
	}
	switch in.HTTP2ProbeCapture {
	case HTTP2CaptureDisabled:
	case HTTP2CaptureHeaders:
		if in.Mode != InteractionMediumExp {
			return fmt.Errorf("interaction.http2_probe_capture: %q requires interaction.mode: %q", HTTP2CaptureHeaders, InteractionMediumExp)
		}
	default:
		return fmt.Errorf("interaction.http2_probe_capture must be %q or %q (got %q)", HTTP2CaptureDisabled, HTTP2CaptureHeaders, in.HTTP2ProbeCapture)
	}
	switch in.SSHKexDepth {
	case SSHKexInitOnly:
	case SSHKexExtendedExp:
		if in.Mode != InteractionMediumExp {
			return fmt.Errorf("interaction.ssh_kex_depth: %q requires interaction.mode: %q", SSHKexExtendedExp, InteractionMediumExp)
		}
	default:
		return fmt.Errorf("interaction.ssh_kex_depth must be %q or %q (got %q)", SSHKexInitOnly, SSHKexExtendedExp, in.SSHKexDepth)
	}
	if in.BrowserTraps != BrowserTrapsOff {
		return fmt.Errorf("interaction.browser_traps must be %q (no real browser is driven; this knob is locked off)", BrowserTrapsOff)
	}
	return nil
}

// Capability describes one high-interaction / experimental feature and its
// current availability under the active Interaction config.
type Capability struct {
	Name   string `json:"name"`
	Status string `json:"status"` // disabled | experimental | locked | unavailable
	Reason string `json:"reason"`
}

// Capability status values.
const (
	CapDisabled     = "disabled"     // off by config, but enabling it is possible
	CapExperimental = "experimental" // enabled but best-effort / incomplete
	CapLocked       = "locked"       // forbidden in the current mode
	CapUnavailable  = "unavailable"  // not implemented / infeasible in any mode
)

// UnavailableCapabilities returns the high-interaction / experimental
// features and why each is not (fully) available under the current config.
// It is the source of truth for `list-unavailable-capabilities`, so an
// operator can see exactly which signals the deployment cannot produce
// instead of inferring it from the docs.
func (in Interaction) UnavailableCapabilities() []Capability {
	var caps []Capability

	// HTTP/2 request capture.
	switch {
	case in.HTTP2ProbeCapture == HTTP2CaptureHeaders:
		caps = append(caps, Capability{"http2-request-capture", CapExperimental,
			"headers_only: pseudo-header capture is best-effort; HPACK bodies and multiplexed-stream reconstruction are not implemented"})
	case in.Mode != InteractionMediumExp:
		caps = append(caps, Capability{"http2-request-capture", CapLocked,
			"locked in low mode; needs interaction.mode: medium_experimental + http2_probe_capture: headers_only (still header-only)"})
	default:
		caps = append(caps, Capability{"http2-request-capture", CapDisabled,
			"set interaction.http2_probe_capture: headers_only to enable header-only capture"})
	}

	// Extended SSH KEX capture.
	if in.SSHKexDepth == SSHKexExtendedExp {
		caps = append(caps, Capability{"ssh-kex-extended", CapExperimental,
			"extended_experimental: best-effort; only the client KEXINIT (HASSH) is fully modelled"})
	} else if in.Mode != InteractionMediumExp {
		caps = append(caps, Capability{"ssh-kex-extended", CapLocked,
			"locked in low mode; only the client KEXINIT (HASSH) is captured. Needs medium_experimental + ssh_kex_depth: extended_experimental"})
	} else {
		caps = append(caps, Capability{"ssh-kex-extended", CapDisabled,
			"set interaction.ssh_kex_depth: extended_experimental to enable best-effort deeper KEX capture"})
	}

	// Browser traps — never available.
	caps = append(caps, Capability{"browser-traps", CapUnavailable,
		"no real browser is driven; JavaScript / canvas / beacon traps cannot execute (locked off in every mode)"})

	// Permanently-infeasible / not-implemented signals the docs warn about,
	// surfaced so they're explicit rather than assumed.
	caps = append(caps,
		Capability{"http3-quic-request-capture", CapUnavailable,
			"QUIC is fingerprinted (long-header) but never decrypted/parsed — no request capture"},
		Capability{"tls-passthrough-decryption", CapUnavailable,
			"the sensor terminates TLS; it never MITMs a real upstream, so passthrough decryption is out of scope"},
		Capability{"real-shell-execution", CapUnavailable,
			"shells are emulated; typed commands are captured + TTP-scanned, never executed"},
		Capability{"smb-ntlmv2-capture", CapUnavailable,
			"SMB is negotiate-level; full SESSION_SETUP / NTLMv2 challenge-response capture is not implemented"},
		Capability{"steganographic-transport-detection", CapUnavailable,
			"covert data hidden inside otherwise-valid traffic cannot be detected in general"},
	)
	return caps
}
