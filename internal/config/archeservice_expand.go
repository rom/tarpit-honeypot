package config

import (
	"fmt"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/archeservice"
	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// expandArcheservices turns each archeservices[] entry into concrete
// Listeners — one per port the role exposes — carrying the entry's
// archetype so the handlers answer with software/version strings
// consistent with that OS/device. Idempotent (guarded). Unresolvable
// entries (unknown role / missing bind) are skipped here and reported by
// validateArcheservices.
func (c *Config) expandArcheservices() {
	if c.archeservicesExpanded {
		return
	}
	c.archeservicesExpanded = true
	for _, as := range c.Archeservices {
		svcs, ok := archeservice.Lookup(as.Role)
		if !ok || as.ID == "" || as.Bind == "" {
			continue
		}
		// A bind that already carries a port is invalid (the role supplies
		// ports); skip and let validateArcheservices report it.
		if _, _, err := net.SplitHostPort(as.Bind); err == nil {
			continue
		}
		mode := as.Mode
		if mode == "" {
			mode = "banner"
		}
		for _, s := range svcs {
			m := mode
			// The raw handler has no banner to send, so banner mode would
			// fail validation — accept + log the connection in drop mode.
			if s.Handler == "raw" && m == "banner" {
				m = "drop"
			}
			c.Listeners = append(c.Listeners, Listener{
				ID:            fmt.Sprintf("%s-%s%d", as.ID, s.Proto, s.Port),
				Proto:         s.Proto,
				Bind:          net.JoinHostPort(as.Bind, strconv.Itoa(s.Port)),
				Mode:          m,
				Handler:       s.Handler,
				Archetype:     as.Archetype,
				Severity:      as.Severity,
				Capture:       as.Capture,
				VulnEmulation: as.VulnEmulation,
			})
		}
	}
}

// validateArcheservices checks each archeservices[] entry. Called from
// Validate before the (now-expanded) listeners are validated, so role/bind
// mistakes get an archeservice-specific error.
func (c *Config) validateArcheservices() error {
	seen := map[string]bool{}
	for i, as := range c.Archeservices {
		if as.ID == "" {
			return fmt.Errorf("archeservices[%d]: id is required", i)
		}
		if seen[as.ID] {
			return fmt.Errorf("archeservice id %q duplicated", as.ID)
		}
		seen[as.ID] = true
		if _, ok := archeservice.Lookup(as.Role); !ok {
			return fmt.Errorf("archeservice %s: unknown role %q (see `tarpit-honeypot list-archeservices`)", as.ID, as.Role)
		}
		if as.Bind == "" {
			return fmt.Errorf("archeservice %s: bind (host/IP, no port) is required", as.ID)
		}
		if _, _, err := net.SplitHostPort(as.Bind); err == nil {
			return fmt.Errorf("archeservice %s: bind must be a host/IP without a port (got %q — the role supplies the ports)", as.ID, as.Bind)
		}
		if as.Archetype != "" && archetype.Find(as.Archetype) == nil {
			return fmt.Errorf("archeservice %s: unknown archetype %q", as.ID, as.Archetype)
		}
		switch as.Mode {
		case "", "banner", "drop", "tarpit":
		default:
			return fmt.Errorf("archeservice %s: unknown mode %q", as.ID, as.Mode)
		}
	}
	return nil
}
