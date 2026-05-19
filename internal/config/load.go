package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Sensor.DataDir == "" {
		c.Sensor.DataDir = "/var/lib/tarpit-honeypot"
	}
	if c.Sensor.Disk.JSONLogMB == 0 {
		c.Sensor.Disk.JSONLogMB = 500
	}
	if c.Sensor.Disk.SQLiteMB == 0 {
		c.Sensor.Disk.SQLiteMB = 500
	}
	if c.Sensor.Disk.PcapMB == 0 {
		c.Sensor.Disk.PcapMB = 1024
	}
	if c.Dedup.DefaultWindow == 0 {
		c.Dedup.DefaultWindow = 5 * time.Minute
	}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Mode == "" {
			l.Mode = "drop"
		}
		if l.Handler == "" {
			l.Handler = "raw"
		}
		if l.Severity == "" {
			l.Severity = "medium"
		}
		if l.ReadBytes == 0 {
			l.ReadBytes = 1024
		}
		if l.ReadTimeout == 0 {
			l.ReadTimeout = 5 * time.Second
		}
		if l.Mode == "tarpit" {
			t := &l.Tarpit
			if t.Strategy == "" {
				t.Strategy = "sticky"
			}
			if t.MaxPerSource == 0 {
				t.MaxPerSource = 4
			}
			if t.MaxTotal == 0 {
				t.MaxTotal = 256
			}
			if t.Trickle.ByteInterval == 0 {
				t.Trickle.ByteInterval = 2 * time.Second
			}
			if t.Keepalive.Interval == 0 {
				t.Keepalive.Interval = 30 * time.Second
			}
		}
	}
	for i := range c.Canaries {
		ca := &c.Canaries[i]
		if ca.Severity == "" {
			ca.Severity = "critical"
		}
		if len(ca.Events) == 0 {
			ca.Events = []string{"write", "remove", "rename"}
		}
	}
	if c.Correlate.PortScan.Enabled {
		if c.Correlate.PortScan.DistinctPorts == 0 {
			c.Correlate.PortScan.DistinctPorts = 5
		}
		if c.Correlate.PortScan.Window == 0 {
			c.Correlate.PortScan.Window = 30 * time.Second
		}
		if c.Correlate.PortScan.Severity == "" {
			c.Correlate.PortScan.Severity = "high"
		}
	}
	if c.Correlate.BruteForce.Enabled {
		if c.Correlate.BruteForce.Attempts == 0 {
			c.Correlate.BruteForce.Attempts = 10
		}
		if c.Correlate.BruteForce.Window == 0 {
			c.Correlate.BruteForce.Window = 60 * time.Second
		}
		if c.Correlate.BruteForce.Severity == "" {
			c.Correlate.BruteForce.Severity = "high"
		}
	}
	for i := range c.Channels {
		ch := &c.Channels[i]
		if ch.MinSeverity == "" {
			ch.MinSeverity = "low"
		}
		if ch.Type == "webhook" && ch.Timeout == 0 {
			ch.Timeout = 5 * time.Second
		}
		if ch.Type == "syslog" && ch.Network == "" {
			ch.Network = "local"
		}
		if ch.Type == "syslog" && ch.Tag == "" {
			ch.Tag = "tarpit-honeypot"
		}
	}
}

func (c *Config) Validate() error {
	// Listeners.
	seenID := map[string]bool{}
	seenBind := map[string]bool{}
	for i, l := range c.Listeners {
		if l.ID == "" {
			return fmt.Errorf("listeners[%d]: id is required", i)
		}
		if seenID[l.ID] {
			return fmt.Errorf("listener id %q duplicated", l.ID)
		}
		seenID[l.ID] = true
		if l.Proto != "tcp" && l.Proto != "udp" {
			return fmt.Errorf("listener %s: proto must be tcp or udp", l.ID)
		}
		if l.Bind == "" {
			return fmt.Errorf("listener %s: bind is required", l.ID)
		}
		key := l.Proto + "://" + l.Bind
		if seenBind[key] {
			return fmt.Errorf("listener %s: duplicate bind %s", l.ID, key)
		}
		seenBind[key] = true
		switch l.Mode {
		case "drop", "banner", "tarpit":
		default:
			return fmt.Errorf("listener %s: unknown mode %q", l.ID, l.Mode)
		}
		switch l.Handler {
		case "raw", "ssh", "http", "https", "telnet", "ftp":
		default:
			return fmt.Errorf("listener %s: unknown handler %q", l.ID, l.Handler)
		}
		if l.Handler != "raw" && l.Proto != "tcp" {
			return fmt.Errorf("listener %s: handler %s is tcp-only", l.ID, l.Handler)
		}
		if l.Mode == "banner" && l.Handler == "raw" && l.Banner == "" {
			return fmt.Errorf("listener %s: banner mode with raw handler requires a banner string", l.ID)
		}
		if l.Mode == "tarpit" {
			if l.Proto != "tcp" {
				return fmt.Errorf("listener %s: tarpit is tcp-only", l.ID)
			}
			switch l.Tarpit.Strategy {
			case "sticky", "trickle", "keepalive":
			default:
				return fmt.Errorf("listener %s: unknown tarpit strategy %q", l.ID, l.Tarpit.Strategy)
			}
			if l.Tarpit.Strategy == "trickle" && l.Tarpit.Trickle.Text == "" {
				return fmt.Errorf("listener %s: trickle strategy requires tarpit.trickle.text", l.ID)
			}
		}
		if _, err := event.ParseSeverity(l.Severity); err != nil {
			return fmt.Errorf("listener %s: %w", l.ID, err)
		}
	}

	// Canaries.
	canID := map[string]bool{}
	for i, ca := range c.Canaries {
		if ca.ID == "" {
			return fmt.Errorf("canaries[%d]: id is required", i)
		}
		if canID[ca.ID] {
			return fmt.Errorf("canary id %q duplicated", ca.ID)
		}
		canID[ca.ID] = true
		if ca.Path == "" {
			return fmt.Errorf("canary %s: path is required", ca.ID)
		}
		for _, evname := range ca.Events {
			switch evname {
			case "write", "remove", "rename", "create", "chmod":
			default:
				return fmt.Errorf("canary %s: unknown event %q", ca.ID, evname)
			}
		}
		if _, err := event.ParseSeverity(ca.Severity); err != nil {
			return fmt.Errorf("canary %s: %w", ca.ID, err)
		}
	}

	// Correlator severities.
	if c.Correlate.PortScan.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.PortScan.Severity); err != nil {
			return fmt.Errorf("correlate.port_scan: %w", err)
		}
	}
	if c.Correlate.BruteForce.Enabled {
		if _, err := event.ParseSeverity(c.Correlate.BruteForce.Severity); err != nil {
			return fmt.Errorf("correlate.brute_force: %w", err)
		}
	}

	// Allowlist.
	for i, s := range c.Allowlist {
		if _, err := netip.ParsePrefix(s); err != nil {
			if _, err2 := netip.ParseAddr(s); err2 != nil {
				return fmt.Errorf("allowlist[%d]: %q is not a valid IP or CIDR", i, s)
			}
		}
	}

	// Channels.
	chanByID := map[string]bool{}
	for i, ch := range c.Channels {
		if ch.ID == "" {
			return fmt.Errorf("channels[%d]: id is required", i)
		}
		if chanByID[ch.ID] {
			return fmt.Errorf("channel id %q duplicated", ch.ID)
		}
		chanByID[ch.ID] = true
		switch ch.Type {
		case "stdout", "jsonlog":
		case "webhook":
			if ch.URL == "" {
				return fmt.Errorf("channel %s: webhook needs url", ch.ID)
			}
			if !strings.HasPrefix(ch.URL, "http://") && !strings.HasPrefix(ch.URL, "https://") {
				return fmt.Errorf("channel %s: webhook url must be http(s)://", ch.ID)
			}
		case "smtp":
			if ch.Host == "" || ch.Port == 0 || ch.From == "" || len(ch.To) == 0 {
				return fmt.Errorf("channel %s: smtp needs host, port, from, to", ch.ID)
			}
		case "syslog":
			switch ch.Network {
			case "local", "tcp", "udp", "unix":
			default:
				return fmt.Errorf("channel %s: syslog network must be local|tcp|udp|unix", ch.ID)
			}
			if ch.Network != "local" && ch.Address == "" {
				return fmt.Errorf("channel %s: syslog network=%s requires address", ch.ID, ch.Network)
			}
		default:
			return fmt.Errorf("channel %s: unknown type %q", ch.ID, ch.Type)
		}
		if _, err := event.ParseSeverity(ch.MinSeverity); err != nil {
			return fmt.Errorf("channel %s: %w", ch.ID, err)
		}
	}

	// Routes.
	for i, r := range c.Routes {
		if r.Match.Severity != "" {
			if _, _, err := parseSeverityMatch(r.Match.Severity); err != nil {
				return fmt.Errorf("routes[%d]: %w", i, err)
			}
		}
		for _, id := range r.Channels {
			if !chanByID[id] {
				return fmt.Errorf("routes[%d]: references unknown channel %q", i, id)
			}
		}
	}
	return nil
}

// parseSeverityMatch parses ">=low" / "<high" / "=critical" into (op, sev).
func parseSeverityMatch(s string) (string, event.Severity, error) {
	s = strings.TrimSpace(s)
	var op, rest string
	switch {
	case strings.HasPrefix(s, ">="), strings.HasPrefix(s, "<="):
		op, rest = s[:2], s[2:]
	case strings.HasPrefix(s, ">"), strings.HasPrefix(s, "<"), strings.HasPrefix(s, "="):
		op, rest = s[:1], s[1:]
	default:
		op, rest = "=", s
	}
	sev, err := event.ParseSeverity(strings.TrimSpace(rest))
	if err != nil {
		return "", 0, fmt.Errorf("invalid severity match %q: %w", s, err)
	}
	return op, sev, nil
}

// SeverityMatches evaluates a parsed match against an event severity.
func SeverityMatches(spec string, sev event.Severity) (bool, error) {
	if spec == "" {
		return true, nil
	}
	op, target, err := parseSeverityMatch(spec)
	if err != nil {
		return false, err
	}
	switch op {
	case "=":
		return sev == target, nil
	case ">":
		return sev > target, nil
	case ">=":
		return sev >= target, nil
	case "<":
		return sev < target, nil
	case "<=":
		return sev <= target, nil
	}
	return false, fmt.Errorf("unknown operator %q", op)
}
