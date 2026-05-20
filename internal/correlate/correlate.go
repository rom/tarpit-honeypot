// Package correlate maintains short-lived in-memory state across events to
// detect port-scans, brute-force attempts (with credential extraction),
// and long-window slow scans from a single source.
//
// Each call to Observe returns the original event plus any aggregate events
// that fired as a result. Concurrent-safe via a single per-correlator mutex.
package correlate

import (
	"strconv"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Correlator struct {
	cfg      config.Correlate
	scanSev  event.Severity
	bruteSev event.Severity
	slowSev  event.Severity
	sweepSev event.Severity

	mu      sync.Mutex
	scan    map[string]*scanState      // key: source IP
	brute   map[string]*bruteState     // key: source IP (+ ":<port>" if PerPort)
	slow    map[string]*slowState      // key: source IP
	sweep   map[string]*sweepState     // key: source IP
	story   map[string]*storylineState // key: source IP
	emitted map[string]time.Time       // dedup of aggregate emission
}

type scanState struct {
	since time.Time
	ports map[int]struct{}
}

type bruteState struct {
	since time.Time
	count int
	// creds is a per-source set of unique credential pairs seen. Capped at
	// 50 to avoid unbounded growth under a long brute-force.
	creds map[string]struct{}
}

type slowState struct {
	firstSeen time.Time
	lastSeen  time.Time
	ports     map[int]time.Time // port -> first-seen
}

type sweepState struct {
	since time.Time
	ips   map[string]struct{} // distinct destination IPs touched via ICMP
}

func New(cfg config.Correlate) (*Correlator, error) {
	c := &Correlator{
		cfg:     cfg,
		scan:    map[string]*scanState{},
		brute:   map[string]*bruteState{},
		slow:    map[string]*slowState{},
		sweep:   map[string]*sweepState{},
		story:   map[string]*storylineState{},
		emitted: map[string]time.Time{},
	}
	if cfg.PortScan.Enabled {
		s, err := event.ParseSeverity(cfg.PortScan.Severity)
		if err != nil {
			return nil, err
		}
		c.scanSev = s
	}
	if cfg.BruteForce.Enabled {
		s, err := event.ParseSeverity(cfg.BruteForce.Severity)
		if err != nil {
			return nil, err
		}
		c.bruteSev = s
	}
	if cfg.SlowScan.Enabled {
		s, err := event.ParseSeverity(cfg.SlowScan.Severity)
		if err != nil {
			return nil, err
		}
		c.slowSev = s
	}
	if cfg.ICMPSweep.Enabled {
		s, err := event.ParseSeverity(cfg.ICMPSweep.Severity)
		if err != nil {
			return nil, err
		}
		c.sweepSev = s
	}
	return c, nil
}

// Observe ingests an event and returns it plus any aggregate events that
// fired. Always returns at least one event (the original).
func (c *Correlator) Observe(ev *event.Event) []*event.Event {
	out := []*event.Event{ev}
	if ev.Source.IP == "" {
		return out
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := ev.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// ICMP sweep is checked first because ICMP events carry no dest
	// port — they'd be dropped by the port-requiring guard below.
	if c.cfg.ICMPSweep.Enabled && ev.Proto == "icmp" {
		if extra := c.checkSweep(ev, now); extra != nil {
			out = append(out, extra)
		}
	}

	// Everything past here keys on a destination port.
	if ev.Dest.Port == 0 {
		// Still feed the storyline correlator (it keys on tactics, not
		// ports) before returning.
		if extra := c.observeStoryline(ev, now); extra != nil {
			out = append(out, extra)
		}
		return out
	}

	if c.cfg.PortScan.Enabled {
		if extra := c.checkScan(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.BruteForce.Enabled {
		if extra := c.checkBrute(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.SlowScan.Enabled {
		if extra := c.checkSlowScan(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if extra := c.observeStoryline(ev, now); extra != nil {
		out = append(out, extra)
	}
	return out
}

func (c *Correlator) checkScan(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.PortScan
	st, ok := c.scan[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &scanState{since: now, ports: map[int]struct{}{}}
		c.scan[ev.Source.IP] = st
	}
	st.ports[ev.Dest.Port] = struct{}{}
	if len(st.ports) < cfg.DistinctPorts {
		return nil
	}
	if !c.shouldEmit("scan|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ports := make([]int, 0, len(st.ports))
	for p := range st.ports {
		ports = append(ports, p)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:port_scan",
		Severity: c.scanSev,
		Source:   ev.Source,
		Proto:    "tcp",
		Meta: map[string]any{
			"distinct_ports": len(ports),
			"window_s":       int(cfg.Window.Seconds()),
			"ports":          ports,
		},
	}
}

// checkSweep detects an ICMP ping sweep: one source touching
// DistinctIPs distinct destination IPs via ICMP within Window. The
// destination IP comes from ev.Dest.IP (the honeynet host the ICMP
// responder answered for). Called with c.mu held.
func (c *Correlator) checkSweep(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.ICMPSweep
	dst := ev.Dest.IP
	if dst == "" {
		// Some ICMP events carry the touched IP in meta instead.
		if m, ok := ev.Meta["target_ip"].(string); ok {
			dst = m
		}
	}
	if dst == "" {
		return nil
	}
	st, ok := c.sweep[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &sweepState{since: now, ips: map[string]struct{}{}}
		c.sweep[ev.Source.IP] = st
	}
	st.ips[dst] = struct{}{}
	if len(st.ips) < cfg.DistinctIPs {
		return nil
	}
	if !c.shouldEmit("sweep|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ips := make([]string, 0, len(st.ips))
	for ip := range st.ips {
		ips = append(ips, ip)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:icmp_sweep",
		Severity: c.sweepSev,
		Source:   ev.Source,
		Proto:    "icmp",
		Meta: map[string]any{
			"distinct_ips": len(ips),
			"window_s":     int(cfg.Window.Seconds()),
			"targets":      ips,
		},
	}
}

func (c *Correlator) checkBrute(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.BruteForce
	key := ev.Source.IP
	if cfg.PerPort {
		key += ":" + strconv.Itoa(ev.Dest.Port)
	}
	st, ok := c.brute[key]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &bruteState{since: now, creds: map[string]struct{}{}}
		c.brute[key] = st
	}
	st.count++
	if pair := extractCreds(ev); pair != "" {
		if len(st.creds) < 50 {
			st.creds[pair] = struct{}{}
		}
	}
	if st.count < cfg.Attempts {
		return nil
	}
	if !c.shouldEmit("brute|"+key, cfg.Window) {
		return nil
	}
	credList := make([]string, 0, len(st.creds))
	for k := range st.creds {
		credList = append(credList, k)
	}
	meta := map[string]any{
		"attempts":     st.count,
		"window_s":     int(cfg.Window.Seconds()),
		"unique_creds": len(credList),
	}
	if len(credList) > 0 {
		meta["credentials"] = credList
	}
	if cfg.PerPort {
		meta["port"] = ev.Dest.Port
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:brute_force",
		Severity: c.bruteSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Meta:     meta,
	}
}

// checkSlowScan tracks port-touches over a long window (default 24h).
// Unlike port_scan, this state is NOT reset on each new event — it
// only ages out per-port entries older than the window so a one-port-
// per-hour scan accumulates over the day.
func (c *Correlator) checkSlowScan(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.SlowScan
	st, ok := c.slow[ev.Source.IP]
	if !ok {
		st = &slowState{firstSeen: now, ports: map[int]time.Time{}}
		c.slow[ev.Source.IP] = st
	}
	st.lastSeen = now
	if _, seen := st.ports[ev.Dest.Port]; !seen {
		st.ports[ev.Dest.Port] = now
	}
	// Age out old ports.
	cutoff := now.Add(-cfg.Window)
	for p, t := range st.ports {
		if t.Before(cutoff) {
			delete(st.ports, p)
		}
	}
	if len(st.ports) < cfg.DistinctPorts {
		return nil
	}
	if !c.shouldEmit("slow|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ports := make([]int, 0, len(st.ports))
	for p := range st.ports {
		ports = append(ports, p)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:slow_scan",
		Severity: c.slowSev,
		Source:   ev.Source,
		Proto:    "tcp",
		Meta: map[string]any{
			"distinct_ports": len(ports),
			"window_hours":   int(cfg.Window.Hours()),
			"first_seen":     st.firstSeen.Format(time.RFC3339),
			"last_seen":      st.lastSeen.Format(time.RFC3339),
			"ports":          ports,
			"spread_seconds": int(st.lastSeen.Sub(st.firstSeen).Seconds()),
		},
	}
}

// extractCreds pulls a credential pair out of well-known event meta keys.
// Returns "" when no credentials are present.
//
// Recognized meta layout:
//
//	ssh handlers don't capture passwords, but client_id is unique-ish
//	ftp -> user_line / pass_line
//	smtp_recv -> auth_user / auth_pass
//	mqtt -> username / password
//	ldap -> bind_dn / bind_pw
//	postgres -> startup_params[user] / password
//	mysql -> username / (auth_response_hex used as "the hashed password")
//	redis -> auth_password (no username)
//	vnc -> auth_response_hex (the DES-encrypted password)
//	winrm -> basic_user / basic_pass
func extractCreds(ev *event.Event) string {
	if ev.Meta == nil {
		return ""
	}
	get := func(k string) string {
		if v, ok := ev.Meta[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	// User + pass pairs.
	pairs := [][2]string{
		{"auth_user", "auth_pass"},
		{"username", "password"},
		{"basic_user", "basic_pass"},
		{"bind_dn", "bind_pw"},
		{"user_line", "pass_line"},
	}
	for _, p := range pairs {
		u := get(p[0])
		pw := get(p[1])
		if u != "" || pw != "" {
			return u + ":" + pw
		}
	}
	// Postgres: startup_params has the user, password is a separate meta key.
	if pwd := get("password"); pwd != "" {
		if params, ok := ev.Meta["startup_params"].(map[string]string); ok {
			return params["user"] + ":" + pwd
		}
		return ":" + pwd
	}
	// MySQL: only the auth response is exposed (it's a hash).
	if u := get("username"); u != "" {
		if h := get("auth_response_hex"); h != "" {
			return u + ":hash=" + h
		}
	}
	// Redis: AUTH leaks just the password.
	if pwd := get("auth_password"); pwd != "" {
		return ":" + pwd
	}
	// VNC: auth response is opaque.
	if h := get("auth_response_hex"); h != "" {
		return ":hash=" + h
	}
	return ""
}

// shouldEmit collapses repeated aggregate events for the same key within
// the window so a sustained scan doesn't flood the sinks.
func (c *Correlator) shouldEmit(key string, window time.Duration) bool {
	now := time.Now()
	if t, ok := c.emitted[key]; ok && now.Sub(t) < window {
		return false
	}
	c.emitted[key] = now
	return true
}
