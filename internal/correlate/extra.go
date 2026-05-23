package correlate

import (
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// This file holds the additional opt-in correlators layered on top of the
// core detectors in correlate.go. They follow the same contract: each
// check* method is called with c.mu held, returns a non-nil aggregate
// event the first time its source crosses a threshold within the window,
// and uses shouldEmit to collapse repeats. All are gated by their config's
// Enabled flag in Observe, so they cost nothing unless a deployment turns
// them on.

// windowedSet returns the per-key setState for now, resetting it when the
// previous one has aged past window. Called with c.mu held.
func windowedSet(m map[string]*setState, key string, now time.Time, window time.Duration) *setState {
	st, ok := m[key]
	if !ok || now.Sub(st.since) > window {
		st = &setState{since: now, set: map[string]struct{}{}}
		m[key] = st
	}
	return st
}

// setKeys returns the sorted members of a string set.
func setKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkHostSweep detects a horizontal sweep: one source touching
// DistinctHosts distinct destination (honeynet) hosts within the window.
func (c *Correlator) checkHostSweep(ev *event.Event, now time.Time) *event.Event {
	dst := ev.Dest.IP
	if dst == "" {
		if m, ok := ev.Meta["target_ip"].(string); ok {
			dst = m
		}
	}
	if dst == "" {
		return nil
	}
	cfg := c.cfg.HostSweep
	st := windowedSet(c.hostSweep, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[dst] = struct{}{}
	}
	if len(st.set) < cfg.DistinctHosts {
		return nil
	}
	if !c.shouldEmit("hostsweep|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:host_sweep",
		Severity: c.hostSweepSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"distinct_hosts": len(st.set),
			"hosts":          setKeys(st.set),
			"dest_port":      ev.Dest.Port,
			"window_s":       int(cfg.Window.Seconds()),
		},
	}
}

// checkServiceSweep detects cross-protocol recon: one source interacting
// with DistinctServices distinct handlers within the window.
func (c *Correlator) checkServiceSweep(ev *event.Event, now time.Time) *event.Event {
	if ev.Handler == "" {
		return nil
	}
	cfg := c.cfg.ServiceSweep
	st := windowedSet(c.svcSweep, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("svcsweep|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:service_sweep",
		Severity: c.svcSweepSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          setKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// checkUARotation detects User-Agent rotation: one source presenting
// DistinctAgents distinct HTTP User-Agents within the window.
func (c *Correlator) checkUARotation(ev *event.Event, now time.Time) *event.Event {
	ua, _ := ev.Meta["user_agent"].(string)
	if ua == "" {
		return nil
	}
	cfg := c.cfg.UARotation
	st := windowedSet(c.uaRot, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ua] = struct{}{}
	}
	if len(st.set) < cfg.DistinctAgents {
		return nil
	}
	if !c.shouldEmit("uarot|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:ua_rotation",
		Severity: c.uaRotSev,
		Source:   ev.Source,
		Dest:     event.Endpoint{Port: ev.Dest.Port},
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"distinct_agents": len(st.set),
			"user_agents":     setKeys(st.set),
			"window_s":        int(cfg.Window.Seconds()),
		},
	}
}

// checkExploitChain detects vuln chaining: one source attempting
// DistinctCVEs distinct CVEs (cve:* events) within the window.
func (c *Correlator) checkExploitChain(ev *event.Event, now time.Time) *event.Event {
	id := strings.TrimPrefix(ev.RuleID, "cve:")
	if id == ev.RuleID || id == "" { // not a cve: event
		return nil
	}
	cfg := c.cfg.ExploitChain
	st := windowedSet(c.exploit, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[id] = struct{}{}
	}
	if len(st.set) < cfg.DistinctCVEs {
		return nil
	}
	if !c.shouldEmit("exploit|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:exploit_chain",
		Severity: c.exploitSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"distinct_cves": len(st.set),
			"cves":          setKeys(st.set),
			"window_s":      int(cfg.Window.Seconds()),
		},
	}
}

// checkICSControl detects OT manipulation: Attempts control / write /
// restart commands to industrial-protocol handlers within the window.
func (c *Correlator) checkICSControl(ev *event.Event, now time.Time) *event.Event {
	if !icsControlSignal(ev) {
		return nil
	}
	cfg := c.cfg.ICSControl
	st, ok := c.ics[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &countState{since: now}
		c.ics[ev.Source.IP] = st
	}
	st.count++
	if st.count < cfg.Attempts {
		return nil
	}
	if !c.shouldEmit("ics|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:ics_control",
		Severity: c.icsSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"control_commands": st.count,
			"handler":          ev.Handler,
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}

// checkCanaryTrip detects decoy harvesting: one source tripping
// DistinctTokens distinct canary tokens / honeyfile URLs within the window.
func (c *Correlator) checkCanaryTrip(ev *event.Event, now time.Time) *event.Event {
	token := strings.TrimPrefix(ev.RuleID, "canary:")
	if token == ev.RuleID || token == "" { // not a canary: event
		return nil
	}
	cfg := c.cfg.CanaryTrip
	st := windowedSet(c.canary, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[token] = struct{}{}
	}
	if len(st.set) < cfg.DistinctTokens {
		return nil
	}
	if !c.shouldEmit("canary|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:canary_trip",
		Severity: c.canarySev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"distinct_tokens": len(st.set),
			"tokens":          setKeys(st.set),
			"window_s":        int(cfg.Window.Seconds()),
		},
	}
}

// checkFingerprintReuse detects a shared client fingerprint (JA3 / JA4 /
// HASSH) arriving from DistinctSources distinct source IPs within the
// window — a botnet / shared tool behind a rotating-IP pool. Keyed on the
// fingerprint value, not the source.
func (c *Correlator) checkFingerprintReuse(ev *event.Event, now time.Time) *event.Event {
	kind, val := pickFingerprint(ev)
	if val == "" {
		return nil
	}
	cfg := c.cfg.FingerprintReuse
	key := kind + ":" + val
	st, ok := c.fpReuse[key]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &reuseState{since: now, sources: map[string]struct{}{}}
		c.fpReuse[key] = st
	}
	if len(st.sources) < corrSetCap {
		st.sources[ev.Source.IP] = struct{}{}
	}
	if len(st.sources) < cfg.DistinctSources {
		return nil
	}
	if !c.shouldEmit("fpreuse|"+key, cfg.Window) {
		return nil
	}
	srcs := make([]string, 0, len(st.sources))
	for s := range st.sources {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:fingerprint_reuse",
		Severity: c.fpReuseSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"fingerprint_kind": kind,
			"fingerprint":      val,
			"distinct_sources": len(srcs),
			"sources":          srcs,
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}

// checkProtocolViolation detects fuzzing: one source tripping
// DistinctAnomalies distinct protocol-misuse markers within the window.
func (c *Correlator) checkProtocolViolation(ev *event.Event, now time.Time) *event.Event {
	if len(ev.Anomalies) == 0 {
		return nil
	}
	cfg := c.cfg.ProtocolViolation
	st := windowedSet(c.protoViol, ev.Source.IP, now, cfg.Window)
	for _, a := range ev.Anomalies {
		if len(st.set) >= corrSetCap {
			break
		}
		st.set[a] = struct{}{}
	}
	if len(st.set) < cfg.DistinctAnomalies {
		return nil
	}
	if !c.shouldEmit("protoviol|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:protocol_violation",
		Severity: c.protoViolSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"distinct_anomalies": len(st.set),
			"anomalies":          setKeys(st.set),
			"window_s":           int(cfg.Window.Seconds()),
		},
	}
}

// checkExfil detects bulk inbound transfer: cumulative request bytes from
// one source crossing the byte threshold within the window.
func (c *Correlator) checkExfil(ev *event.Event, now time.Time) *event.Event {
	n := eventBytes(ev)
	if n <= 0 {
		return nil
	}
	cfg := c.cfg.Exfil
	st, ok := c.exfil[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &byteState{since: now}
		c.exfil[ev.Source.IP] = st
	}
	st.bytes += n
	if st.bytes < cfg.Bytes {
		return nil
	}
	if !c.shouldEmit("exfil|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:exfil",
		Severity: c.exfilSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"bytes":    st.bytes,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}

// checkSessionFlood detects volumetric abuse: one source opening
// Connections connections within the window regardless of port spread.
func (c *Correlator) checkSessionFlood(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.SessionFlood
	st, ok := c.flood[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &countState{since: now}
		c.flood[ev.Source.IP] = st
	}
	st.count++
	if st.count < cfg.Connections {
		return nil
	}
	if !c.shouldEmit("flood|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:session_flood",
		Severity: c.floodSev,
		Source:   ev.Source,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"connections": st.count,
			"window_s":    int(cfg.Window.Seconds()),
		},
	}
}

// icsControlSignal reports whether an event represents an OT control / write
// / manipulation attempt rather than a passive read or probe. The
// industrial handlers flag these with a "<proto>-write-attempt" anomaly
// (modbus-write-attempt, bacnet-write-attempt, …); the contains-checks also
// future-proof for explicit -control / -stop / force markers.
func icsControlSignal(ev *event.Event) bool {
	for _, a := range ev.Anomalies {
		la := strings.ToLower(a)
		if strings.Contains(la, "write-attempt") ||
			strings.Contains(la, "-control") ||
			strings.HasSuffix(la, "-stop") ||
			strings.Contains(la, "force-attempt") {
			return true
		}
	}
	return false
}

// eventBytes returns the best-available inbound byte count for an event:
// the captured payload length, or a larger handler-reported byte meta.
func eventBytes(ev *event.Event) int64 {
	n := int64(ev.PayloadLen)
	for _, k := range []string{"bytes", "bytes_in", "request_bytes"} {
		if b, ok := metaInt(ev.Meta[k]); ok && b > n {
			n = b
		}
	}
	return n
}

// metaInt coerces a meta value (int / int64 / float64, as JSON round-trips
// produce) into an int64.
func metaInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	}
	return 0, false
}

// pickFingerprint returns the first client fingerprint present on an event,
// preferring JA3, then JA4, then HASSH.
func pickFingerprint(ev *event.Event) (kind, val string) {
	for _, k := range []string{"ja3", "ja4", "hassh"} {
		if v, ok := ev.Meta[k].(string); ok && v != "" {
			return k, v
		}
	}
	return "", ""
}
