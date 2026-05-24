package correlate

import (
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// More opt-in correlators (see extra.go for the contract). All are gated by
// their config Enabled flag in Observe and emit at most once per window.

// lateralHandlers are the remote-access / lateral-movement service handlers.
var lateralHandlers = map[string]bool{
	"rdp": true, "smb": true, "winrm": true, "ssh": true, "ssh_interactive": true,
	"vnc": true, "dcerpc": true, "rlogin": true, "x11": true, "telnet": true,
}

// icsHandlers are the industrial-protocol handlers (kept in sync with the
// devices package's ICS set).
var icsHandlers = map[string]bool{
	"modbus": true, "s7": true, "s7comm_plus": true, "iec104": true, "dnp3": true,
	"ethernetip": true, "opcua": true, "bacnet": true, "fins": true, "melsec": true,
	"mms": true, "codesys": true, "ge_srtp": true, "atg": true, "fox": true,
	"hartip": true, "pcworx": true, "knx": true, "profinet": true,
	"fins_tcp": true, "secs_gem": true, "pcom": true,
}

// checkLateralMovement detects one source probing DistinctServices distinct
// lateral-movement services within the window.
func (c *Correlator) checkLateralMovement(ev *event.Event, now time.Time) *event.Event {
	if !lateralHandlers[ev.Handler] {
		return nil
	}
	cfg := c.cfg.LateralMovement
	st := windowedSet(c.lateral, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("lateral|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:lateral_movement", Severity: c.lateralSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          setKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// checkOTRecon detects an ICS/OT recon sweep: DistinctServices distinct
// industrial-protocol handlers touched by one source within the window.
func (c *Correlator) checkOTRecon(ev *event.Event, now time.Time) *event.Event {
	if !icsHandlers[ev.Handler] {
		return nil
	}
	cfg := c.cfg.OTRecon
	st := windowedSet(c.otRecon, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("otrecon|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:ot_recon", Severity: c.otReconSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          setKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// dataAccessSignal reports whether an event represents data-store collection
// (a read against a NoSQL/cache/search store or a share listing).
func dataAccessSignal(ev *event.Event) bool {
	for _, a := range ev.Anomalies {
		switch a {
		case "mongodb-data-access", "elasticsearch-data-access", "memcached-stats-probe",
			"dcerpc-srvsvc-enum", "honeyfile-download", "ftp-download-attempt":
			return true
		}
	}
	return false
}

// checkDataAccess detects Attempts data-access events from one source.
func (c *Correlator) checkDataAccess(ev *event.Event, now time.Time) *event.Event {
	if !dataAccessSignal(ev) {
		return nil
	}
	cfg := c.cfg.DataAccess
	st := windowedCount(c.dataAcc, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Attempts {
		return nil
	}
	if !c.shouldEmit("dataacc|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:data_access", Severity: c.dataAccSev,
		Source: ev.Source, Dest: ev.Dest, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{"accesses": st.count, "window_s": int(cfg.Window.Seconds())},
	}
}

// checkMalwareCampaign detects Captures malware:capture events from one source.
func (c *Correlator) checkMalwareCampaign(ev *event.Event, now time.Time) *event.Event {
	if ev.RuleID != "malware:capture" {
		return nil
	}
	cfg := c.cfg.MalwareCampaign
	st := windowedCount(c.malware, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Captures {
		return nil
	}
	if !c.shouldEmit("malware|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:malware_campaign", Severity: c.malwareSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{"captures": st.count, "window_s": int(cfg.Window.Seconds())},
	}
}

// checkWebshell detects Attempts web-shell access/command events from one source.
func (c *Correlator) checkWebshell(ev *event.Event, now time.Time) *event.Event {
	hit := false
	for _, a := range ev.Anomalies {
		if strings.HasPrefix(a, "webshell-") {
			hit = true
			break
		}
	}
	if !hit {
		return nil
	}
	cfg := c.cfg.Webshell
	st := windowedCount(c.webshell, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Attempts {
		return nil
	}
	if !c.shouldEmit("webshell|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:webshell", Severity: c.webshellSev,
		Source: ev.Source, Dest: ev.Dest, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{"interactions": st.count, "window_s": int(cfg.Window.Seconds())},
	}
}

// windowedCount returns the per-key countState for now, resetting it when the
// previous one has aged past window. Called with c.mu held.
func windowedCount(m map[string]*countState, key string, now time.Time, window time.Duration) *countState {
	st, ok := m[key]
	if !ok || now.Sub(st.since) > window {
		st = &countState{since: now}
		m[key] = st
	}
	return st
}
