package correlate

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-five remote-access / out-of-band-management correlators: third-party
// remote-tool hunting, management-plane targeting, and cleartext remote command
// execution.

// remoteToolHandlers are the third-party remote-control / VDI handlers (kept
// distinct from the OS-native set in lateralHandlers).
var remoteToolHandlers = map[string]bool{
	"teamviewer": true, "anydesk": true, "radmin": true, "dameware": true,
	"pcanywhere": true, "pcoip": true, "spice": true, "ard": true,
	"citrix_ica": true, "nx": true, "vmware_authd": true,
}

// oobMgmtHandlers are the out-of-band / lights-out management surfaces.
var oobMgmtHandlers = map[string]bool{
	"redfish": true, "ilo": true, "idrac": true, "intel_amt": true,
	"esxi": true, "lantronix": true, "ipmi": true, "moxa_mgmt": true,
}

// remoteExecMarkers are the markers that mean a command was executed over a
// cleartext remote-exec channel.
var remoteExecMarkers = map[string]bool{
	"rexec-command": true,
	"rsh-command":   true,
}

// checkRemoteToolSweep detects one source probing several DISTINCT third-party
// remote-access tools within the window — hunting for a remote-control
// foothold.
func (c *Correlator) checkRemoteToolSweep(ev *event.Event, now time.Time) *event.Event {
	if !remoteToolHandlers[ev.Handler] {
		return nil
	}
	cfg := c.cfg.RemoteToolSweep
	st := windowedSet(c.remoteTool, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctTools {
		return nil
	}
	if !c.shouldEmit("rtool|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:remote_tool_sweep", Severity: c.remoteToolSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_tools": len(st.set),
			"tools":          setKeys(st.set),
			"window_s":       int(cfg.Window.Seconds()),
		},
	}
}

// checkOOBMgmtAccess detects one source touching several DISTINCT out-of-band /
// lights-out management surfaces within the window — targeting the management
// plane (BMC / IPMI / console servers).
func (c *Correlator) checkOOBMgmtAccess(ev *event.Event, now time.Time) *event.Event {
	if !oobMgmtHandlers[ev.Handler] {
		return nil
	}
	cfg := c.cfg.OOBMgmtAccess
	st := windowedSet(c.oobMgmt, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("oob|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:oob_mgmt_access", Severity: c.oobMgmtSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          setKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// checkRemoteExecCommand fires when a source executes a command over a
// cleartext remote-exec channel (rexec / rsh) — hands-on code execution in the
// clear.
func (c *Correlator) checkRemoteExecCommand(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, remoteExecMarkers) {
		return nil
	}
	cfg := c.cfg.RemoteExecCommand
	st := windowedCount(c.remoteExec, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("rexec|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:remote_exec_command", Severity: c.remoteExecSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"commands": st.count,
			"handler":  ev.Handler,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}
