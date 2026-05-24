package correlate

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-four OT correlators: PLC program/firmware downloads, CPU operating-
// mode changes, and the discovery -> manipulation ICS kill-chain. These key on
// the high-signal ICS markers the industrial handlers flag, so they fire from
// real control-protocol activity rather than raw packet shape.

// programDownloadMarkers are the markers that represent a logic / firmware
// download to a controller — the Stuxnet / Triton manipulation step.
var programDownloadMarkers = map[string]bool{
	"secs-program-send":     true,
	"pcom-program-download": true,
	"fins-program-download": true,
	"s7-program-download":   true,
	"codesys-download":      true,
	"ics-firmware-upload":   true,
}

// modeChangeMarkers are the markers that represent a CPU operating-mode change
// (RUN / STOP / PROGRAM) — a change-operating-mode / denial-of-control step.
var modeChangeMarkers = map[string]bool{
	"fins-run-mode-change": true,
	"pcom-mode-change":     true,
	"s7-cpu-stop":          true,
	"ics-mode-change":      true,
}

func evHasMarkerIn(ev *event.Event, set map[string]bool) bool {
	for _, a := range ev.Anomalies {
		if set[a] {
			return true
		}
	}
	return false
}

// checkPLCProgramDownload fires when a source downloads logic / firmware to a
// controller — almost never legitimate against an internet-exposed PLC and the
// core of the highest-impact ICS attacks.
func (c *Correlator) checkPLCProgramDownload(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, programDownloadMarkers) {
		return nil
	}
	cfg := c.cfg.PLCProgramDownload
	st := windowedCount(c.plcProg, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("plcprog|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:plc_program_download", Severity: c.plcProgSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"downloads": st.count,
			"handler":   ev.Handler,
			"window_s":  int(cfg.Window.Seconds()),
		},
	}
}

// checkICSModeChange fires when a source changes a controller's operating mode
// (RUN/STOP/PROGRAM) — a denial-of-control / change-operating-mode action.
func (c *Correlator) checkICSModeChange(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, modeChangeMarkers) {
		return nil
	}
	cfg := c.cfg.ICSModeChange
	st := windowedCount(c.modeChg, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("icsmode|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:ics_mode_change", Severity: c.modeChgSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"mode_changes": st.count,
			"handler":      ev.Handler,
			"window_s":     int(cfg.Window.Seconds()),
		},
	}
}

// checkOTKillChain fires when one source both reconnoiters an ICS protocol and
// issues a control / program / mode command within the window — the
// discovery -> manipulation transition of the ICS kill chain.
func (c *Correlator) checkOTKillChain(ev *event.Event, now time.Time) *event.Event {
	recon := icsHandlers[ev.Handler]
	control := icsControlSignal(ev) ||
		evHasMarkerIn(ev, programDownloadMarkers) || evHasMarkerIn(ev, modeChangeMarkers)
	if !recon && !control {
		return nil
	}
	cfg := c.cfg.OTKillChain
	st := windowedSet(c.otKill, ev.Source.IP, now, cfg.Window)
	if recon {
		st.set["recon"] = struct{}{}
	}
	if control {
		st.set["control"] = struct{}{}
	}
	if _, ok := st.set["recon"]; !ok {
		return nil
	}
	if _, ok := st.set["control"]; !ok {
		return nil
	}
	if !c.shouldEmit("otkill|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:ot_kill_chain", Severity: c.otKillSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"handler":  ev.Handler,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}
