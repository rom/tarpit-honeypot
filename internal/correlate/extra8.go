package correlate

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-six VoIP / telephony correlators: toll-fraud call probing, PBX/
// telephony enumeration, and PBX administrative control.

// voipHandlers are the telephony-protocol handlers.
var voipHandlers = map[string]bool{
	"sip": true, "sip_tcp": true, "sccp": true, "h323": true,
	"iax2": true, "asterisk_ami": true,
}

// tollFraudMarkers mean a call was placed / attempted — INVITE scanning or an
// AMI Originate, the monetized step of telephony abuse.
var tollFraudMarkers = map[string]bool{
	"sip-invite-attempt": true,
	"ami-originate":      true,
}

// pbxControlMarkers mean administrative interaction with a PBX manager
// interface.
var pbxControlMarkers = map[string]bool{
	"ami-login":   true,
	"ami-command": true,
}

// checkTollFraud counts call-placement attempts from one source; a burst is
// toll-fraud probing (premium / international call origination).
func (c *Correlator) checkTollFraud(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, tollFraudMarkers) {
		return nil
	}
	cfg := c.cfg.TollFraud
	st := windowedCount(c.tollFraud, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("toll|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:toll_fraud", Severity: c.tollFraudSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"call_attempts": st.count,
			"handler":       ev.Handler,
			"window_s":      int(cfg.Window.Seconds()),
		},
	}
}

// checkVoIPEnum detects telephony reconnaissance: one source touching several
// DISTINCT VoIP protocols within the window.
func (c *Correlator) checkVoIPEnum(ev *event.Event, now time.Time) *event.Event {
	if !voipHandlers[ev.Handler] {
		return nil
	}
	cfg := c.cfg.VoIPEnum
	st := windowedSet(c.voipEnum, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[ev.Handler] = struct{}{}
	}
	if len(st.set) < cfg.DistinctServices {
		return nil
	}
	if !c.shouldEmit("voipenum|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:voip_enum", Severity: c.voipEnumSev,
		Source: ev.Source, Proto: ev.Proto,
		Meta: map[string]any{
			"distinct_services": len(st.set),
			"services":          setKeys(st.set),
			"window_s":          int(cfg.Window.Seconds()),
		},
	}
}

// checkPBXControl counts administrative manager-interface interactions from one
// source; repeated access is an attempt to take over the PBX.
func (c *Correlator) checkPBXControl(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, pbxControlMarkers) {
		return nil
	}
	cfg := c.cfg.PBXControl
	st := windowedCount(c.pbxCtrl, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("pbxctrl|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:pbx_control", Severity: c.pbxCtrlSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"actions":  st.count,
			"handler":  ev.Handler,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}
