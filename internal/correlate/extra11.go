package correlate

import (
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-eleven correlators built on signals added in the detection-depth pass:
// web-attack-class fuzzing, SSH key-spraying, and SMTP spam-relay probing.

// checkWebAttackProbe counts the DISTINCT web-attack classes one source
// triggers (the webapp:* anomaly markers from the HTTP handlers). Several
// distinct classes within the window is systematic vuln-class fuzzing, not a
// single targeted exploit.
func (c *Correlator) checkWebAttackProbe(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.WebAttackProbe
	st := windowedSet(c.webProbe, ev.Source.IP, now, cfg.Window)
	hit := false
	for _, a := range ev.Anomalies {
		if strings.HasPrefix(a, "webapp:") {
			if len(st.set) < corrSetCap {
				st.set[a] = struct{}{}
			}
			hit = true
		}
	}
	if !hit || len(st.set) < cfg.DistinctClasses {
		return nil
	}
	if !c.shouldEmit("webprobe|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	classes := make([]string, 0, len(st.set))
	for cls := range st.set {
		classes = append(classes, cls)
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:web_attack_probe", Severity: c.webProbeSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"distinct_classes": len(st.set),
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}

// checkSSHKeySpray counts the DISTINCT SSH public keys one source offers
// (meta.ssh_pubkey_fps, surfaced by ssh_interactive). Many distinct keys from
// one IP is key-spraying / testing a stolen-key collection.
func (c *Correlator) checkSSHKeySpray(ev *event.Event, now time.Time) *event.Event {
	fps := metaStrings(ev, "ssh_pubkey_fps")
	if len(fps) == 0 {
		return nil
	}
	cfg := c.cfg.SSHKeySpray
	st := windowedSet(c.sshKey, ev.Source.IP, now, cfg.Window)
	for _, fp := range fps {
		if len(st.set) < corrSetCap {
			st.set[fp] = struct{}{}
		}
	}
	if len(st.set) < cfg.DistinctKeys {
		return nil
	}
	if !c.shouldEmit("sshkey|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:ssh_key_spray", Severity: c.sshKeySev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"distinct_keys": len(st.set),
			"window_s":      int(cfg.Window.Seconds()),
		},
	}
}

// spamRelayMarkers are the SMTP anomaly markers that mean a source is probing
// for relay / harvesting recipients.
var spamRelayMarkers = map[string]bool{
	"smtp-open-relay-probe": true,
	"smtp-user-enumeration": true,
}

// checkSpamRelay counts open-relay / recipient-enumeration attempts from one
// source; several within the window is a spammer probing the mail server.
func (c *Correlator) checkSpamRelay(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, spamRelayMarkers) {
		return nil
	}
	cfg := c.cfg.SpamRelay
	st := windowedCount(c.spamRelay, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("spamrelay|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:spam_relay", Severity: c.spamRelaySev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"events":   st.count,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}

// metaStrings coerces an event meta value (string / []string / []any) into a
// []string — the correlate counterpart of the same helper in other packages.
func metaStrings(ev *event.Event, key string) []string {
	if ev.Meta == nil {
		return nil
	}
	switch t := ev.Meta[key].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t != "" {
			return []string{t}
		}
	}
	return nil
}
