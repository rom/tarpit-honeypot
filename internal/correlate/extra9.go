package correlate

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-seven correlators for the cloud-native + SSRF attack surface:
// cloud credential-theft bursts and repeated SSRF out-of-band callbacks.

// cloudCredTheftMarkers are the anomaly markers that mean an attacker grabbed
// (or tried to grab) cloud credentials — from the cloud_metadata / etcd
// handlers or the post-login shell.
var cloudCredTheftMarkers = map[string]bool{
	"cloud-credential-theft": true,
	"etcd-secret-read":       true,
	"shell-cloud-cred-theft": true,
}

// checkCloudCredTheft counts cloud credential-theft operations from one source;
// several within the window is active cloud-credential harvesting (IMDS / etcd
// secrets / cloud-CLI) rather than a stray scan.
func (c *Correlator) checkCloudCredTheft(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, cloudCredTheftMarkers) {
		return nil
	}
	cfg := c.cfg.CloudCredTheft
	st := windowedCount(c.cloudCred, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("cloudcred|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:cloud_cred_theft", Severity: c.cloudCredSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"events":   st.count,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}

// checkSSRFCallback counts DISTINCT ssrf tokens called back by one source. The
// ssrf_canary handler flags ssrf-callback and records ssrf_token in meta;
// several distinct tokens within the window means an attacker is actively
// exercising an SSRF/XXE/webhook primitive against multiple planted tokens.
func (c *Correlator) checkSSRFCallback(ev *event.Event, now time.Time) *event.Event {
	hit := false
	for _, a := range ev.Anomalies {
		if a == "ssrf-callback" {
			hit = true
			break
		}
	}
	if !hit {
		return nil
	}
	cfg := c.cfg.SSRFCallback
	st := windowedSet(c.ssrfCb, ev.Source.IP, now, cfg.Window)
	// Key on the distinct token when present, else on the raw path so a
	// token-less callback still counts as one observation.
	tok, _ := ev.Meta["ssrf_token"].(string)
	if tok == "" {
		tok, _ = ev.Meta["path"].(string)
	}
	if tok != "" && len(st.set) < corrSetCap {
		st.set[tok] = struct{}{}
	}
	if len(st.set) < cfg.Events {
		return nil
	}
	if !c.shouldEmit("ssrfcb|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:ssrf_callback", Severity: c.ssrfCbSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"distinct_tokens": len(st.set),
			"window_s":        int(cfg.Window.Seconds()),
		},
	}
}
