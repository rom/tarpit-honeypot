package correlate

import (
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// Round-ten correlators for capabilities added since the cloud-native round:
// TLS-interception captures, network-fingerprint rotation, and
// container-platform takeover.

// tlsDecryptMarkers are the anomaly markers the tls_intercept handler raises
// when it pulls an exploit or credential out of the decrypted tunnel.
var tlsDecryptMarkers = map[string]bool{
	"tls-decrypted-exploit":     true,
	"tls-decrypted-credentials": true,
}

// checkTLSMITMCapture counts events where the decrypt-and-forward MITM caught
// an attack inside the TLS tunnel. Several within the window means a source is
// actively running attacks it believed were protected by TLS — the payoff of
// interception, worth a single rolled-up finding.
func (c *Correlator) checkTLSMITMCapture(ev *event.Event, now time.Time) *event.Event {
	if !evHasMarkerIn(ev, tlsDecryptMarkers) {
		return nil
	}
	cfg := c.cfg.TLSMITMCapture
	st := windowedCount(c.mitmCap, ev.Source.IP, now, cfg.Window)
	st.count++
	if st.count < cfg.Events {
		return nil
	}
	if !c.shouldEmit("tlsmitm|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:tls_mitm_capture", Severity: c.mitmCapSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"events":   st.count,
			"window_s": int(cfg.Window.Seconds()),
		},
	}
}

// checkFingerprintRotation counts the DISTINCT network fingerprints a single
// source presents. One client legitimately has one JA4 (+JA3/HASSH); several
// DISTINCT JA4 values from one IP within a window is a single actor rotating
// its TLS/SSH stack (or proxy pool) to dodge fingerprint blocking. We key the
// set on one fingerprint per event (JA4, then JA3, then HASSH) so a normal
// single-stack client never trips it.
func (c *Correlator) checkFingerprintRotation(ev *event.Event, now time.Time) *event.Event {
	fp := ""
	for _, k := range []string{"ja4", "ja3", "hassh"} {
		if v, ok := ev.Meta[k].(string); ok && v != "" {
			fp = v
			break
		}
	}
	if fp == "" {
		return nil
	}
	cfg := c.cfg.FingerprintRotation
	st := windowedSet(c.fpRot, ev.Source.IP, now, cfg.Window)
	if len(st.set) < corrSetCap {
		st.set[fp] = struct{}{}
	}
	if len(st.set) < cfg.DistinctFingerprints {
		return nil
	}
	if !c.shouldEmit("fprot|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:fp_rotation", Severity: c.fpRotSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"distinct_fingerprints": len(st.set),
			"window_s":              int(cfg.Window.Seconds()),
		},
	}
}

// containerCtrlMarkers are the container / Kubernetes control operations whose
// combination signals platform takeover rather than a stray probe.
var containerCtrlMarkers = map[string]bool{
	"docker-container-create": true,
	"docker-remote-control":   true,
	"k8s-pod-create":          true,
	"k8s-pod-exec":            true,
	"k8s-secret-enum":         true,
	"k8s-token-auth":          true,
}

// checkContainerTakeover counts the DISTINCT container/k8s control operations
// one source performs. Several distinct ops (e.g. enumerate secrets, then
// create a pod, then exec into it) within the window is an orchestration
// takeover attempt.
func (c *Correlator) checkContainerTakeover(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.ContainerTakeover
	st := windowedSet(c.ctrTake, ev.Source.IP, now, cfg.Window)
	hit := false
	for _, a := range ev.Anomalies {
		if containerCtrlMarkers[a] {
			if len(st.set) < corrSetCap {
				st.set[a] = struct{}{}
			}
			hit = true
		}
	}
	if !hit || len(st.set) < cfg.DistinctOps {
		return nil
	}
	if !c.shouldEmit("ctrtake|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ops := make([]string, 0, len(st.set))
	for op := range st.set {
		ops = append(ops, op)
	}
	return &event.Event{
		ID: event.NewID(), Time: now, Sensor: ev.Sensor,
		RuleID: "correlate:container_takeover", Severity: c.ctrTakeSev,
		Source: ev.Source, Proto: ev.Proto, Handler: ev.Handler,
		Meta: map[string]any{
			"distinct_ops": len(st.set),
			"window_s":     int(cfg.Window.Seconds()),
		},
	}
}
