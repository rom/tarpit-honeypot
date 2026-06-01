package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestTLSMITMCaptureFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		TLSMITMCapture: config.CorrTLSMITMCapture{Enabled: true, Events: 2, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"tls-decrypted-exploit", "tls-decrypted-credentials"} {
		ev := mkEvent("1.2.3.4", 443, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:tls_mitm_capture") == nil {
		t.Fatalf("tls_mitm_capture did not fire: %v", last)
	}
}

func TestFingerprintRotationFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		FingerprintRotation: config.CorrFingerprintRotation{Enabled: true, DistinctFingerprints: 3, Window: time.Hour, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent("203.0.113.9", 443, now.Add(time.Duration(i)*time.Second))
		ev.Meta = map[string]any{"ja4": fmt.Sprintf("t13d%04d", i)}
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:fp_rotation")
	if agg == nil {
		t.Fatalf("fp_rotation did not fire: %v", last)
	}
	if agg.Meta["distinct_fingerprints"].(int) != 3 {
		t.Errorf("distinct_fingerprints = %v, want 3", agg.Meta["distinct_fingerprints"])
	}
}

func TestFingerprintRotationSameFPDoesNotFire(t *testing.T) {
	cor, _ := New(config.Correlate{
		FingerprintRotation: config.CorrFingerprintRotation{Enabled: true, DistinctFingerprints: 3, Window: time.Hour, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 5; i++ {
		ev := mkEvent("203.0.113.10", 443, now.Add(time.Duration(i)*time.Second))
		ev.Meta = map[string]any{"ja4": "t13d-stable"} // same client stack each time
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:fp_rotation") != nil {
		t.Error("a single stable fingerprint must not trip fp_rotation")
	}
}

func TestContainerTakeoverFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ContainerTakeover: config.CorrContainerTakeover{Enabled: true, DistinctOps: 2, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"k8s-secret-enum", "k8s-pod-exec"} {
		ev := mkEvent("1.2.3.4", 6443, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:container_takeover") == nil {
		t.Fatalf("container_takeover did not fire: %v", last)
	}
}
