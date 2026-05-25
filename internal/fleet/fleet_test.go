package fleet

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// ev builds a minimal listener event for the correlator.
func ev(sensorID, srcIP string, meta map[string]any) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		SensorID: sensorID,
		RuleID:   "listener:http",
		Source:   event.Endpoint{IP: srcIP},
		Meta:     meta,
	}
}

// findAlert returns the first emitted event with the given rule id, or nil.
func findAlert(out []*event.Event, ruleID string) *event.Event {
	for _, e := range out {
		if e.RuleID == ruleID {
			return e
		}
	}
	return nil
}

func TestDisabledReturnsNil(t *testing.T) {
	if c := New(Config{Enabled: false}); c != nil {
		t.Fatalf("New(disabled) = %v; want nil", c)
	}
	// A nil correlator must be a safe no-op (the leaf-sensor path).
	var c *Correlator
	if out := c.Observe(ev("s1", "1.2.3.4", nil)); out != nil {
		t.Fatalf("nil.Observe = %v; want nil", out)
	}
}

func TestSourceMultiSensor(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 3})
	const ip = "203.0.113.7"

	if a := findAlert(c.Observe(ev("s1", ip, nil)), "fleet:source-multi-sensor"); a != nil {
		t.Fatal("fired after 1 sensor")
	}
	if a := findAlert(c.Observe(ev("s2", ip, nil)), "fleet:source-multi-sensor"); a != nil {
		t.Fatal("fired after 2 sensors")
	}
	a := findAlert(c.Observe(ev("s3", ip, nil)), "fleet:source-multi-sensor")
	if a == nil {
		t.Fatal("did not fire at threshold (3 sensors)")
	}
	if a.Severity != event.SeverityHigh {
		t.Errorf("severity = %v; want high", a.Severity)
	}
	if got := a.Source.IP; got != ip {
		t.Errorf("alert source = %q; want %q", got, ip)
	}
	if got, _ := a.Meta["sensor_count"].(int); got != 3 {
		t.Errorf("sensor_count = %d; want 3", got)
	}
	sensors, _ := a.Meta["sensors"].([]string)
	if len(sensors) != 3 {
		t.Errorf("sensors = %v; want 3 entries", sensors)
	}

	// Must not re-fire within the same window.
	if a := findAlert(c.Observe(ev("s4", ip, nil)), "fleet:source-multi-sensor"); a != nil {
		t.Fatal("re-fired within window after 4th sensor")
	}
}

func TestASNMultiSensor(t *testing.T) {
	c := New(Config{Enabled: true, ASNSensors: 2})
	meta := func() map[string]any { return map[string]any{"asn": "AS64500", "asn_org": "Example Net"} }

	if a := findAlert(c.Observe(ev("s1", "198.51.100.1", meta())), "fleet:asn-multi-sensor"); a != nil {
		t.Fatal("fired after 1 sensor")
	}
	// A different source IP on a second sensor, same ASN -> coordinated.
	a := findAlert(c.Observe(ev("s2", "198.51.100.2", meta())), "fleet:asn-multi-sensor")
	if a == nil {
		t.Fatal("did not fire at ASN threshold")
	}
	if got, _ := a.Meta["asn"].(string); got != "AS64500" {
		t.Errorf("asn = %q; want AS64500", got)
	}
	if got, _ := a.Meta["asn_org"].(string); got != "Example Net" {
		t.Errorf("asn_org = %q; want Example Net", got)
	}
}

func TestASNIgnoredWhenAbsent(t *testing.T) {
	c := New(Config{Enabled: true, ASNSensors: 2})
	// No asn meta: the ASN branch must not fire even across many sensors.
	c.Observe(ev("s1", "198.51.100.1", nil))
	if a := findAlert(c.Observe(ev("s2", "198.51.100.2", nil)), "fleet:asn-multi-sensor"); a != nil {
		t.Fatal("ASN alert fired with no asn meta")
	}
}

func TestFingerprintShared(t *testing.T) {
	c := New(Config{Enabled: true, FPSensors: 2, FPSources: 2})
	fp := func() map[string]any { return map[string]any{"ja3": "771,4865-4866,0-23,29-23,0"} }

	// One sensor + one source: neither breadth met.
	if a := findAlert(c.Observe(ev("s1", "192.0.2.1", fp())), "fleet:fingerprint-shared"); a != nil {
		t.Fatal("fired with one sensor / one source")
	}
	// Second sensor AND second distinct source -> shared toolkit.
	a := findAlert(c.Observe(ev("s2", "192.0.2.2", fp())), "fleet:fingerprint-shared")
	if a == nil {
		t.Fatal("did not fire when both fingerprint breadths met")
	}
	if got, _ := a.Meta["source_count"].(int); got != 2 {
		t.Errorf("source_count = %d; want 2", got)
	}
	if got, _ := a.Meta["fingerprint"].(string); got != "ja3:771,4865-4866,0-23,29-23,0" {
		t.Errorf("fingerprint = %q", got)
	}
}

func TestFingerprintNeedsBothBreadths(t *testing.T) {
	c := New(Config{Enabled: true, FPSensors: 2, FPSources: 3})
	fp := func() map[string]any { return map[string]any{"hassh": "deadbeef"} }

	// Two sensors but only two distinct sources (need 3): no alert.
	c.Observe(ev("s1", "192.0.2.1", fp()))
	if a := findAlert(c.Observe(ev("s2", "192.0.2.2", fp())), "fleet:fingerprint-shared"); a != nil {
		t.Fatal("fired before source breadth met")
	}
	// Third distinct source (still across the two sensors) crosses it.
	a := findAlert(c.Observe(ev("s1", "192.0.2.3", fp())), "fleet:fingerprint-shared")
	if a == nil {
		t.Fatal("did not fire once both breadths met")
	}
}

func TestLoopGuardIgnoresFleetEvents(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 2})
	const ip = "203.0.113.9"
	// A fleet:* event must never be correlated (it would feed back on itself).
	feedback := ev("s1", ip, nil)
	feedback.RuleID = "fleet:source-multi-sensor"
	c.Observe(feedback)
	c.Observe(feedback)
	// A real event from one new sensor should now be the FIRST tracked sensor,
	// so the threshold of 2 is not yet met.
	if a := findAlert(c.Observe(ev("s2", ip, nil)), "fleet:source-multi-sensor"); a != nil {
		t.Fatal("fleet:* feedback events were counted as sensors")
	}
}

func TestIgnoresEmptyKeys(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 1})
	if out := c.Observe(ev("s1", "", nil)); out != nil {
		t.Errorf("empty source IP produced %v", out)
	}
	if out := c.Observe(ev("", "203.0.113.1", nil)); out != nil {
		t.Errorf("empty sensor id produced %v", out)
	}
}

func TestSensorNameFallback(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 2})
	const ip = "203.0.113.20"
	// SensorID empty but Sensor (name) set: still counts as a distinct sensor.
	e1 := ev("", ip, nil)
	e1.Sensor = "node-a"
	e2 := ev("", ip, nil)
	e2.Sensor = "node-b"
	c.Observe(e1)
	if a := findAlert(c.Observe(e2), "fleet:source-multi-sensor"); a == nil {
		t.Fatal("did not fire using Sensor-name fallback")
	}
}

func TestWindowPruneRefires(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 2, Window: time.Hour})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	const ip = "203.0.113.30"

	c.Observe(ev("s1", ip, nil))
	if a := findAlert(c.Observe(ev("s2", ip, nil)), "fleet:source-multi-sensor"); a == nil {
		t.Fatal("did not fire in first window")
	}
	// Advance past the window so the actor is pruned; the same pattern must
	// be able to fire again (thresholds are per-window).
	now = now.Add(2 * time.Hour)
	c.Observe(ev("s1", ip, nil))
	if a := findAlert(c.Observe(ev("s2", ip, nil)), "fleet:source-multi-sensor"); a == nil {
		t.Fatal("did not re-fire after the window elapsed")
	}
}

func TestListCappedAndSorted(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 3, MaxList: 2})
	const ip = "203.0.113.40"
	c.Observe(ev("s3", ip, nil))
	c.Observe(ev("s1", ip, nil))
	a := findAlert(c.Observe(ev("s2", ip, nil)), "fleet:source-multi-sensor")
	if a == nil {
		t.Fatal("did not fire at threshold")
	}
	if got, _ := a.Meta["sensor_count"].(int); got != 3 {
		t.Errorf("sensor_count = %d; want the true count 3", got)
	}
	sensors, _ := a.Meta["sensors"].([]string)
	if len(sensors) != 2 {
		t.Fatalf("sensors = %v; want capped to 2", sensors)
	}
	if sensors[0] != "s1" || sensors[1] != "s2" {
		t.Errorf("sensors = %v; want sorted [s1 s2]", sensors)
	}
}

func TestWindowMetaStamped(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 1, Window: 90 * time.Minute})
	a := findAlert(c.Observe(ev("s1", "203.0.113.50", nil)), "fleet:source-multi-sensor")
	if a == nil {
		t.Fatal("did not fire at threshold 1")
	}
	if got, _ := a.Meta["window"].(string); got != "1h30m0s" {
		t.Errorf("window meta = %q; want 1h30m0s", got)
	}
}
