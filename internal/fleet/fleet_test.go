package fleet

import (
	"fmt"
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
	// All 3 of 3 active sensors hit -> broad (internet background), medium.
	if a.Severity != event.SeverityMedium {
		t.Errorf("severity = %v; want medium (broad)", a.Severity)
	}
	if s, _ := a.Meta["scope"].(string); s != "broad" {
		t.Errorf("scope = %q; want broad", s)
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

func TestSourceCoverageTargeted(t *testing.T) {
	c := New(Config{Enabled: true, SourceSensors: 2, BroadCoverage: 0.8})
	// Build a broad fleet baseline: 10 sensors each seeing a different source,
	// so the active-sensor count is large but no single source spans them.
	for i := 0; i < 10; i++ {
		c.Observe(ev(fmt.Sprintf("bg%d", i), fmt.Sprintf("198.51.100.%d", i), nil))
	}
	// One source hits a small subset (2 of 12) -> targeted -> high.
	const ip = "203.0.113.5"
	c.Observe(ev("t1", ip, nil))
	a := findAlert(c.Observe(ev("t2", ip, nil)), "fleet:source-multi-sensor")
	if a == nil {
		t.Fatal("did not fire")
	}
	if a.Severity != event.SeverityHigh {
		t.Errorf("severity = %v; want high (targeted)", a.Severity)
	}
	if s, _ := a.Meta["scope"].(string); s != "targeted" {
		t.Errorf("scope = %q; want targeted", s)
	}
	if cov, _ := a.Meta["coverage"].(float64); cov >= 0.8 {
		t.Errorf("coverage = %v; want < 0.8", cov)
	}
}

func TestPayloadCampaign(t *testing.T) {
	c := New(Config{Enabled: true, PayloadSensors: 2})
	art := func() map[string]any { return map[string]any{"payload_artifacts": []string{"elf:abc123def"}} }
	if a := findAlert(c.Observe(ev("s1", "192.0.2.1", art())), "fleet:payload-campaign"); a != nil {
		t.Fatal("fired at one sensor")
	}
	a := findAlert(c.Observe(ev("s2", "192.0.2.2", art())), "fleet:payload-campaign")
	if a == nil {
		t.Fatal("did not fire when the same hash reached 2 sensors")
	}
	if h, _ := a.Meta["sha256"].(string); h != "abc123def" {
		t.Errorf("sha256 = %q; want abc123def", h)
	}
	if got, _ := a.Meta["source_count"].(int); got != 2 {
		t.Errorf("source_count = %d; want 2", got)
	}
	if a.Severity != event.SeverityHigh {
		t.Errorf("severity = %v; want high", a.Severity)
	}
}

func TestPayloadHashParsing(t *testing.T) {
	// []any (JSON round-trip form) + the " -> filename" suffix must still key
	// on the bare hash.
	c := New(Config{Enabled: true, PayloadSensors: 2})
	c.Observe(ev("s1", "192.0.2.1", map[string]any{"payload_artifacts": []any{"pe:deadbeef -> mal.exe"}}))
	a := findAlert(c.Observe(ev("s2", "192.0.2.2", map[string]any{"payload_artifacts": []string{"pe:deadbeef"}})), "fleet:payload-campaign")
	if a == nil {
		t.Fatal("did not unify the two artifact descriptor forms on the hash")
	}
	if h, _ := a.Meta["sha256"].(string); h != "deadbeef" {
		t.Errorf("sha256 = %q; want deadbeef", h)
	}
}

func TestCredentialCampaign(t *testing.T) {
	c := New(Config{Enabled: true, CredSensors: 2})
	creds := func() map[string]any { return map[string]any{"username": "admin", "password": "Summer2025!"} }
	if a := findAlert(c.Observe(ev("s1", "192.0.2.1", creds())), "fleet:credential-campaign"); a != nil {
		t.Fatal("fired at one sensor")
	}
	a := findAlert(c.Observe(ev("s2", "192.0.2.2", creds())), "fleet:credential-campaign")
	if a == nil {
		t.Fatal("did not fire when the same credential reached 2 sensors")
	}
	if u, _ := a.Meta["username"].(string); u != "admin" {
		t.Errorf("username = %q; want admin", u)
	}
	if got, _ := a.Meta["source_count"].(int); got != 2 {
		t.Errorf("source_count = %d; want 2", got)
	}
}

func TestCredentialUserPassFallback(t *testing.T) {
	// Handlers that use the "user"/"pass" meta keys must correlate identically.
	c := New(Config{Enabled: true, CredSensors: 2})
	c.Observe(ev("s1", "192.0.2.1", map[string]any{"user": "root", "pass": "toor"}))
	if a := findAlert(c.Observe(ev("s2", "192.0.2.2", map[string]any{"user": "root", "pass": "toor"})), "fleet:credential-campaign"); a == nil {
		t.Fatal("did not fire using user/pass fallback keys")
	}
}

func TestCVEWave(t *testing.T) {
	c := New(Config{Enabled: true, CVESensors: 3, BroadCoverage: 0.8})
	cveEv := func(sid, ip string) *event.Event {
		e := ev(sid, ip, nil)
		e.RuleID = "cve:CVE-2021-44228"
		return e
	}
	// Distinct subnets so this isolates cve-wave from subnet-coordinated.
	c.Observe(cveEv("s1", "192.0.2.1"))
	c.Observe(cveEv("s2", "198.51.100.2"))
	a := findAlert(c.Observe(cveEv("s3", "203.0.113.3")), "fleet:cve-wave")
	if a == nil {
		t.Fatal("did not fire when the CVE reached 3 sensors")
	}
	if got, _ := a.Meta["cve"].(string); got != "CVE-2021-44228" {
		t.Errorf("cve = %q", got)
	}
	if got, _ := a.Meta["source_count"].(int); got != 3 {
		t.Errorf("source_count = %d; want 3", got)
	}
	// 3 of 3 active sensors -> broad.
	if s, _ := a.Meta["scope"].(string); s != "broad" {
		t.Errorf("scope = %q; want broad", s)
	}
	if a.Severity != event.SeverityMedium {
		t.Errorf("severity = %v; want medium (broad)", a.Severity)
	}
}

func TestSubnetCoordinated(t *testing.T) {
	c := New(Config{Enabled: true, SubnetSensors: 2, SubnetSources: 2, SourceSensors: 99})
	// Two distinct IPs in 203.0.113.0/24, each on a different sensor.
	c.Observe(ev("s1", "203.0.113.10", nil))
	a := findAlert(c.Observe(ev("s2", "203.0.113.20", nil)), "fleet:subnet-coordinated")
	if a == nil {
		t.Fatal("did not fire for a coordinated /24 across sensors")
	}
	if got, _ := a.Meta["subnet"].(string); got != "203.0.113.0/24" {
		t.Errorf("subnet = %q; want 203.0.113.0/24", got)
	}
	if got, _ := a.Meta["source_count"].(int); got != 2 {
		t.Errorf("source_count = %d; want 2", got)
	}
}

func TestSubnetNeedsMultipleIPs(t *testing.T) {
	// One IP across sensors is source-multi-sensor, not subnet-coordinated.
	c := New(Config{Enabled: true, SubnetSensors: 2, SubnetSources: 2, SourceSensors: 99})
	c.Observe(ev("s1", "203.0.113.10", nil))
	if a := findAlert(c.Observe(ev("s2", "203.0.113.10", nil)), "fleet:subnet-coordinated"); a != nil {
		t.Fatal("fired for a single IP (should require multiple distinct IPs)")
	}
}

func TestOutlierSensor(t *testing.T) {
	c := New(Config{Enabled: true, OutlierMinEvents: 5, OutlierFactor: 3, OutlierMinPeers: 2})
	hev := func(sid, ip string) *event.Event {
		e := ev(sid, ip, nil)
		e.Severity = event.SeverityHigh
		return e
	}
	// Three quiet peers (one high-sev event each, distinct sources).
	c.Observe(hev("p1", "198.51.100.1"))
	c.Observe(hev("p2", "198.51.100.2"))
	c.Observe(hev("p3", "198.51.100.3"))
	// One sensor floods with high-sev events from many distinct sources.
	var got *event.Event
	for i := 0; i < 20; i++ {
		for _, e := range c.Observe(hev("target", fmt.Sprintf("203.0.113.%d", i))) {
			if e.RuleID == "fleet:outlier-sensor" {
				got = e
			}
		}
	}
	if got == nil {
		t.Fatal("outlier-sensor did not fire for the flooded node")
	}
	if s, _ := got.Meta["sensor"].(string); s != "target" {
		t.Errorf("sensor = %q; want target", s)
	}
	if got.Source.IP != "" {
		t.Errorf("outlier source = %q; want empty (node-level finding)", got.Source.IP)
	}
}

func TestOutlierNeedsPeers(t *testing.T) {
	// With too few peers to compare against, no outlier is declared.
	c := New(Config{Enabled: true, OutlierMinEvents: 3, OutlierFactor: 2, OutlierMinPeers: 5})
	hev := func(ip string) *event.Event {
		e := ev("target", ip, nil)
		e.Severity = event.SeverityHigh
		return e
	}
	for i := 0; i < 20; i++ {
		for _, e := range c.Observe(hev(fmt.Sprintf("203.0.113.%d", i))) {
			if e.RuleID == "fleet:outlier-sensor" {
				t.Fatal("fired without enough peers to compare")
			}
		}
	}
}
