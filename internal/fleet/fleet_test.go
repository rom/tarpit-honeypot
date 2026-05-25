package fleet

import (
	"fmt"
	"strings"
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

// evd builds an event with a destination IP and timestamp (for the trajectory
// detector, which keys on the time-ordered sequence of destinations).
func evd(sid, srcIP, destIP string, when time.Time) *event.Event {
	e := ev(sid, srcIP, nil)
	e.Dest = event.Endpoint{IP: destIP}
	e.Time = when
	return e
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

// collectAlert drives Observe over many events and returns the last alert of
// the given rule id (for detectors that fire mid-sequence amid other output).
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
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

func TestScanTrajectory(t *testing.T) {
	c := New(Config{Enabled: true, TrajectoryHits: 4, TrajectorySensors: 2, TrajectoryMonotonic: 0.8, SourceSensors: 99})
	base := time.Unix(1_700_000_000, 0)
	sensors := []string{"s1", "s2"}
	var got *event.Event
	for i := 0; i < 5; i++ {
		dest := fmt.Sprintf("10.0.0.%d", i+1) // ascending walk of the address space
		e := evd(sensors[i%2], "9.9.9.9", dest, base.Add(time.Duration(i)*time.Second))
		for _, out := range c.Observe(e) {
			if out.RuleID == "fleet:scan-trajectory" {
				got = out
			}
		}
	}
	if got == nil {
		t.Fatal("scan-trajectory did not fire for an ascending address walk")
	}
	if d, _ := got.Meta["direction"].(string); d != "ascending" {
		t.Errorf("direction = %q; want ascending", d)
	}
	if nt, _ := got.Meta["next_target"].(string); nt != "10.0.0.5" {
		t.Errorf("next_target = %q; want 10.0.0.5", nt)
	}
	if dd, _ := got.Meta["distinct_dests"].(int); dd != 4 {
		t.Errorf("distinct_dests = %d; want 4", dd)
	}
}

func TestSynchronizedBurst(t *testing.T) {
	c := New(Config{Enabled: true, BurstWindow: time.Minute, BurstMinEvents: 3, BurstSensors: 2})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	var got *event.Event
	n := 0
	fire := func(sid string) {
		n++
		for _, e := range c.Observe(ev(sid, fmt.Sprintf("8.%d.0.1", n), nil)) {
			if e.RuleID == "fleet:synchronized-burst" {
				got = e
			}
		}
	}
	for i := 0; i < 3; i++ {
		fire("s1")
	}
	for i := 0; i < 3; i++ {
		fire("s2")
	}
	if got == nil {
		t.Fatal("synchronized-burst did not fire when 2 sensors spiked together")
	}
	if sc, _ := got.Meta["sensor_count"].(int); sc != 2 {
		t.Errorf("sensor_count = %d; want 2", sc)
	}
}

func TestFirstFleetContact(t *testing.T) {
	c := New(Config{Enabled: true, FirstContactSensors: 2, ASNSensors: 99})
	m := func() map[string]any { return map[string]any{"asn": "AS-NEW"} }
	if a := findAlert(c.Observe(ev("s1", "1.1.1.1", m())), "fleet:first-fleet-contact"); a != nil {
		t.Fatal("fired at one sensor")
	}
	a := findAlert(c.Observe(ev("s2", "2.2.2.2", m())), "fleet:first-fleet-contact")
	if a == nil {
		t.Fatal("did not fire for a novel ASN reaching 2 sensors")
	}
	if k, _ := a.Meta["kind"].(string); k != "asn" {
		t.Errorf("kind = %q; want asn", k)
	}
	if id, _ := a.Meta["identity"].(string); id != "AS-NEW" {
		t.Errorf("identity = %q; want AS-NEW", id)
	}
}

func TestFirstContactNotNovelAfterWindow(t *testing.T) {
	c := New(Config{Enabled: true, FirstContactSensors: 2, ASNSensors: 99, Window: time.Hour})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	old := func(sid, ip string) *event.Event { return ev(sid, ip, map[string]any{"asn": "AS-OLD"}) }
	c.Observe(old("s1", "1.1.1.1")) // first contact recorded at t0
	now = now.Add(2 * time.Hour)    // beyond the novelty window
	c.Observe(old("s2", "2.2.2.2"))
	if a := findAlert(c.Observe(old("s3", "3.3.3.3")), "fleet:first-fleet-contact"); a != nil {
		t.Fatal("fired for an established (non-novel) ASN")
	}
}

func TestIdentityPivot(t *testing.T) {
	c := New(Config{Enabled: true, PivotSources: 3, PivotSensors: 2})
	// ja3 (strong) + tool (secondary) = a 2-attribute link that survives IP rotation.
	attrs := func() map[string]any { return map[string]any{"ja3": "J1", "tools": []string{"nmap"}} }
	c.Observe(ev("s1", "10.0.0.1", attrs()))
	c.Observe(ev("s1", "10.0.0.2", attrs()))
	a := findAlert(c.Observe(ev("s2", "10.0.0.3", attrs())), "fleet:identity-pivot")
	if a == nil {
		t.Fatal("did not fire for one identity across 3 IPs / 2 sensors")
	}
	ids, _ := a.Meta["identity"].([]string)
	if !containsStr(ids, "ja3=J1") || !containsStr(ids, "tool=nmap") {
		t.Errorf("identity = %v; want ja3=J1 + tool=nmap", ids)
	}
	if sc, _ := a.Meta["source_count"].(int); sc != 3 {
		t.Errorf("source_count = %d; want 3", sc)
	}
}

func TestIdentityPivotNeedsStrongAttr(t *testing.T) {
	// UA + tool alone (no fingerprint/credential) must not link.
	c := New(Config{Enabled: true, PivotSources: 2, PivotSensors: 2})
	weak := func() map[string]any { return map[string]any{"user_agent": "curl/8", "tools": []string{"nmap"}} }
	c.Observe(ev("s1", "10.0.0.1", weak()))
	if a := findAlert(c.Observe(ev("s2", "10.0.0.2", weak())), "fleet:identity-pivot"); a != nil {
		t.Fatal("linked on weak attributes only")
	}
}

func TestGeoDistributedActor(t *testing.T) {
	c := New(Config{Enabled: true, GeoCountries: 3, GeoSensors: 2})
	g := func(country string) map[string]any { return map[string]any{"ja3": "JG", "geo_country": country} }
	c.Observe(ev("s1", "10.0.0.1", g("US")))
	c.Observe(ev("s1", "10.0.0.2", g("DE")))
	a := findAlert(c.Observe(ev("s2", "10.0.0.3", g("BR"))), "fleet:geo-distributed-actor")
	if a == nil {
		t.Fatal("did not fire for one fingerprint from 3 countries / 2 sensors")
	}
	if by, _ := a.Meta["by"].(string); by != "fingerprint" {
		t.Errorf("by = %q; want fingerprint", by)
	}
	if cc, _ := a.Meta["country_count"].(int); cc != 3 {
		t.Errorf("country_count = %d; want 3", cc)
	}
}

func TestTargetProfileMatch(t *testing.T) {
	c := New(Config{Enabled: true, ProfileCVEs: 2, ProfileSources: 2, ProfileSensors: 2, CVESensors: 99})
	cve := func(sid, ip, id string) *event.Event {
		e := ev(sid, ip, nil)
		e.RuleID = "cve:" + id
		return e
	}
	// Two sources independently run the same A+B CVE playbook, across 2 sensors.
	c.Observe(cve("s1", "1.1.1.1", "CVE-A"))
	c.Observe(cve("s1", "1.1.1.1", "CVE-B"))
	c.Observe(cve("s2", "2.2.2.2", "CVE-A"))
	a := findAlert(c.Observe(cve("s2", "2.2.2.2", "CVE-B")), "fleet:target-profile-match")
	if a == nil {
		t.Fatal("did not fire for a shared multi-CVE playbook across sensors")
	}
	pb, _ := a.Meta["playbook"].([]string)
	if len(pb) != 2 || !containsStr(pb, "CVE-A") || !containsStr(pb, "CVE-B") {
		t.Errorf("playbook = %v; want [CVE-A CVE-B]", pb)
	}
	if sc, _ := a.Meta["source_count"].(int); sc != 2 {
		t.Errorf("source_count = %d; want 2", sc)
	}
}

func TestHoneytokenSpread(t *testing.T) {
	c := New(Config{Enabled: true, HoneytokenSensors: 2, SourceSensors: 99})
	tk := func(sid, ip string) *event.Event {
		e := ev(sid, ip, nil)
		e.RuleID = "canary:url:secret-token"
		return e
	}
	if a := findAlert(c.Observe(tk("s1", "1.1.1.1")), "fleet:honeytoken-spread"); a != nil {
		t.Fatal("fired at one sensor")
	}
	a := findAlert(c.Observe(tk("s2", "2.2.2.2")), "fleet:honeytoken-spread")
	if a == nil {
		t.Fatal("did not fire when the token reached 2 sensors")
	}
	if a.Severity != event.SeverityCritical {
		t.Errorf("severity = %v; want critical", a.Severity)
	}
	if tok, _ := a.Meta["token"].(string); tok != "canary:url:secret-token" {
		t.Errorf("token = %q", tok)
	}
}

func TestCVEEmergence(t *testing.T) {
	c := New(Config{Enabled: true, CVEEmergenceSensors: 2, CVESensors: 99, Window: time.Hour})
	ce := func(sid, ip, id string) *event.Event {
		e := ev(sid, ip, nil)
		e.RuleID = "cve:" + id
		return e
	}
	c.Observe(ce("s1", "1.1.1.1", "CVE-2026-0001"))
	a := findAlert(c.Observe(ce("s2", "2.2.2.2", "CVE-2026-0001")), "fleet:cve-emergence")
	if a == nil {
		t.Fatal("did not fire for a novel CVE on 2 sensors")
	}
	if got, _ := a.Meta["cve"].(string); got != "CVE-2026-0001" {
		t.Errorf("cve = %q", got)
	}
}

func TestCVEEmergenceEstablishedSilent(t *testing.T) {
	c := New(Config{Enabled: true, CVEEmergenceSensors: 2, CVESensors: 99, Window: time.Hour})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	ce := func(sid, ip, id string) *event.Event {
		e := ev(sid, ip, nil)
		e.RuleID = "cve:" + id
		return e
	}
	c.Observe(ce("s1", "1.1.1.1", "CVE-OLD")) // first contact at t0
	now = now.Add(2 * time.Hour)              // established beyond the window
	c.Observe(ce("s2", "2.2.2.2", "CVE-OLD"))
	if a := findAlert(c.Observe(ce("s3", "3.3.3.3", "CVE-OLD")), "fleet:cve-emergence"); a != nil {
		t.Fatal("fired for an established (non-novel) CVE")
	}
}

func TestCrossProtocolActor(t *testing.T) {
	c := New(Config{Enabled: true, CrossProtoHandlers: 3, CrossProtoSensors: 2, SourceSensors: 99})
	h := func(sid, handler string) *event.Event {
		e := ev(sid, "5.5.5.5", nil)
		e.Handler = handler
		return e
	}
	c.Observe(h("s1", "ssh"))
	c.Observe(h("s1", "http"))
	a := findAlert(c.Observe(h("s2", "redis")), "fleet:cross-protocol-actor")
	if a == nil {
		t.Fatal("did not fire for one source across 3 services / 2 sensors")
	}
	if hc, _ := a.Meta["handler_count"].(int); hc != 3 {
		t.Errorf("handler_count = %d; want 3", hc)
	}
}

func TestFingerprintASNSpread(t *testing.T) {
	c := New(Config{Enabled: true, FPASNs: 3, FPASNSensors: 2, FPSensors: 99, ASNSensors: 99})
	f := func(sid, ip, asn string) *event.Event {
		return ev(sid, ip, map[string]any{"ja3": "JX", "asn": asn})
	}
	c.Observe(f("s1", "1.1.1.1", "AS1"))
	c.Observe(f("s1", "2.2.2.2", "AS2"))
	a := findAlert(c.Observe(f("s2", "3.3.3.3", "AS3")), "fleet:fingerprint-asn-spread")
	if a == nil {
		t.Fatal("did not fire for one fingerprint from 3 ASNs / 2 sensors")
	}
	if ac, _ := a.Meta["asn_count"].(int); ac != 3 {
		t.Errorf("asn_count = %d; want 3", ac)
	}
}

func TestThreatIntelSurge(t *testing.T) {
	c := New(Config{Enabled: true, ThreatSurgeSources: 3, ThreatSurgeSensors: 2, SourceSensors: 99})
	flagged := func(sid, ip string) *event.Event { return ev(sid, ip, map[string]any{"threat_intel_hit": true}) }
	c.Observe(flagged("s1", "1.1.1.1"))
	c.Observe(flagged("s1", "2.2.2.2"))
	a := findAlert(c.Observe(flagged("s2", "3.3.3.3")), "fleet:threat-intel-surge")
	if a == nil {
		t.Fatal("did not fire for 3 flagged sources across 2 sensors")
	}
	if sc, _ := a.Meta["source_count"].(int); sc != 3 {
		t.Errorf("source_count = %d; want 3", sc)
	}
	// An unflagged event must not contribute.
	c2 := New(Config{Enabled: true, ThreatSurgeSources: 2, ThreatSurgeSensors: 1})
	c2.Observe(ev("s1", "9.9.9.9", nil))
	if a := findAlert(c2.Observe(ev("s2", "8.8.8.8", nil)), "fleet:threat-intel-surge"); a != nil {
		t.Fatal("fired for unflagged sources")
	}
}

func TestToolCampaign(t *testing.T) {
	c := New(Config{Enabled: true, ToolSensors: 2, ToolSources: 2, SourceSensors: 99})
	tl := func(sid, ip string) *event.Event { return ev(sid, ip, map[string]any{"tools": []string{"nuclei"}}) }
	c.Observe(tl("s1", "1.1.1.1"))
	a := findAlert(c.Observe(tl("s2", "2.2.2.2")), "fleet:tool-campaign")
	if a == nil {
		t.Fatal("did not fire when one tool reached 2 sensors / 2 sources")
	}
	if got, _ := a.Meta["tool"].(string); got != "nuclei" {
		t.Errorf("tool = %q", got)
	}
}

func TestC2Shared(t *testing.T) {
	c := New(Config{Enabled: true, C2Sensors: 2})
	u := func(sid, ip string) *event.Event {
		return ev(sid, ip, map[string]any{"harvested_urls": []string{"http://evil.example/x.sh"}})
	}
	c.Observe(u("s1", "1.1.1.1"))
	a := findAlert(c.Observe(u("s2", "2.2.2.2")), "fleet:c2-shared")
	if a == nil {
		t.Fatal("did not fire when one C2 URL reached 2 sensors")
	}
	if a.Severity != event.SeverityCritical {
		t.Errorf("severity = %v; want critical", a.Severity)
	}
	if got, _ := a.Meta["url"].(string); got != "http://evil.example/x.sh" {
		t.Errorf("url = %q", got)
	}
}

func TestUserAgentShared(t *testing.T) {
	c := New(Config{Enabled: true, UASensors: 2, UASources: 3, SourceSensors: 99})
	ua := func(sid, ip string) *event.Event {
		return ev(sid, ip, map[string]any{"user_agent": "python-requests/2.31"})
	}
	c.Observe(ua("s1", "1.1.1.1"))
	c.Observe(ua("s1", "2.2.2.2"))
	a := findAlert(c.Observe(ua("s2", "3.3.3.3")), "fleet:user-agent-shared")
	if a == nil {
		t.Fatal("did not fire for one UA across 2 sensors / 3 sources")
	}
	if got, _ := a.Meta["user_agent"].(string); got != "python-requests/2.31" {
		t.Errorf("user_agent = %q", got)
	}
}

func TestTacticConvergence(t *testing.T) {
	c := New(Config{Enabled: true, TacticSources: 3, TacticSensors: 2, SourceSensors: 99})
	tac := func(sid, ip string) *event.Event {
		e := ev(sid, ip, nil)
		e.MitreTechniques = []string{"T1190"}
		return e
	}
	c.Observe(tac("s1", "1.1.1.1"))
	c.Observe(tac("s1", "2.2.2.2"))
	a := findAlert(c.Observe(tac("s2", "3.3.3.3")), "fleet:tactic-convergence")
	if a == nil {
		t.Fatal("did not fire for one technique across 3 sources / 2 sensors")
	}
	if got, _ := a.Meta["technique"].(string); got != "T1190" {
		t.Errorf("technique = %q", got)
	}
}

func TestRecidivistNetwork(t *testing.T) {
	c := New(Config{Enabled: true, RecidivistBucket: time.Hour, RecidivistWindows: 3, ASNSensors: 99, Window: 10 * time.Minute, FirstSeenHorizon: 30 * 24 * time.Hour})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	asn := func() map[string]any { return map[string]any{"asn": "AS31337"} }
	c.Observe(ev("s1", "1.1.1.1", asn())) // bucket 0
	now = now.Add(time.Hour)
	c.Observe(ev("s2", "2.2.2.2", asn())) // bucket 1
	now = now.Add(time.Hour)
	a := findAlert(c.Observe(ev("s1", "3.3.3.3", asn())), "fleet:recidivist-network") // bucket 2 -> 3 buckets
	if a == nil {
		t.Fatal("did not fire for an ASN active across 3 buckets")
	}
	if ab, _ := a.Meta["active_buckets"].(int); ab != 3 {
		t.Errorf("active_buckets = %d; want 3", ab)
	}
}

func TestPortCampaign(t *testing.T) {
	c := New(Config{Enabled: true, PortCampaignSources: 3, PortCampaignSensors: 2, SourceSensors: 99})
	p := func(sid, ip string, port int) *event.Event {
		e := ev(sid, ip, nil)
		e.Dest = event.Endpoint{Port: port}
		return e
	}
	c.Observe(p("s1", "1.1.1.1", 23))
	c.Observe(p("s1", "2.2.2.2", 23))
	a := findAlert(c.Observe(p("s2", "3.3.3.3", 23)), "fleet:port-campaign")
	if a == nil {
		t.Fatal("did not fire for port 23 across 3 sources / 2 sensors")
	}
	if got, _ := a.Meta["port"].(int); got != 23 {
		t.Errorf("port = %d; want 23", got)
	}
}

func TestPortCampaignExcludesUbiquitous(t *testing.T) {
	c := New(Config{Enabled: true, PortCampaignSources: 2, PortCampaignSensors: 2, SourceSensors: 99})
	p := func(sid, ip string) *event.Event {
		e := ev(sid, ip, nil)
		e.Dest = event.Endpoint{Port: 443} // excluded by default
		return e
	}
	c.Observe(p("s1", "1.1.1.1"))
	if a := findAlert(c.Observe(p("s2", "2.2.2.2")), "fleet:port-campaign"); a != nil {
		t.Fatal("fired for an excluded ubiquitous port (443)")
	}
}

func TestCredentialSprayFleet(t *testing.T) {
	c := New(Config{Enabled: true, CredSprayPasswords: 3, CredSpraySensors: 2, CredSensors: 99, SourceSensors: 99})
	cr := func(sid, ip, pass string) *event.Event {
		return ev(sid, ip, map[string]any{"username": "admin", "password": pass})
	}
	c.Observe(cr("s1", "1.1.1.1", "p1"))
	c.Observe(cr("s1", "2.2.2.2", "p2"))
	a := findAlert(c.Observe(cr("s2", "3.3.3.3", "p3")), "fleet:credential-spray-fleet")
	if a == nil {
		t.Fatal("did not fire for one user / 3 passwords / 2 sensors")
	}
	if pc, _ := a.Meta["password_count"].(int); pc != 3 {
		t.Errorf("password_count = %d; want 3", pc)
	}
	if u, _ := a.Meta["username"].(string); u != "admin" {
		t.Errorf("username = %q", u)
	}
}

func TestAsnOrgCampaign(t *testing.T) {
	c := New(Config{Enabled: true, AsnOrgASNs: 2, AsnOrgSensors: 2, ASNSensors: 99, SourceSensors: 99})
	o := func(sid, ip, asn string) *event.Event {
		return ev(sid, ip, map[string]any{"asn": asn, "asn_org": "BadCloud Inc"})
	}
	c.Observe(o("s1", "1.1.1.1", "AS1"))
	a := findAlert(c.Observe(o("s2", "2.2.2.2", "AS2")), "fleet:asn-org-campaign")
	if a == nil {
		t.Fatal("did not fire for one org / 2 ASNs / 2 sensors")
	}
	if ac, _ := a.Meta["asn_count"].(int); ac != 2 {
		t.Errorf("asn_count = %d; want 2", ac)
	}
	if org, _ := a.Meta["asn_org"].(string); org != "BadCloud Inc" {
		t.Errorf("asn_org = %q", org)
	}
}

func TestAsnOrgNeedsMultipleASNs(t *testing.T) {
	// One org but a single ASN is just asn-multi-sensor territory, not this.
	c := New(Config{Enabled: true, AsnOrgASNs: 2, AsnOrgSensors: 2, ASNSensors: 99, SourceSensors: 99})
	o := func(sid, ip string) *event.Event {
		return ev(sid, ip, map[string]any{"asn": "AS1", "asn_org": "OneCloud"})
	}
	c.Observe(o("s1", "1.1.1.1"))
	if a := findAlert(c.Observe(o("s2", "2.2.2.2")), "fleet:asn-org-campaign"); a != nil {
		t.Fatal("fired for a single ASN")
	}
}

func TestCatalog(t *testing.T) {
	cat := Catalog()
	if len(cat) < 20 {
		t.Fatalf("catalog has %d entries; want the full detector set", len(cat))
	}
	seen := map[string]bool{}
	for _, r := range cat {
		if !strings.HasPrefix(r.ID, "fleet:") {
			t.Errorf("catalog id %q lacks fleet: prefix", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate catalog id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Summary == "" || len(r.Config) == 0 {
			t.Errorf("catalog entry %q missing summary/config", r.ID)
		}
	}
}

func TestCVEWaveCarriesRiskMeta(t *testing.T) {
	c := New(Config{Enabled: true, CVESensors: 2})
	cve := func(sid, ip string) *event.Event {
		e := ev(sid, ip, map[string]any{"cvss": 10.0, "epss": 0.94, "cwe": []string{"CWE-502"}, "cpe": "cpe:2.3:a:apache:log4j:*"})
		e.RuleID = "cve:CVE-2021-44228"
		return e
	}
	c.Observe(cve("s1", "1.1.1.1"))
	a := findAlert(c.Observe(cve("s2", "2.2.2.2")), "fleet:cve-wave")
	if a == nil {
		t.Fatal("cve-wave did not fire")
	}
	if cvss, _ := a.Meta["cvss"].(float64); cvss != 10.0 {
		t.Errorf("cvss = %v; want 10 propagated from the cve: event", a.Meta["cvss"])
	}
	if epss, _ := a.Meta["epss"].(float64); epss != 0.94 {
		t.Errorf("epss = %v; want 0.94", a.Meta["epss"])
	}
	if a.Meta["cwe"] == nil || a.Meta["cpe"] == nil {
		t.Errorf("cwe/cpe not propagated: %v / %v", a.Meta["cwe"], a.Meta["cpe"])
	}
}
