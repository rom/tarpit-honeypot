package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestHostSweepFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		HostSweep: config.CorrHostSweep{Enabled: true, DistinctHosts: 4, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 4; i++ {
		ev := mkEvent("1.1.1.1", 445, now.Add(time.Duration(i)*time.Second))
		ev.Dest.IP = fmt.Sprintf("10.0.0.%d", 10+i)
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:host_sweep")
	if agg == nil {
		t.Fatalf("host_sweep did not fire: %v", last)
	}
	if agg.Meta["distinct_hosts"].(int) != 4 {
		t.Errorf("distinct_hosts = %v; want 4", agg.Meta["distinct_hosts"])
	}
	// Re-hitting the same host must not re-fire (deduped + no new host).
	ev := mkEvent("1.1.1.1", 445, now)
	ev.Dest.IP = "10.0.0.10"
	if aggregate(cor.Observe(ev), "correlate:host_sweep") != nil {
		t.Error("host_sweep should be deduped within the window")
	}
}

func TestServiceSweepFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ServiceSweep: config.CorrServiceSweep{Enabled: true, DistinctServices: 3, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, h := range []string{"ssh", "http", "modbus"} {
		ev := mkEvent("2.2.2.2", 1000+i, now.Add(time.Duration(i)*time.Second))
		ev.Handler = h
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:service_sweep") == nil {
		t.Fatalf("service_sweep did not fire: %v", last)
	}
}

func TestUARotationFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		UARotation: config.CorrUARotation{Enabled: true, DistinctAgents: 3, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, ua := range []string{"curl/8", "python-requests/2", "Mozilla/5.0"} {
		ev := mkEvent("3.3.3.3", 80, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "http"
		ev.Meta = map[string]any{"user_agent": ua}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:ua_rotation") == nil {
		t.Fatalf("ua_rotation did not fire: %v", last)
	}
	// A single repeated UA must not trip a different source.
	cor2, _ := New(config.Correlate{
		UARotation: config.CorrUARotation{Enabled: true, DistinctAgents: 3, Window: time.Minute, Severity: "medium"},
	})
	for i := 0; i < 4; i++ {
		ev := mkEvent("4.4.4.4", 80, now.Add(time.Duration(i)*time.Second))
		ev.Meta = map[string]any{"user_agent": "same"}
		last = cor2.Observe(ev)
	}
	if aggregate(last, "correlate:ua_rotation") != nil {
		t.Error("one repeated UA must not trip ua_rotation")
	}
}

func TestExploitChainFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ExploitChain: config.CorrExploitChain{Enabled: true, DistinctCVEs: 2, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, id := range []string{"CVE-2021-44228", "CVE-2014-6271"} {
		ev := mkEvent("5.5.5.5", 80, now.Add(time.Duration(i)*time.Second))
		ev.RuleID = "cve:" + id
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:exploit_chain")
	if agg == nil {
		t.Fatalf("exploit_chain did not fire: %v", last)
	}
	if agg.Severity != event.SeverityCritical {
		t.Errorf("severity = %v; want critical", agg.Severity)
	}
	if agg.Meta["distinct_cves"].(int) != 2 {
		t.Errorf("distinct_cves = %v; want 2", agg.Meta["distinct_cves"])
	}
}

func TestICSControlFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ICSControl: config.CorrICSControl{Enabled: true, Attempts: 3, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	// A passive read must NOT count toward the control threshold.
	read := mkEvent("6.6.6.6", 502, now)
	read.Handler = "modbus"
	cor.Observe(read)
	for i := 0; i < 3; i++ {
		ev := mkEvent("6.6.6.6", 502, now.Add(time.Duration(i+1)*time.Second))
		ev.Handler = "modbus"
		ev.Anomalies = []string{"modbus-write-attempt"}
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:ics_control")
	if agg == nil {
		t.Fatalf("ics_control did not fire: %v", last)
	}
	if agg.Meta["control_commands"].(int) != 3 {
		t.Errorf("control_commands = %v; want 3 (read must not count)", agg.Meta["control_commands"])
	}
}

func TestCanaryTripFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		CanaryTrip: config.CorrCanaryTrip{Enabled: true, DistinctTokens: 2, Window: time.Hour, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, rid := range []string{"canary:db_password", "canary:url:admin_portal"} {
		ev := mkEvent("7.7.7.7", 443, now.Add(time.Duration(i)*time.Second))
		ev.RuleID = rid
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:canary_trip") == nil {
		t.Fatalf("canary_trip did not fire: %v", last)
	}
}

func TestFingerprintReuseFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		FingerprintReuse: config.CorrFingerprintReuse{Enabled: true, DistinctSources: 3, Window: time.Hour, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, src := range []string{"9.0.0.1", "9.0.0.2", "9.0.0.3"} {
		ev := mkEvent(src, 443, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "https"
		ev.Meta = map[string]any{"ja3": "deadbeefcafe"}
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:fingerprint_reuse")
	if agg == nil {
		t.Fatalf("fingerprint_reuse did not fire: %v", last)
	}
	if agg.Meta["distinct_sources"].(int) != 3 || agg.Meta["fingerprint_kind"] != "ja3" {
		t.Errorf("meta = %v; want 3 ja3 sources", agg.Meta)
	}
	// The same fingerprint from one repeated source must not trip it.
	cor2, _ := New(config.Correlate{
		FingerprintReuse: config.CorrFingerprintReuse{Enabled: true, DistinctSources: 3, Window: time.Hour, Severity: "medium"},
	})
	for i := 0; i < 5; i++ {
		ev := mkEvent("9.9.9.9", 443, now.Add(time.Duration(i)*time.Second))
		ev.Meta = map[string]any{"ja3": "x"}
		last = cor2.Observe(ev)
	}
	if aggregate(last, "correlate:fingerprint_reuse") != nil {
		t.Error("one source must not trip fingerprint_reuse")
	}
}

func TestProtocolViolationFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ProtocolViolation: config.CorrProtocolViolation{Enabled: true, DistinctAnomalies: 3, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, a := range []string{"http-method-unknown", "ssh-banner-non-printable", "tls-record-oversize"} {
		ev := mkEvent("8.8.8.8", 80, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{a}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:protocol_violation") == nil {
		t.Fatalf("protocol_violation did not fire: %v", last)
	}
}

func TestExfilFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		Exfil: config.CorrExfil{Enabled: true, Bytes: 1000, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent("1.0.0.9", 80, now.Add(time.Duration(i)*time.Second))
		ev.PayloadLen = 400
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:exfil")
	if agg == nil {
		t.Fatalf("exfil did not fire: %v", last)
	}
	if agg.Meta["bytes"].(int64) < 1000 {
		t.Errorf("bytes = %v; want >= 1000", agg.Meta["bytes"])
	}
}

func TestSessionFloodFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		SessionFlood: config.CorrSessionFlood{Enabled: true, Connections: 5, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 5; i++ {
		last = cor.Observe(mkEvent("1.0.0.8", 22, now.Add(time.Duration(i)*time.Second)))
	}
	agg := aggregate(last, "correlate:session_flood")
	if agg == nil {
		t.Fatalf("session_flood did not fire: %v", last)
	}
	if agg.Meta["connections"].(int) != 5 {
		t.Errorf("connections = %v; want 5", agg.Meta["connections"])
	}
}

// TestExtraCorrelatorsDisabledByDefault: with an empty config none of the
// new detectors fire, so they're strictly opt-in (no behavior change for
// existing deployments).
func TestExtraCorrelatorsDisabledByDefault(t *testing.T) {
	cor, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 50; i++ {
		ev := mkEvent("1.2.3.4", 80, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "http"
		ev.RuleID = "cve:CVE-2021-44228"
		ev.Anomalies = []string{"a", "b", "c", "d", "e"}
		ev.Meta = map[string]any{"ja3": "x", "user_agent": fmt.Sprintf("ua%d", i)}
		ev.PayloadLen = 1 << 20
		ev.Dest.IP = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		out := cor.Observe(ev)
		for _, e := range out {
			if e.RuleID != ev.RuleID && len(e.RuleID) > 10 && e.RuleID[:10] == "correlate:" {
				t.Fatalf("disabled correlator fired: %s", e.RuleID)
			}
		}
	}
}
