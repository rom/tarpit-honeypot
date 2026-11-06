package sensor

import (
	"bytes"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/devices"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/fuzzdos"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/ioc"
)

func TestForwardDest(t *testing.T) {
	cases := map[string]string{
		"http://host:8080/x": "host:8080",
		"http://host/x":      "host:80",
		"https://host/x":     "host:443",
		"https://[::1]:9/y":  "[::1]:9",
		"":                   "",
		"::notaurl":          "",
	}
	for in, want := range cases {
		if got := forwardDest(in); got != want {
			t.Errorf("forwardDest(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSqliteTuning(t *testing.T) {
	st := sqliteTuning(config.Tuning{SinkBatch: 10, SinkFlush: 20, SinkHardCap: 30})
	if st.Batch != 10 || st.Flush != 20 || st.HardCap != 30 {
		t.Errorf("sqliteTuning mapped wrong: %+v", st)
	}
}

func TestContainsStrAndBroadcast(t *testing.T) {
	if !containsStr([]string{"a", "b"}, "b") || containsStr([]string{"a"}, "z") {
		t.Error("containsStr wrong")
	}
	for _, h := range []string{"ssdp", "llmnr", "nbns", "mdns", "ws-discovery", "cldap", "coap"} {
		if !isBroadcastHandler(h) {
			t.Errorf("isBroadcastHandler(%q) = false; want true", h)
		}
	}
	if isBroadcastHandler("http") {
		t.Error("http is not a broadcast handler")
	}
}

func TestMetaStringSlice(t *testing.T) {
	if got := metaStringSlice([]string{"a", "b"}); len(got) != 2 {
		t.Errorf("[]string → %v", got)
	}
	if got := metaStringSlice([]any{"a", 1, "b"}); len(got) != 2 {
		t.Errorf("[]any → %v (should keep only strings)", got)
	}
	if got := metaStringSlice("solo"); len(got) != 1 || got[0] != "solo" {
		t.Errorf("string → %v", got)
	}
	if got := metaStringSlice(42); got != nil {
		t.Errorf("int → %v; want nil", got)
	}
}

func TestHoneynetSnapshotNil(t *testing.T) {
	s := honeynetSnapshot(nil)
	if len(s.Hosts) != 0 || len(s.Networks) != 0 {
		t.Errorf("nil topology should yield empty snapshot: %+v", s)
	}
}

func TestEffIface(t *testing.T) {
	s := &Sensor{cfg: &config.Config{}}
	s.cfg.Sensor.Interfaces = []string{"eth0", "eth1"}
	if got := s.effIface("eth9"); got != "eth9" {
		t.Errorf("explicit section iface = %q; want eth9", got)
	}
	if got := s.effIface(""); got != "eth0" {
		t.Errorf("fallback to first configured iface = %q; want eth0", got)
	}
	s.cfg.Sensor.Interfaces = nil
	if got := s.effIface(""); got != "" {
		t.Errorf("no ifaces → %q; want empty", got)
	}
}

func TestIOCEventAndRiskEvent(t *testing.T) {
	s := &Sensor{name: "sensorA", identity: identity.New("seed-xyz")}
	src := &event.Event{Source: event.Endpoint{IP: "203.0.113.9"}, Proto: "tcp", RuleID: "listener:http"}

	ie := s.iocEvent(ioc.Indicator{Type: "url", Value: "http://evil/x"}, src)
	if ie.RuleID != "ioc:url" || ie.Sensor != "sensorA" {
		t.Errorf("iocEvent wrong: rule=%q sensor=%q", ie.RuleID, ie.Sensor)
	}
	if ie.Meta["ioc_value"] != "http://evil/x" || ie.Source.IP != "203.0.113.9" {
		t.Errorf("iocEvent meta/source wrong: %+v", ie)
	}

	for _, tc := range []struct {
		level string
		want  event.Severity
	}{
		{"critical", event.SeverityCritical},
		{"elevated", event.SeverityMedium},
		{"high", event.SeverityHigh},
	} {
		re := s.riskEvent(src, tc.level, 9.5)
		if re.RuleID != "risk:"+tc.level || re.Severity != tc.want {
			t.Errorf("riskEvent(%q): rule=%q sev=%v; want sev %v", tc.level, re.RuleID, re.Severity, tc.want)
		}
		if re.Meta["score"] != 9.5 {
			t.Errorf("riskEvent score = %v; want 9.5", re.Meta["score"])
		}
	}
}

func TestObserveFuzzDoSStampsAnomaly(t *testing.T) {
	s := &Sensor{name: "t", fuzzTrack: fuzzdos.NewTracker(time.Minute)}
	ev := &event.Event{
		RuleID: "listener:raw", Proto: "tcp", Handler: "raw",
		Source: event.Endpoint{IP: "203.0.113.4"}, Dest: event.Endpoint{Port: 9}, Time: time.Now(),
	}
	_ = s.observeFuzzDoS(ev, bytes.Repeat([]byte("A"), 2000)) // buffer-overflow filler
	if !containsStr(ev.Anomalies, "fuzzing-buffer-overflow") {
		t.Errorf("expected a fuzzing-buffer-overflow anomaly; got %v", ev.Anomalies)
	}
	if ev.Meta["fuzz_technique"] != "buffer-overflow" {
		t.Errorf("fuzz_technique meta = %v; want buffer-overflow", ev.Meta["fuzz_technique"])
	}
	// Non-listener events are ignored.
	other := &event.Event{RuleID: "device:new", Source: event.Endpoint{IP: "203.0.113.4"}}
	if got := s.observeFuzzDoS(other, []byte("x")); got != nil {
		t.Errorf("non-listener event should be ignored; got %v", got)
	}
}

func TestObserveDeviceEmitsNew(t *testing.T) {
	s := &Sensor{name: "t", devices: devices.New(devices.Config{Learn: false})}
	ev := &event.Event{
		RuleID: "listener:dhcp", Source: event.Endpoint{IP: "10.0.0.50"}, Time: time.Now(),
		Meta: map[string]any{"client_mac": "aa:bb:cc:dd:ee:ff", "hostname": "workstation"},
	}
	d := s.observeDevice(ev)
	if d == nil || d.RuleID != "device:new" {
		t.Fatalf("expected device:new; got %v", d)
	}
	// Our own device events never recurse.
	if got := s.observeDevice(&event.Event{RuleID: "device:new", Source: event.Endpoint{IP: "10.0.0.51"}}); got != nil {
		t.Errorf("device:new event should not recurse; got %v", got)
	}
	// Nil registry → no-op.
	bare := &Sensor{name: "t"}
	if got := bare.observeDevice(ev); got != nil {
		t.Errorf("nil registry should no-op; got %v", got)
	}
}
