package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func mkEvent(srcIP string, dstPort int, t time.Time) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		Time:     t,
		Sensor:   "test",
		RuleID:   "listener:any",
		Severity: event.SeverityLow,
		Source:   event.Endpoint{IP: srcIP, Port: 12345},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: dstPort},
		Proto:    "tcp",
	}
}

func TestPortScanFires(t *testing.T) {
	cor, err := New(config.Correlate{
		PortScan: config.CorrPortScan{
			Enabled:       true,
			DistinctPorts: 3,
			Window:        time.Minute,
			Severity:      "high",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var lastOut []*event.Event
	for i, port := range []int{22, 80, 443} {
		lastOut = cor.Observe(mkEvent("1.2.3.4", port, now.Add(time.Duration(i)*time.Second)))
	}
	if len(lastOut) != 2 {
		t.Fatalf("third event should produce 2 (orig + aggregate), got %d", len(lastOut))
	}
	if lastOut[1].RuleID != "correlate:port_scan" {
		t.Fatalf("expected port_scan aggregate, got %s", lastOut[1].RuleID)
	}
	if lastOut[1].Severity != event.SeverityHigh {
		t.Fatalf("expected high severity, got %v", lastOut[1].Severity)
	}
}

func TestPortScanDedupsRepeats(t *testing.T) {
	cor, _ := New(config.Correlate{
		PortScan: config.CorrPortScan{
			Enabled: true, DistinctPorts: 2, Window: time.Minute, Severity: "high",
		},
	})
	now := time.Now().UTC()
	cor.Observe(mkEvent("1.2.3.4", 22, now))
	out := cor.Observe(mkEvent("1.2.3.4", 80, now))
	if len(out) != 2 {
		t.Fatalf("threshold hit should emit aggregate, got %d", len(out))
	}
	out = cor.Observe(mkEvent("1.2.3.4", 443, now))
	if len(out) != 1 {
		t.Fatalf("re-firing within window should be deduped, got %d", len(out))
	}
}

func TestBruteForceFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		BruteForce: config.CorrBruteForce{
			Enabled: true, Attempts: 3, Window: time.Minute, PerPort: true, Severity: "high",
		},
	})
	now := time.Now().UTC()
	var lastOut []*event.Event
	for i := 0; i < 3; i++ {
		lastOut = cor.Observe(mkEvent("9.9.9.9", 22, now.Add(time.Duration(i)*time.Second)))
	}
	if len(lastOut) != 2 || lastOut[1].RuleID != "correlate:brute_force" {
		t.Fatalf("expected brute_force aggregate; got %+v", lastOut)
	}
	if lastOut[1].Meta["port"] != 22 {
		t.Errorf("expected port=22 in meta, got %v", lastOut[1].Meta["port"])
	}
}

func TestPortScanWindowResets(t *testing.T) {
	cor, _ := New(config.Correlate{
		PortScan: config.CorrPortScan{
			Enabled: true, DistinctPorts: 3, Window: 50 * time.Millisecond, Severity: "high",
		},
	})
	now := time.Now().UTC()
	cor.Observe(mkEvent("1.1.1.1", 22, now))
	cor.Observe(mkEvent("1.1.1.1", 80, now))
	out := cor.Observe(mkEvent("1.1.1.1", 443, now.Add(200*time.Millisecond)))
	if len(out) != 1 {
		t.Fatalf("window should have reset; got %d events", len(out))
	}
}

func TestDisabledCorrelatorIsNoOp(t *testing.T) {
	cor, _ := New(config.Correlate{})
	out := cor.Observe(mkEvent("1.2.3.4", 22, time.Now().UTC()))
	if len(out) != 1 {
		t.Fatalf("disabled correlator should return only the original event, got %d", len(out))
	}
}
