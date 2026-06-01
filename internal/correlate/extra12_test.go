package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDNSTunnelFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		DNSTunnel: config.CorrDNSTunnel{Enabled: true, Events: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent("1.2.3.4", 53, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{"dns-tunnel-suspected"}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:dns_tunnel") == nil {
		t.Fatalf("dns_tunnel did not fire: %v", last)
	}
}

func TestReconToExploitFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ReconToExploit: config.CorrReconToExploit{Enabled: true, Window: 30 * time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	// Stage 1: recon.
	e1 := mkEvent("9.9.9.9", 80, now)
	e1.MitreTactics = []string{"reconnaissance"}
	cor.Observe(e1)
	// Stage 2: a CVE exploit from the same source -> fires.
	e2 := mkEvent("9.9.9.9", 80, now.Add(time.Minute))
	e2.RuleID = "cve:CVE-2021-44228"
	out := cor.Observe(e2)
	if aggregate(out, "correlate:recon_to_exploit") == nil {
		t.Fatalf("recon_to_exploit did not fire: %v", out)
	}
	// A bare exploit with no prior recon must not fire.
	cor2, _ := New(config.Correlate{
		ReconToExploit: config.CorrReconToExploit{Enabled: true, Window: 30 * time.Minute, Severity: "high"},
	})
	e3 := mkEvent("5.5.5.5", 80, now)
	e3.RuleID = "cve:CVE-2021-44228"
	if aggregate(cor2.Observe(e3), "correlate:recon_to_exploit") != nil {
		t.Error("exploit without prior recon should not fire recon_to_exploit")
	}
}
