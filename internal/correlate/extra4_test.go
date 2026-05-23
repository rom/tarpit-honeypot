package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestAmplificationProbeFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		AmplificationProbe: config.CorrAmplificationProbe{Enabled: true, DistinctServices: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, h := range []string{"chargen", "ntp", "dns"} {
		ev := mkEvent("1.2.3.4", 100+i, now.Add(time.Duration(i)*time.Second))
		ev.Handler = h
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:amplification_probe")
	if agg == nil {
		t.Fatalf("amplification_probe did not fire: %v", last)
	}
	if agg.Meta["distinct_services"].(int) != 3 {
		t.Errorf("distinct_services = %v; want 3", agg.Meta["distinct_services"])
	}
	// A non-amplifier service must not contribute.
	ev := mkEvent("5.5.5.5", 80, now)
	ev.Handler = "http"
	if aggregate(cor.Observe(ev), "correlate:amplification_probe") != nil {
		t.Error("http should not trip amplification_probe")
	}
}

func TestDefaultCredSweepFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		DefaultCredSweep: config.CorrDefaultCredSweep{Enabled: true, DistinctServices: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, h := range []string{"ssh", "ftp", "telnet"} {
		ev := mkEvent("9.9.9.9", 1000+i, now.Add(time.Duration(i)*time.Second))
		ev.Handler = h
		ev.Anomalies = []string{"default-credential-attempt"}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:default_cred_sweep") == nil {
		t.Fatalf("default_cred_sweep did not fire: %v", last)
	}
}

func TestCVECampaignFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		CVECampaign: config.CorrCVECampaign{Enabled: true, DistinctSources: 3, Window: time.Hour, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent(fmt.Sprintf("203.0.113.%d", 10+i), 443, now.Add(time.Duration(i)*time.Second))
		ev.RuleID = "cve:CVE-2021-44228"
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:cve_campaign")
	if agg == nil {
		t.Fatalf("cve_campaign did not fire: %v", last)
	}
	if agg.Meta["cve"] != "CVE-2021-44228" || agg.Meta["distinct_sources"].(int) != 3 {
		t.Errorf("cve_campaign meta = %v", agg.Meta)
	}
}
