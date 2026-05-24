package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestTollFraudFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		TollFraud: config.CorrTollFraud{Enabled: true, Events: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent("1.2.3.4", 5060, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "sip_tcp"
		ev.Anomalies = []string{"sip-invite-attempt"}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:toll_fraud") == nil {
		t.Fatalf("toll_fraud did not fire: %v", last)
	}
}

func TestVoIPEnumFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		VoIPEnum: config.CorrVoIPEnum{Enabled: true, DistinctServices: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, h := range []string{"sip_tcp", "sccp", "h323"} {
		ev := mkEvent("9.9.9.9", 5060+i, now.Add(time.Duration(i)*time.Second))
		ev.Handler = h
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:voip_enum") == nil {
		t.Fatalf("voip_enum did not fire: %v", last)
	}
	// A non-VoIP handler must not contribute.
	ev := mkEvent("5.5.5.5", 80, now)
	ev.Handler = "http"
	if aggregate(cor.Observe(ev), "correlate:voip_enum") != nil {
		t.Error("http should not trip voip_enum")
	}
}

func TestPBXControlFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		PBXControl: config.CorrPBXControl{Enabled: true, Events: 2, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"ami-login", "ami-command"} {
		ev := mkEvent("10.0.0.5", 5038, now.Add(time.Duration(i)*time.Second))
		ev.Handler = "asterisk_ami"
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:pbx_control") == nil {
		t.Fatalf("pbx_control did not fire: %v", last)
	}
}
