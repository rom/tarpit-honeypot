package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestCloudCredTheftFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		CloudCredTheft: config.CorrCloudCredTheft{Enabled: true, Events: 2, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"cloud-credential-theft", "etcd-secret-read"} {
		ev := mkEvent("1.2.3.4", 80+i, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:cloud_cred_theft") == nil {
		t.Fatalf("cloud_cred_theft did not fire: %v", last)
	}
	// An unrelated anomaly must not contribute.
	ev := mkEvent("5.6.7.8", 80, now)
	ev.Anomalies = []string{"http-login-attempt"}
	if aggregate(cor.Observe(ev), "correlate:cloud_cred_theft") != nil {
		t.Error("a login attempt should not trip cloud_cred_theft")
	}
}

func TestSSRFCallbackFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		SSRFCallback: config.CorrSSRFCallback{Enabled: true, Events: 3, Window: time.Hour, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 3; i++ {
		ev := mkEvent("203.0.113.9", 80, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{"ssrf-callback"}
		ev.Meta = map[string]any{"ssrf_token": fmt.Sprintf("tok-%d", i)}
		last = cor.Observe(ev)
	}
	agg := aggregate(last, "correlate:ssrf_callback")
	if agg == nil {
		t.Fatalf("ssrf_callback did not fire: %v", last)
	}
	if agg.Meta["distinct_tokens"].(int) != 3 {
		t.Errorf("ssrf_callback distinct_tokens = %v, want 3", agg.Meta["distinct_tokens"])
	}
}

func TestSSRFCallbackSameTokenDoesNotFire(t *testing.T) {
	cor, _ := New(config.Correlate{
		SSRFCallback: config.CorrSSRFCallback{Enabled: true, Events: 3, Window: time.Hour, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i := 0; i < 5; i++ {
		ev := mkEvent("203.0.113.9", 80, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{"ssrf-callback"}
		ev.Meta = map[string]any{"ssrf_token": "same-token"}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:ssrf_callback") != nil {
		t.Error("repeated callbacks of the SAME token should not reach the distinct-token threshold")
	}
}
