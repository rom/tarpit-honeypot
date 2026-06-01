package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestWebAttackProbeFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		WebAttackProbe: config.CorrWebAttackProbe{Enabled: true, DistinctClasses: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"webapp:ssti", "webapp:xxe", "webapp:nosqli"} {
		ev := mkEvent("1.2.3.4", 80, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:web_attack_probe") == nil {
		t.Fatalf("web_attack_probe did not fire: %v", last)
	}
	// A single repeated class must not trip it.
	cor2, _ := New(config.Correlate{
		WebAttackProbe: config.CorrWebAttackProbe{Enabled: true, DistinctClasses: 3, Window: time.Minute, Severity: "high"},
	})
	var l2 []*event.Event
	for i := 0; i < 5; i++ {
		ev := mkEvent("5.5.5.5", 80, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{"webapp:sqli"}
		l2 = cor2.Observe(ev)
	}
	if aggregate(l2, "correlate:web_attack_probe") != nil {
		t.Error("one repeated class should not trip web_attack_probe")
	}
}

func TestSSHKeySprayFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		SSHKeySpray: config.CorrSSHKeySpray{Enabled: true, DistinctKeys: 3, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, fp := range []string{"ssh-rsa:SHA256:a", "ssh-ed25519:SHA256:b", "ecdsa:SHA256:c"} {
		ev := mkEvent("1.2.3.4", 22, now.Add(time.Duration(i)*time.Second))
		ev.Meta = map[string]any{"ssh_pubkey_fps": []string{fp}}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:ssh_key_spray") == nil {
		t.Fatalf("ssh_key_spray did not fire: %v", last)
	}
}

func TestSpamRelayFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		SpamRelay: config.CorrSpamRelay{Enabled: true, Events: 2, Window: time.Minute, Severity: "medium"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, m := range []string{"smtp-open-relay-probe", "smtp-user-enumeration"} {
		ev := mkEvent("1.2.3.4", 25, now.Add(time.Duration(i)*time.Second))
		ev.Anomalies = []string{m}
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:spam_relay") == nil {
		t.Fatalf("spam_relay did not fire: %v", last)
	}
}
