package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func mkAuthEvent(srcIP, user, pass string, t time.Time) *event.Event {
	return &event.Event{
		ID:       event.NewID(),
		Time:     t,
		Sensor:   "test",
		RuleID:   "listener:any",
		Severity: event.SeverityLow,
		Source:   event.Endpoint{IP: srcIP, Port: 12345},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: 22},
		Proto:    "tcp",
		Meta:     map[string]any{"username": user, "password": pass},
	}
}

func findRule(out []*event.Event, rule string) *event.Event {
	for _, e := range out {
		if e.RuleID == rule {
			return e
		}
	}
	return nil
}

func TestPasswordSprayFires(t *testing.T) {
	cor, err := New(config.Correlate{
		PasswordSpray: config.CorrPasswordSpray{Enabled: true, DistinctUsers: 3, Window: time.Minute, Severity: "high"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var last []*event.Event
	for i, u := range []string{"admin", "root", "operator"} {
		last = cor.Observe(mkAuthEvent("5.5.5.5", u, "Winter2024", now.Add(time.Duration(i)*time.Second)))
	}
	ev := findRule(last, "correlate:password_spray")
	if ev == nil {
		t.Fatalf("expected password_spray after 3 distinct users; got %d events", len(last))
	}
	if ev.Meta["distinct_users"].(int) != 3 {
		t.Errorf("distinct_users = %v; want 3", ev.Meta["distinct_users"])
	}
}

func TestPasswordSprayIgnoresSameUser(t *testing.T) {
	cor, _ := New(config.Correlate{
		PasswordSpray: config.CorrPasswordSpray{Enabled: true, DistinctUsers: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now()
	var last []*event.Event
	for i := 0; i < 5; i++ {
		last = cor.Observe(mkAuthEvent("5.5.5.5", "admin", "p", now.Add(time.Duration(i)*time.Second)))
	}
	if findRule(last, "correlate:password_spray") != nil {
		t.Error("password_spray fired for repeated same username (that's brute force, not spray)")
	}
}

func TestCredentialReuseFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		CredReuse: config.CorrCredReuse{Enabled: true, DistinctSources: 3, Window: time.Hour, Severity: "high"},
	})
	now := time.Now()
	var last []*event.Event
	for i, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		last = cor.Observe(mkAuthEvent(ip, "admin", "Password1", now.Add(time.Duration(i)*time.Second)))
	}
	ev := findRule(last, "correlate:credential_reuse")
	if ev == nil {
		t.Fatalf("expected credential_reuse after 3 distinct sources; got %d events", len(last))
	}
	if ev.Meta["distinct_sources"].(int) != 3 {
		t.Errorf("distinct_sources = %v; want 3", ev.Meta["distinct_sources"])
	}
	if ev.Meta["username"] != "admin" {
		t.Errorf("username = %v; want admin", ev.Meta["username"])
	}
	// The password must never appear in the emitted event.
	for k, v := range ev.Meta {
		if s, ok := v.(string); ok && s == "Password1" {
			t.Errorf("password leaked in meta[%q]", k)
		}
	}
}
