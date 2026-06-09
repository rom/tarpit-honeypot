package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

const sampleRules = `
- id: custom-log4shell-ua
  title: Log4Shell in User-Agent
  severity: critical
  tags: [custom:log4shell, attack.t1190]
  match:
    handler: [http, https]
    meta.user_agent|contains: "${jndi:"
- id: custom-ssh-root
  title: SSH root login attempt
  severity: high
  tags: [custom:ssh-root]
  match:
    handler: ssh
    meta.user_attempt: root
- id: custom-highport-redis
  title: redis on a high port
  match:
    handler: redis
    dest_port|gt: "1024"
    anomaly: redis-config-probe
`

func loadTmp(t *testing.T, body string) *Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, errs := Load(dir)
	if len(errs) != 0 {
		t.Fatalf("load errors: %v", errs)
	}
	return eng
}

func TestEngineMatches(t *testing.T) {
	eng := loadTmp(t, sampleRules)
	if eng.Count() != 3 {
		t.Fatalf("loaded %d rules; want 3", eng.Count())
	}

	// http with a jndi UA → critical rule fires, severity raised, tags added.
	ev := &event.Event{Handler: "http", Severity: event.SeverityLow,
		Meta: map[string]any{"user_agent": "Mozilla ${jndi:ldap://x/a}"}}
	m := eng.Apply(ev)
	if len(m) != 1 || m[0] != "custom-log4shell-ua" {
		t.Fatalf("matched = %v; want [custom-log4shell-ua]", m)
	}
	if ev.Severity != event.SeverityCritical || !ev.SeverityOverridden {
		t.Errorf("severity not raised to critical: %v", ev.Severity)
	}
	if !has(ev.Anomalies, "custom:log4shell") || !has(ev.Anomalies, "attack.t1190") || !has(ev.Anomalies, "detect:custom-log4shell-ua") {
		t.Errorf("expected tags + detect marker in anomalies, got %v", ev.Anomalies)
	}

	// ssh non-root → no match (AND on the exact user_attempt).
	nomatch := &event.Event{Handler: "ssh", Meta: map[string]any{"user_attempt": "admin"}}
	if m := eng.Apply(nomatch); len(m) != 0 {
		t.Errorf("ssh admin should not match, got %v", m)
	}

	// multi-condition: redis + high port + anomaly all required.
	redis := &event.Event{Handler: "redis", Dest: event.Endpoint{Port: 6379},
		Anomalies: []string{"redis-config-probe"}}
	if m := eng.Apply(redis); len(m) != 1 || m[0] != "custom-highport-redis" {
		t.Errorf("redis rule: matched = %v; want [custom-highport-redis]", m)
	}
	// same redis but low port → AND fails.
	redisLow := &event.Event{Handler: "redis", Dest: event.Endpoint{Port: 80},
		Anomalies: []string{"redis-config-probe"}}
	if m := eng.Apply(redisLow); len(m) != 0 {
		t.Errorf("redis low-port should not match, got %v", m)
	}
}

func TestLoadRejectsBadRule(t *testing.T) {
	_, errs := Load(tmpWith(t, "- id: bad\n  match:\n    meta.x|re: \"(\"\n"))
	if len(errs) == 0 {
		t.Fatal("expected a compile error for the invalid regex")
	}
}

func tmpWith(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
