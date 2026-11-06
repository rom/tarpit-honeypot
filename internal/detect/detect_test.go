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

func TestEngineStatsHitCounts(t *testing.T) {
	eng := loadTmp(t, sampleRules)
	// Fire the ssh-root rule twice.
	for i := 0; i < 2; i++ {
		eng.Apply(&event.Event{Handler: "ssh", Meta: map[string]any{"user_attempt": "root"}})
	}
	stats := eng.Stats()
	if len(stats) != 3 {
		t.Fatalf("Stats len = %d; want 3", len(stats))
	}
	// Sorted by hits desc, so the ssh-root rule is first with 2.
	if stats[0].ID != "custom-ssh-root" || stats[0].Hits != 2 {
		t.Errorf("top stat = %+v; want custom-ssh-root hits=2", stats[0])
	}
	if stats[0].Title == "" || stats[0].Conditions == 0 {
		t.Errorf("stat metadata not populated: %+v", stats[0])
	}
}

// The shipped configs/rules/ packs all compile cleanly (this is what an
// operator copies into their rules_dir, and what validate-config loads).
func TestShippedRulesCompile(t *testing.T) {
	eng, errs := Load("../../configs/rules")
	if len(errs) != 0 {
		t.Fatalf("shipped rules failed to load: %v", errs)
	}
	if eng.Count() == 0 {
		t.Fatal("shipped rules dir loaded zero rules")
	}
}

// The enrichment-reputation pack fires on the v1.2 enrichment labels.
func TestEnrichmentRulesFire(t *testing.T) {
	eng, errs := Load("../../configs/rules")
	if len(errs) != 0 {
		t.Fatalf("load: %v", errs)
	}
	fires := func(meta map[string]any, wantID string, wantSev event.Severity) {
		t.Helper()
		ev := &event.Event{Handler: "http", Severity: event.SeverityLow, Meta: meta}
		m := eng.Apply(ev)
		if !has(m, wantID) {
			t.Errorf("meta %v: matched %v; want %q among them", meta, m, wantID)
		}
		if wantSev != 0 && ev.Severity < wantSev {
			t.Errorf("meta %v: severity %v; want >= %v", meta, ev.Severity, wantSev)
		}
	}
	fires(map[string]any{"spoofed_ptr": true}, "enrich-spoofed-crawler-ptr", event.SeverityHigh)
	fires(map[string]any{"threat_confidence": "high"}, "enrich-high-threat-confidence", event.SeverityHigh)
	fires(map[string]any{"anonymized": true}, "enrich-anonymized-source", event.SeverityMedium)
	fires(map[string]any{"asn_reputation": []string{"spamhaus-asndrop"}}, "enrich-bulletproof-asn", event.SeverityMedium)
	fires(map[string]any{"asn_geo_mismatch": true}, "enrich-asn-geo-mismatch", event.SeverityMedium)
	fires(map[string]any{"geo_risk": true}, "enrich-high-risk-geo", 0)
	fires(map[string]any{"cred_class": "default"}, "enrich-default-or-breached-credentials", event.SeverityHigh)
	fires(map[string]any{"cred_class": "breach"}, "enrich-default-or-breached-credentials", event.SeverityHigh)
	fires(map[string]any{"dns_dga": true}, "enrich-dga-domain", event.SeverityMedium)
	fires(map[string]any{"domain_bad": true}, "enrich-malicious-domain", event.SeverityHigh)
	// Combination rules reach critical.
	fires(map[string]any{"spoofed_ptr": true, "threat_intel_hit": true}, "enrich-spoofing-and-blacklisted", event.SeverityCritical)
	fires(map[string]any{"anonymized": true, "threat_confidence": "high"}, "enrich-anonymized-high-confidence", event.SeverityCritical)

	// A benign event trips none of the enrichment rules.
	benign := &event.Event{Handler: "http", Severity: event.SeverityLow, Meta: map[string]any{"geo_country": "US"}}
	for _, id := range eng.Apply(benign) {
		if len(id) >= 7 && id[:7] == "enrich-" {
			t.Errorf("benign event matched enrichment rule %q", id)
		}
	}
}

// The named OT-malware pack recognizes family TTPs from the OT handlers'
// anomaly markers (handler + anomaly, so it fires on protocol-legal control
// actions, not an exploit string).
func TestOTMalwareRulesFire(t *testing.T) {
	eng, errs := Load("../../configs/rules")
	if len(errs) != 0 {
		t.Fatalf("load: %v", errs)
	}
	fires := func(handler string, anoms []string, meta map[string]any, wantID string) {
		t.Helper()
		ev := &event.Event{Handler: handler, Severity: event.SeverityLow, Anomalies: anoms, Meta: meta}
		if m := eng.Apply(ev); !has(m, wantID) {
			t.Errorf("handler=%s anomalies=%v: matched %v; want %q", handler, anoms, m, wantID)
		}
	}
	fires("modbus", []string{"ics-plc-write"}, nil, "ot-malware-frostygoop")
	fires("iec104", []string{"ics-iec104-command"}, nil, "ot-malware-industroyer")
	fires("tristation", []string{"ics-safety-controller-manipulation"}, nil, "ot-malware-triton")
	fires("codesys", []string{"ics-plc-program-access"}, nil, "ot-malware-pipedream")
	fires("s7", []string{"ics-plc-mode-change"}, nil, "ot-malware-stuxnet")
	fires("opcua", []string{"ics-opcua-open-channel"}, nil, "ot-malware-havex")

	// A plain Modbus read (no write marker) must NOT trip FrostyGoop.
	ev := &event.Event{Handler: "modbus", Anomalies: []string{"ics-process-data-access"}}
	if has(eng.Apply(ev), "ot-malware-frostygoop") {
		t.Error("a Modbus read wrongly matched the FrostyGoop rule")
	}
}

// The agentic-attack pack fires on the agent:* markers from the agent handler.
func TestAgenticRulesFire(t *testing.T) {
	eng, errs := Load("../../configs/rules")
	if len(errs) != 0 {
		t.Fatalf("load: %v", errs)
	}
	fires := func(handler string, anoms []string, wantID string) {
		t.Helper()
		ev := &event.Event{Handler: handler, Severity: event.SeverityLow, Anomalies: anoms}
		if m := eng.Apply(ev); !has(m, wantID) {
			t.Errorf("handler=%s anomalies=%v: matched %v; want %q", handler, anoms, m, wantID)
		}
	}
	fires("agent", []string{"agent-attack", "agent:autonomous"}, "agentic-attack")
	fires("agent", []string{"agent:counter-exfil"}, "agentic-counter-exfil")
	fires("agent", []string{"agent:exfil", "agent:cred-access"}, "agentic-exfil")
	fires("agent", []string{"agent:ap2", "agent:payment-target"}, "agentic-payment-fraud")
	fires("agent", []string{"agent:a2a"}, "agentic-protocol-probe")
}
