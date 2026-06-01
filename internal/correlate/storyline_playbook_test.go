package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// lastStory returns the storyline:* event from an Observe result, if any.
func lastStory(out []*event.Event) *event.Event {
	for i := len(out) - 1; i >= 0; i-- {
		if out[i].RuleID == "storyline:multi_stage" {
			return out[i]
		}
	}
	return nil
}

// TestStorylineCloudTakeoverPlaybook: a chain through the cloud handlers that
// reaches credential-access is labelled cloud-credential-takeover.
func TestStorylineCloudTakeoverPlaybook(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.50"}
	now := time.Now().UTC()
	steps := []*event.Event{
		{Source: src, Handler: "http", RuleID: "listener:http", Time: now,
			MitreTactics: []string{"reconnaissance"}, MitreTechniques: []string{"T1595"}},
		{Source: src, Handler: "kubernetes_api", RuleID: "listener:k8s", Time: now.Add(time.Second),
			MitreTactics: []string{"discovery"}, MitreTechniques: []string{"T1613"}},
		{Source: src, Handler: "vault", RuleID: "listener:vault", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"credential-access"}, MitreTechniques: []string{"T1555"},
			Anomalies: []string{"vault-secret-read"}},
	}
	var story *event.Event
	for _, e := range steps {
		story = lastStory(c.Observe(e))
	}
	if story == nil {
		t.Fatal("expected a storyline to fire")
	}
	if story.Meta["playbook"] != "cloud-credential-takeover" {
		t.Errorf("playbook = %v; want cloud-credential-takeover", story.Meta["playbook"])
	}
}

// TestStorylineTokenReuseCompromise: replaying a planted honeytoken flips the
// storyline to a confirmed compromise (critical + credential-replay playbook).
func TestStorylineTokenReuseCompromise(t *testing.T) {
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	src := event.Endpoint{IP: "203.0.113.51"}
	now := time.Now().UTC()
	steps := []*event.Event{
		{Source: src, Handler: "http", RuleID: "listener:http", Time: now,
			MitreTactics: []string{"reconnaissance"}, MitreTechniques: []string{"T1595"}},
		{Source: src, Handler: "ssh", RuleID: "listener:ssh", Time: now.Add(time.Second),
			MitreTactics: []string{"credential-access"}, MitreTechniques: []string{"T1110.001"}},
		{Source: src, Handler: "vault", RuleID: "canary:token_used", Time: now.Add(2 * time.Second),
			Severity:     event.SeverityCritical,
			MitreTactics: []string{"defense-evasion"}, MitreTechniques: []string{"T1078"}},
	}
	var story *event.Event
	for _, e := range steps {
		story = lastStory(c.Observe(e))
	}
	if story == nil {
		t.Fatal("expected a storyline to fire")
	}
	if story.Severity != event.SeverityCritical {
		t.Errorf("severity = %v; want critical", story.Severity)
	}
	if story.Meta["token_reuse"] != true {
		t.Errorf("token_reuse not set: %v", story.Meta)
	}
	if story.Meta["playbook"] != "credential-replay-compromise" {
		t.Errorf("playbook = %v; want credential-replay-compromise", story.Meta["playbook"])
	}
}

// TestStorylineWebVulnFuzzingPlaybook: many web-attack classes without landing
// execution is labelled web-vuln-fuzzing.
func TestStorylineWebVulnFuzzingPlaybook(t *testing.T) {
	c, _ := New(config.Correlate{})
	src := event.Endpoint{IP: "203.0.113.70"}
	now := time.Now().UTC()
	steps := []*event.Event{
		{Source: src, Handler: "http", RuleID: "listener:http", Time: now,
			MitreTactics: []string{"reconnaissance"}, MitreTechniques: []string{"T1595"}},
		{Source: src, Handler: "http", RuleID: "listener:http", Time: now.Add(time.Second),
			MitreTactics: []string{"initial-access"}, MitreTechniques: []string{"T1190"},
			Anomalies: []string{"webapp:ssti"}},
		{Source: src, Handler: "http", RuleID: "listener:http", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"discovery"}, MitreTechniques: []string{"T1083"},
			Anomalies: []string{"webapp:nosqli"}},
	}
	var story *event.Event
	for _, e := range steps {
		story = lastStory(c.Observe(e))
	}
	if story == nil || story.Meta["playbook"] != "web-vuln-fuzzing" {
		t.Fatalf("playbook = %v; want web-vuln-fuzzing", story)
	}
}

// TestStorylineDataExfilPlaybook: reaching the exfiltration stage labels the
// chain data-exfiltration.
func TestStorylineDataExfilPlaybook(t *testing.T) {
	c, _ := New(config.Correlate{})
	src := event.Endpoint{IP: "203.0.113.71"}
	now := time.Now().UTC()
	steps := []*event.Event{
		{Source: src, Handler: "ftp", RuleID: "listener:ftp", Time: now,
			MitreTactics: []string{"reconnaissance"}, MitreTechniques: []string{"T1595"}},
		{Source: src, Handler: "ftp", RuleID: "listener:ftp", Time: now.Add(time.Second),
			MitreTactics: []string{"credential-access"}, MitreTechniques: []string{"T1110.001"}},
		{Source: src, Handler: "ftp", RuleID: "listener:ftp", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"exfiltration"}, MitreTechniques: []string{"T1020"},
			Anomalies: []string{"ftp-download-attempt"}},
	}
	var story *event.Event
	for _, e := range steps {
		story = lastStory(c.Observe(e))
	}
	if story == nil || story.Meta["playbook"] != "data-exfiltration" {
		t.Fatalf("playbook = %v; want data-exfiltration", story)
	}
	if story.Severity != event.SeverityCritical {
		t.Errorf("exfiltration storyline should be critical; got %v", story.Severity)
	}
}
