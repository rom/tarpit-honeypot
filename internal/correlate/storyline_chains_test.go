package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// driveStory feeds the steps and returns the last storyline event.
func driveStory(t *testing.T, steps []*event.Event) *event.Event {
	t.Helper()
	c, err := New(config.Correlate{})
	if err != nil {
		t.Fatal(err)
	}
	var story *event.Event
	for _, e := range steps {
		story = lastStory(c.Observe(e))
	}
	if story == nil {
		t.Fatal("expected a storyline to fire")
	}
	return story
}

func TestStorylineCoercedAuthRelay(t *testing.T) {
	src := event.Endpoint{IP: "203.0.113.60"}
	now := time.Now().UTC()
	story := driveStory(t, []*event.Event{
		{Source: src, Handler: "smb", RuleID: "listener:smb", Time: now,
			MitreTactics: []string{"reconnaissance"}},
		{Source: src, Handler: "dcerpc", RuleID: "listener:dcerpc", Time: now.Add(time.Second),
			MitreTactics: []string{"discovery"}, Anomalies: []string{"dcerpc-samr-enum"}},
		{Source: src, Handler: "dcerpc", RuleID: "listener:dcerpc", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"credential-access"}, Anomalies: []string{"dcerpc-coerced-auth"}},
	})
	if story.Meta["playbook"] != "ad-coerced-authentication-relay" {
		t.Errorf("playbook = %v; want ad-coerced-authentication-relay", story.Meta["playbook"])
	}
}

func TestStorylinePsExecLateral(t *testing.T) {
	src := event.Endpoint{IP: "203.0.113.61"}
	now := time.Now().UTC()
	story := driveStory(t, []*event.Event{
		{Source: src, Handler: "smb", RuleID: "listener:smb", Time: now,
			MitreTactics: []string{"reconnaissance"}},
		{Source: src, Handler: "dcerpc", RuleID: "listener:dcerpc", Time: now.Add(time.Second),
			MitreTactics: []string{"discovery"}, Anomalies: []string{"dcerpc-samr-enum"}},
		{Source: src, Handler: "dcerpc", RuleID: "listener:dcerpc", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"lateral-movement"}, Anomalies: []string{"dcerpc-svcctl-access"}},
	})
	if story.Meta["playbook"] != "ad-lateral-movement-psexec" {
		t.Errorf("playbook = %v; want ad-lateral-movement-psexec", story.Meta["playbook"])
	}
}

func TestStorylineDatabaseToRCE(t *testing.T) {
	src := event.Endpoint{IP: "203.0.113.62"}
	now := time.Now().UTC()
	story := driveStory(t, []*event.Event{
		{Source: src, Handler: "mssql", RuleID: "listener:mssql", Time: now,
			MitreTactics: []string{"reconnaissance"}},
		{Source: src, Handler: "mssql", RuleID: "listener:mssql", Time: now.Add(time.Second),
			MitreTactics: []string{"credential-access"}, Anomalies: []string{"mssql-login-attempt"}},
		{Source: src, Handler: "mssql", RuleID: "listener:mssql", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"execution"}, Anomalies: []string{"mssql-xp-cmdshell"}},
	})
	if story.Meta["playbook"] != "database-to-rce" {
		t.Errorf("playbook = %v; want database-to-rce", story.Meta["playbook"])
	}
}

func TestStorylineRedisRogueReplica(t *testing.T) {
	src := event.Endpoint{IP: "203.0.113.63"}
	now := time.Now().UTC()
	story := driveStory(t, []*event.Event{
		{Source: src, Handler: "redis", RuleID: "listener:redis", Time: now,
			MitreTactics: []string{"reconnaissance"}},
		{Source: src, Handler: "redis", RuleID: "listener:redis", Time: now.Add(time.Second),
			MitreTactics: []string{"lateral-movement"}, Anomalies: []string{"redis-replication-takeover"}},
		{Source: src, Handler: "redis", RuleID: "listener:redis", Time: now.Add(2 * time.Second),
			MitreTactics: []string{"execution"}, Anomalies: []string{"redis-module-load"}},
	})
	if story.Meta["playbook"] != "redis-rogue-replica-rce" {
		t.Errorf("playbook = %v; want redis-rogue-replica-rce", story.Meta["playbook"])
	}
}
