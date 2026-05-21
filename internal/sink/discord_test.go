package sink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDiscordSink(t *testing.T) {
	var got []byte
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s, err := newDiscord(config.Channel{ID: "d", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ev := &event.Event{
		ID: "e1", RuleID: "webapp:sqli", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "203.0.113.9"}, Time: time.Now(),
		Meta: map[string]any{"path": "/x", "tool": "sqlmap"},
	}
	if err := s.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if ct != "application/json" {
		t.Errorf("content-type = %q; want application/json", ct)
	}
	var p discordPayload
	if err := json.Unmarshal(got, &p); err != nil {
		t.Fatalf("payload not JSON: %v (%s)", err, got)
	}
	if len(p.Embeds) != 1 {
		t.Fatalf("embeds = %d; want 1", len(p.Embeds))
	}
	if p.Embeds[0].Title != "webapp:sqli" {
		t.Errorf("title = %q", p.Embeds[0].Title)
	}
	if p.Embeds[0].Color != 0xE67E22 {
		t.Errorf("color = %#x; want high=orange", p.Embeds[0].Color)
	}
	// Source must appear in a field.
	foundSrc := false
	for _, f := range p.Embeds[0].Fields {
		if f.Name == "Source" && f.Value == "203.0.113.9" {
			foundSrc = true
		}
	}
	if !foundSrc {
		t.Errorf("source field missing: %+v", p.Embeds[0].Fields)
	}
}

func TestDiscordURLEnv(t *testing.T) {
	t.Setenv("DISCORD_HOOK", "https://discord.example/api/webhooks/1/abc")
	s, err := newDiscord(config.Channel{ID: "d", URLEnv: "DISCORD_HOOK"})
	if err != nil {
		t.Fatal(err)
	}
	if s.(*discordSink).url != "https://discord.example/api/webhooks/1/abc" {
		t.Errorf("url not read from env: %q", s.(*discordSink).url)
	}
	if _, err := newDiscord(config.Channel{ID: "d"}); err == nil {
		t.Error("expected error when no url/url_env")
	}
}
