package enrich

import (
	"testing"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestDecorateAIClassByHandler(t *testing.T) {
	e := &Enricher{}
	ev := &event.Event{Handler: "agent", Source: event.Endpoint{IP: "10.1.2.3"}, Meta: map[string]any{}}
	e.Decorate(ev)
	if ev.Meta["ai"] != true || ev.Meta["ai_class"] != "agent" {
		t.Errorf("agent handler should set ai=true/ai_class=agent, got %v/%v", ev.Meta["ai"], ev.Meta["ai_class"])
	}
	if !hasLabel(ev, "meta:ai") {
		t.Errorf("want meta:ai umbrella, got %v", ev.Meta["labels"])
	}
}

func TestDecorateAIClassByMeta(t *testing.T) {
	// An autonomous agent recognized on an ordinary HTTP port is still AI.
	e := &Enricher{}
	ev := &event.Event{Handler: "http", Source: event.Endpoint{IP: "10.1.2.4"},
		Meta: map[string]any{"agent_protocol": "a2a"}}
	e.Decorate(ev)
	if ev.Meta["ai"] != true || ev.Meta["ai_class"] != "agent" {
		t.Errorf("agent_protocol meta should classify as AI/agent, got %v/%v", ev.Meta["ai"], ev.Meta["ai_class"])
	}
	if !hasLabel(ev, "meta:ai") {
		t.Errorf("want meta:ai from meta detection, got %v", ev.Meta["labels"])
	}
	// A plain web hit is not AI.
	plain := &event.Event{Handler: "http", Source: event.Endpoint{IP: "10.1.2.5"}, Meta: map[string]any{}}
	e.Decorate(plain)
	if _, ok := plain.Meta["ai"]; ok {
		t.Error("plain http must not be classified AI")
	}
}
