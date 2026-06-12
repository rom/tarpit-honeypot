package store

import (
	"context"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// ConversationNav steps through the events between two peers (src_ip ↔ dst_ip)
// in time order, ignoring events that share only one of the two endpoints.
func TestConversationNav(t *testing.T) {
	s, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)
	mk := func(id, src, dst string, off int) *event.Event {
		return &event.Event{
			ID: id, Time: base.Add(time.Duration(off) * time.Minute), Sensor: "t",
			RuleID: "r", Severity: event.SeverityHigh,
			Source: event.Endpoint{IP: src, Port: 1000}, Dest: event.Endpoint{IP: dst, Port: 22},
			Proto: "tcp", Handler: "ssh",
		}
	}
	for _, e := range []*event.Event{
		mk("a1", "10.0.0.9", "192.0.2.5", 1),
		mk("a2", "10.0.0.9", "192.0.2.5", 2),
		mk("a3", "10.0.0.9", "192.0.2.5", 3),
		mk("noiseC", "10.0.0.9", "192.0.2.6", 2), // same src, different dst — not in A↔B
		mk("noiseD", "10.0.0.8", "192.0.2.5", 2), // different src, same dst — not in A↔B
	} {
		if err := s.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	get := func(id string) *event.Event {
		ev, err := s.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		return ev
	}

	// Middle event: prev=a1, next=a3, total=3 (noise excluded), pos=2.
	nb, err := s.ConversationNav(ctx, get("a2"))
	if err != nil {
		t.Fatal(err)
	}
	if nb.PrevID != "a1" || nb.NextID != "a3" || nb.Total != 3 || nb.Pos != 2 {
		t.Errorf("a2 nav = %+v; want prev a1 next a3 total 3 pos 2", nb)
	}
	// First event: no prev, next=a2, pos=1.
	if nb, _ = s.ConversationNav(ctx, get("a1")); nb.PrevID != "" || nb.NextID != "a2" || nb.Pos != 1 || nb.Total != 3 {
		t.Errorf("a1 nav = %+v", nb)
	}
	// Last event: prev=a2, no next, pos=3.
	if nb, _ = s.ConversationNav(ctx, get("a3")); nb.PrevID != "a2" || nb.NextID != "" || nb.Pos != 3 {
		t.Errorf("a3 nav = %+v", nb)
	}
	// A peer with an empty IP yields an empty (Total 0) result.
	if nb, _ = s.ConversationNav(ctx, &event.Event{Source: event.Endpoint{IP: "1.2.3.4"}}); nb.Total != 0 {
		t.Errorf("empty-peer nav = %+v", nb)
	}
}
