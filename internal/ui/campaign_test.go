package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestBuildCampaignViewLinksByFingerprint(t *testing.T) {
	now := time.Now()
	// Two distinct IPs share the same JA4 → one campaign. A third IP has a
	// different JA4 → its own single-IP cluster.
	evs := []*event.Event{
		{RuleID: "listener:ssh", Handler: "ssh", Time: now.Add(-3 * time.Minute),
			Source: event.Endpoint{IP: "10.0.0.1"}, Severity: event.SeverityHigh,
			Meta: map[string]any{"ja4": "SHARED-FP"}},
		{RuleID: "listener:web", Handler: "http", Time: now.Add(-2 * time.Minute),
			Source: event.Endpoint{IP: "10.0.0.2"}, Severity: event.SeverityMedium,
			Meta: map[string]any{"ja4": "SHARED-FP"}},
		{RuleID: "listener:web", Handler: "http", Time: now.Add(-1 * time.Minute),
			Source: event.Endpoint{IP: "10.9.9.9"}, Severity: event.SeverityLow,
			Meta: map[string]any{"ja4": "LONELY-FP"}},
	}
	v := buildCampaignView(now.Add(-time.Hour), evs)

	if v.Sources != 3 {
		t.Fatalf("sources = %d; want 3", v.Sources)
	}
	// Find the linked multi-IP campaign.
	var multi *campaignCluster
	for i := range v.Clusters {
		if v.Clusters[i].Multi {
			multi = &v.Clusters[i]
		}
	}
	if multi == nil {
		t.Fatalf("expected a multi-IP campaign; clusters=%+v", v.Clusters)
	}
	if len(multi.Sources) != 2 {
		t.Errorf("campaign members = %v; want the two SHARED-FP IPs", multi.Sources)
	}
	if v.Linked != 2 {
		t.Errorf("linked sources = %d; want 2", v.Linked)
	}
	// The shared fingerprint must be reported as the linking evidence.
	var hasShared bool
	for _, l := range multi.Links {
		if l.Value == "SHARED-FP" {
			hasShared = true
		}
	}
	if !hasShared {
		t.Errorf("shared fingerprint not reported as link: %+v", multi.Links)
	}
	// Severity is the max across members (high).
	if multi.MaxSev != "high" {
		t.Errorf("campaign max severity = %q; want high", multi.MaxSev)
	}
	// Multi-IP campaign must sort ahead of the single-IP one.
	if !v.Clusters[0].Multi {
		t.Errorf("multi-IP campaign should sort first; got %+v", v.Clusters[0])
	}
}

func TestBuildJourneySankey(t *testing.T) {
	now := time.Now()
	// One source progresses discovery (ssh) → credential-access is implicit in
	// ssh; use distinct handlers to get distinct tactics in time order.
	evs := []*event.Event{
		{RuleID: "listener:a", Handler: "http", Time: now.Add(-3 * time.Minute), Source: event.Endpoint{IP: "1.1.1.1"}},
		{RuleID: "listener:b", Handler: "modbus", Time: now.Add(-1 * time.Minute), Source: event.Endpoint{IP: "1.1.1.1"}},
	}
	v := buildCampaignView(now.Add(-time.Hour), evs)
	if v.JourneyB64 == "" {
		t.Fatalf("expected a journey sankey for a multi-tactic source")
	}
	// Template renders without error and shows the headline.
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "campaign", v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "attacker journey") {
		t.Errorf("campaign page missing heading; got %d bytes", b.Len())
	}
}

func TestCampaignClusterIDStable(t *testing.T) {
	a := clusterID([]string{"1.1.1.1", "2.2.2.2"})
	b := clusterID([]string{"1.1.1.1", "2.2.2.2"})
	c := clusterID([]string{"3.3.3.3"})
	if a != b {
		t.Errorf("clusterID not stable: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("distinct member sets collided: %q", a)
	}
	if len(a) != 8 {
		t.Errorf("clusterID len = %d; want 8", len(a))
	}
}
