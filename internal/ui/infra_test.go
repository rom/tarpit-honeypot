package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestOverlayActivity(t *testing.T) {
	now := time.Now()
	evs := []*event.Event{
		{Dest: event.Endpoint{IP: "10.0.0.5"}, Source: event.Endpoint{IP: "1.1.1.1"}, Severity: event.SeverityHigh, Time: now.Add(-2 * time.Minute)},
		{Dest: event.Endpoint{IP: "10.0.0.5"}, Source: event.Endpoint{IP: "2.2.2.2"}, Severity: event.SeverityCritical, Time: now},
		{Dest: event.Endpoint{IP: "10.0.0.6"}, Source: event.Endpoint{IP: "1.1.1.1"}, Severity: event.SeverityLow, Time: now},
	}
	nets := []topoNetworkView{{
		ID: "corp", Hosts: []topoHostView{
			{IP: "10.0.0.5"}, {IP: "10.0.0.6"}, {IP: "10.0.0.7"},
		},
	}}
	active := overlayActivity(nets, aggregateHostActivity(evs))
	if !active {
		t.Fatal("expected activity overlaid")
	}
	h5 := nets[0].Hosts[0]
	if h5.Events != 2 || h5.Attackers != 2 || h5.MaxSev != "critical" {
		t.Errorf("host 10.0.0.5 overlay wrong: %+v", h5)
	}
	if nets[0].Hosts[2].Events != 0 {
		t.Errorf("quiet host should have 0 events: %+v", nets[0].Hosts[2])
	}
	// Network rollup: 3 events, 2 distinct attackers.
	if nets[0].Events != 3 || nets[0].Attackers != 2 {
		t.Errorf("network rollup wrong: events=%d attackers=%d", nets[0].Events, nets[0].Attackers)
	}

	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "topology", topologyPage{Networks: nets, Active: active}); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"Infrastructure map", "10.0.0.5", "attacker(s)", "quiet"} {
		if !strings.Contains(html, want) {
			t.Errorf("infra map missing %q", want)
		}
	}
}
