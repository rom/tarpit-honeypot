package ui

import (
	"html/template"
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/honeynet"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
)

func uiTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("").Funcs(tmplFuncs(func() int { return 0 }, "nvd", "")).Parse(tmpls)
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func buildTestTopo(t *testing.T) *honeynet.Topology {
	t.Helper()
	cfg := []config.Honeynet{{
		ID:      "corp",
		CIDR:    "10.50.0.0/24",
		Gateway: "10.50.0.1",
		Domain:  "corp.example.local",
		Hosts: []config.HoneynetHost{
			{IP: "10.50.0.10", Hostname: "web-prod-01", OS: "linux", Services: []config.HoneynetService{
				{Port: 22, Handler: "ssh"},
				{Port: 80, Handler: "http"},
			}},
		},
	}}
	topo, err := honeynet.Build(cfg, identity.New("ui-test-seed"), jitter.New(0, 0), t.TempDir(), nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

func TestTopologyViewFromTopology(t *testing.T) {
	s := &Server{topo: buildTestTopo(t)}
	nets := s.topologyView()
	if len(nets) != 1 {
		t.Fatalf("got %d networks; want 1", len(nets))
	}
	n := nets[0]
	if n.ID != "corp" || n.CIDR != "10.50.0.0/24" || n.Domain != "corp.example.local" {
		t.Errorf("network meta wrong: %+v", n)
	}
	if len(n.Hosts) != 1 {
		t.Fatalf("got %d hosts; want 1", len(n.Hosts))
	}
	h := n.Hosts[0]
	if h.IP != "10.50.0.10" || h.Hostname != "web-prod-01" {
		t.Errorf("host wrong: %+v", h)
	}
	if h.MAC == "" || len(strings.Split(h.MAC, ":")) != 6 {
		t.Errorf("host MAC not rendered: %q", h.MAC)
	}
	if len(h.Services) != 2 {
		t.Errorf("got %d services; want 2", len(h.Services))
	}
}

func TestTopologyViewNilTopo(t *testing.T) {
	s := &Server{}
	if v := s.topologyView(); v != nil {
		t.Errorf("nil topology should yield nil view; got %v", v)
	}
}

func TestTopologyTemplateRenders(t *testing.T) {
	s := &Server{topo: buildTestTopo(t)}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "topology", topologyPage{Networks: s.topologyView()}); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"honeynet topology", "corp", "10.50.0.10", "web-prod-01", "22/ssh", "80/http"} {
		if !strings.Contains(html, want) {
			t.Errorf("topology page missing %q", want)
		}
	}
}

func TestTopologyTemplateEmptyPlaceholder(t *testing.T) {
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "topology", topologyPage{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No honeynet configured") {
		t.Errorf("empty topology should show placeholder")
	}
}

func TestDocsTemplateRenders(t *testing.T) {
	var b strings.Builder
	p := docsPage{Listeners: 7, Networks: 2, Hosts: 5, DevicesOn: true, UIBind: "127.0.0.1:8080"}
	if err := uiTmpl(t).ExecuteTemplate(&b, "docs", p); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		"documentation", "scananalysis:profile", "Small services", "tarpit.emulate",
		"7 listener(s)", "127.0.0.1:8080",
		`href="/topology"`, `href="/docs"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("docs page missing %q", want)
		}
	}
}
