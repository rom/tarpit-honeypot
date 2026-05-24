package ui

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestChartFigureEncodesBase64JSON(t *testing.T) {
	fig := chartFigure("bar", "Test", map[string]any{"series": []chBar{{Label: "ssh", Value: 7}}})
	if fig.Type != "bar" || fig.Title != "Test" || fig.B64 == "" {
		t.Fatalf("bad fig: %+v", fig)
	}
	raw, err := base64.StdEncoding.DecodeString(fig.B64)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	var got struct {
		Series []chBar `json:"series"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(got.Series) != 1 || got.Series[0].Label != "ssh" || got.Series[0].Value != 7 {
		t.Errorf("series round-trip wrong: %+v", got.Series)
	}
}

func TestBuildTopologyGraph(t *testing.T) {
	s := &Server{topo: buildTestTopo(t)}
	fig := buildTopologyGraph(s.topologyView())
	if fig.Type != "topology" || fig.B64 == "" {
		t.Fatalf("bad topology fig: %+v", fig)
	}
	raw, _ := base64.StdEncoding.DecodeString(fig.B64)
	var g struct {
		Nodes []chNode `json:"nodes"`
		Edges []chEdge `json:"edges"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("json: %v", err)
	}
	var hasGW, hasHost bool
	for _, n := range g.Nodes {
		if n.Kind == "gateway" {
			hasGW = true
		}
		if n.Kind == "host" && n.Label == "web-prod-01" {
			hasHost = true
		}
	}
	if !hasGW || !hasHost {
		t.Errorf("topology graph missing gateway/host nodes: %+v", g.Nodes)
	}
	if len(g.Edges) == 0 {
		t.Errorf("topology graph has no edges")
	}
}

func TestChartfigTemplateRenders(t *testing.T) {
	var b strings.Builder
	fig := chartFigure("pie", "Sev", map[string]any{"slices": []chSlice{{Label: "high", Value: 3}}})
	if err := uiTmpl(t).ExecuteTemplate(&b, "chartfig", fig); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if !strings.Contains(html, `data-chart="pie"`) || !strings.Contains(html, "data-chart-b64=") {
		t.Errorf("chartfig render missing attrs: %s", html)
	}
}

func TestChartsTemplateRenders(t *testing.T) {
	page := chartsPage{Scanned: 42, Sections: []chartSection{{
		Heading: "Overview",
		Figs:    []chartFig{chartFigure("hbar", "Top", map[string]any{"series": []chBar{{Label: "x", Value: 1}}})},
	}}}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "charts", page); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"analytics", "Overview", `data-chart="hbar"`, "42 recent events"} {
		if !strings.Contains(html, want) {
			t.Errorf("charts page missing %q", want)
		}
	}
}

func TestTopologyTemplateIncludesGraph(t *testing.T) {
	s := &Server{topo: buildTestTopo(t)}
	page := topologyPage{Networks: s.topologyView(), Graph: buildTopologyGraph(s.topologyView())}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "topology", page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `data-chart="topology"`) {
		t.Errorf("topology page should embed the topology graph figure")
	}
}
