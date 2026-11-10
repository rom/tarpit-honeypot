package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// TestAnalyticsTemplateRenders: the analytics template executes cleanly against a
// populated view and shows each section.
func TestAnalyticsTemplateRenders(t *testing.T) {
	v := analyticsView{
		Sources:      5,
		Transactions: 5,
		Rules:        []ruleRow{{Antecedent: "svc:modbus", Consequent: "svc:s7", Count: 3, SupportPct: 60, ConfPct: 100, Lift: 1.67}},
		Pairs:        []pairRow{{A: "svc:modbus", B: "svc:s7", Count: 3, Lift: 1.67, Jaccard: 0.6}},
		GraphB64:     "e30=", // {}
		GraphNodes:   4, GraphEdges: 3, GraphBetween: true,
		TopNodes: []centRow{{Label: "ja4:t13d", Kind: "fp", Degree: 3, Betweenness: 3}},
		Actors:   []actorDiv{{IP: "1.2.3.4", Events: 10, Services: 2, Evenness: 0.9, Gini: 0.1, Focus: "spray", TopService: "modbus"}},
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "analytics", v); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"association rules", "infrastructure pivot graph", "actor targeting diversity", "svc:modbus", "ja4:t13d", "1.2.3.4", `data-chart="force"`} {
		if !strings.Contains(html, want) {
			t.Errorf("analytics page missing %q", want)
		}
	}
}

// TestHandleAnalyticsEndToEnd: three sources that share a JA4 fingerprint and all
// hit modbus+s7, plus two http-only sources, should yield the modbus→s7 rule and
// a non-empty pivot graph with the shared fingerprint as central infrastructure.
func TestHandleAnalyticsEndToEnd(t *testing.T) {
	s := fleetTestServer(t)
	ctx := context.Background()
	id := 0
	ins := func(ip, handler string, meta map[string]any) {
		id++
		ev := &event.Event{
			ID:   time.Now().Format("150405.000000") + "-" + handler + itoa(id),
			Time: time.Now().UTC(), RuleID: "listener:" + handler, Severity: event.SeverityHigh,
			Handler: handler, Source: event.Endpoint{IP: ip}, Dest: event.Endpoint{Port: 502}, Meta: meta,
		}
		if err := s.store.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		ins(ip, "modbus", map[string]any{"ja4": "t13d1516h2_shared"})
		ins(ip, "s7", map[string]any{"ja4": "t13d1516h2_shared"})
	}
	ins("10.0.0.4", "http", map[string]any{})
	ins("10.0.0.5", "http", map[string]any{})

	w := httptest.NewRecorder()
	s.handleAnalytics(w, httptest.NewRequest(http.MethodGet, "/analytics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// Association rule svc:modbus -> svc:s7 (lift ~1.67) should surface.
	if !strings.Contains(body, "svc:modbus") || !strings.Contains(body, "svc:s7") {
		t.Error("expected the modbus/s7 association in the page")
	}
	// The shared JA4 is central infrastructure (3 sources) and must appear.
	if !strings.Contains(body, "t13d1516h2_shared") && !strings.Contains(body, "ja4:t13d") {
		t.Error("expected the shared JA4 fingerprint as central infrastructure")
	}
	if !strings.Contains(body, "infrastructure pivot graph") || !strings.Contains(body, `data-chart="force"`) {
		t.Error("expected the pivot graph figure")
	}
}
