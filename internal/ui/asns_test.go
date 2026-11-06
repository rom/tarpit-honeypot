package ui

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func asnEv(id, ip string, asn int, org, country string, sev event.Severity) *event.Event {
	return &event.Event{
		ID: id, Time: time.Now().UTC(), Sensor: "s", RuleID: "r", Severity: sev,
		Source: event.Endpoint{IP: ip}, Handler: "http", Dest: event.Endpoint{Port: 80},
		Meta: map[string]any{"asn": asn, "asn_org": org, "geo_country": country},
	}
}

func TestBuildASNsViewRanksByAttackers(t *testing.T) {
	evs := []*event.Event{
		// AS64500: 2 distinct attacking hosts, 3 events.
		asnEv("a", "1.1.1.1", 64500, "Evil Hosting", "RU", event.SeverityHigh),
		asnEv("b", "1.1.1.2", 64500, "Evil Hosting", "RU", event.SeverityCritical),
		asnEv("c", "1.1.1.1", 64500, "Evil Hosting", "RU", event.SeverityLow),
		// AS64501: 1 host, 2 events.
		asnEv("d", "2.2.2.2", 64501, "Quiet Net", "DE", event.SeverityMedium),
		asnEv("e", "2.2.2.2", 64501, "Quiet Net", "DE", event.SeverityLow),
		// No ASN enrichment -> ignored.
		{ID: "f", Time: time.Now().UTC(), Source: event.Endpoint{IP: "3.3.3.3"}, Severity: event.SeverityHigh, Meta: map[string]any{}},
	}
	p := buildASNsView(evs)
	if p.TotalASNs != 2 {
		t.Fatalf("TotalASNs=%d want 2", p.TotalASNs)
	}
	if p.TotalAttackers != 3 {
		t.Errorf("TotalAttackers=%d want 3 (distinct IPs with an ASN)", p.TotalAttackers)
	}
	if len(p.Rows) != 2 || p.Rows[0].ASN != 64500 {
		t.Fatalf("ranking wrong: %+v", p.Rows)
	}
	if p.Rows[0].Attackers != 2 || p.Rows[0].Events != 3 {
		t.Errorf("AS64500 row=%+v want 2 attackers / 3 events", p.Rows[0])
	}
	if p.Rows[0].Rank != 1 || p.Rows[1].Rank != 2 {
		t.Errorf("ranks not assigned: %+v", p.Rows)
	}
	if p.Rows[0].MaxSev != "critical" {
		t.Errorf("AS64500 max severity=%q want critical", p.Rows[0].MaxSev)
	}
	if p.Rows[0].Href != "/events?asn=64500" {
		t.Errorf("AS64500 href=%q", p.Rows[0].Href)
	}
}

func TestASNsHandlerRenders(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	_ = st.Insert(ctx, asnEv("a", "1.1.1.1", 64500, "Evil Hosting", "RU", event.SeverityHigh))
	_ = st.Insert(ctx, asnEv("b", "1.1.1.2", 64500, "Evil Hosting", "RU", event.SeverityCritical))
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.handleASNs(w, httptest.NewRequest("GET", "/asns", nil))
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"networks", "AS64500", "Evil Hosting", "/events?asn=64500"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered networks page missing %q", want)
		}
	}
}
