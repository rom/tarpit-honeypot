package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestBuildFingerprintReport(t *testing.T) {
	now := time.Now().UTC()
	evs := []*event.Event{
		{ID: "1", Time: now.Add(-10 * time.Minute), Sensor: "edge-1", RuleID: "listener:tls",
			Severity: event.SeverityMedium, Source: event.Endpoint{IP: "1.1.1.1"},
			Dest: event.Endpoint{Port: 443}, Proto: "tcp",
			Meta: map[string]any{"ja3": "aaa", "geo_country": "RU", "asn": 13335, "asn_org": "Cloudflare", "tools": []any{"sqlmap"}}},
		{ID: "2", Time: now.Add(-2 * time.Minute), Sensor: "edge-2", RuleID: "malware:capture",
			Severity: event.SeverityCritical, Source: event.Endpoint{IP: "2.2.2.2"},
			Dest: event.Endpoint{Port: 8080}, Proto: "tcp",
			Meta: map[string]any{"ja3": "aaa", "geo_country": "CN", "payload_artifacts": []any{"elf:deadbeef -> x.bin"}}},
	}
	rep := buildFingerprintReport("ja3", "aaa", evs)
	if rep.Count != 2 || rep.IPs != 2 {
		t.Errorf("count/ips wrong: %+v", rep)
	}
	if rep.FirstSeen.After(rep.LastSeen) {
		t.Errorf("first/last seen inverted: %+v", rep)
	}
	if len(rep.Sensors) != 2 {
		t.Errorf("want 2 sensors (fleet correlation), got %+v", rep.Sensors)
	}
	if len(rep.Countries) != 2 {
		t.Errorf("want 2 countries, got %+v", rep.Countries)
	}
	if len(rep.Malware) == 0 || rep.Malware[0].Label != "elf" {
		t.Errorf("malware artifact kind not aggregated: %+v", rep.Malware)
	}
	// Ports labelled with service names.
	foundHTTPS := false
	for _, b := range rep.Ports {
		if strings.Contains(b.Label, "https") {
			foundHTTPS = true
		}
	}
	if !foundHTTPS {
		t.Errorf("port 443 not labelled with service name: %+v", rep.Ports)
	}
	// ASN label combines number + org.
	if len(rep.ASNs) == 0 || !strings.Contains(rep.ASNs[0].Label, "AS13335") {
		t.Errorf("asn label wrong: %+v", rep.ASNs)
	}
}

func TestFingerprintTemplatesRender(t *testing.T) {
	tmpl := uiTmpl(t)

	var b strings.Builder
	page := fingerprintsPage{Window: "30d", Rows: []store.FingerprintRow{
		{Kind: "ja3", Value: "abc123", Count: 9, IPs: 3, Sensors: 2, FirstSeen: time.Now(), LastSeen: time.Now()},
	}}
	if err := tmpl.ExecuteTemplate(&b, "fingerprints", page); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"fingerprint reputation", "abc123", `href="/fingerprints/ja3/abc123"`, `href="/fingerprints"`} {
		if !strings.Contains(html, want) {
			t.Errorf("fingerprints index missing %q", want)
		}
	}

	b.Reset()
	rep := buildFingerprintReport("ja3", "abc123", []*event.Event{
		{ID: "1", Time: time.Now(), Sensor: "edge-1", RuleID: "listener:tls",
			Severity: event.SeverityMedium, Source: event.Endpoint{IP: "1.1.1.1"},
			Dest: event.Endpoint{Port: 443}, Proto: "tcp", Meta: map[string]any{"ja3": "abc123", "geo_country": "RU"}},
	})
	if err := tmpl.ExecuteTemplate(&b, "fingerprint", rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"fingerprint — ja3", "abc123", "fleet correlation", "countries", "destination ports"} {
		if !strings.Contains(out, want) {
			t.Errorf("fingerprint detail missing %q", want)
		}
	}
}

func TestFingerprintHandlersEndToEnd(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	ev := &event.Event{
		ID: "1", Time: time.Now().UTC(), Sensor: "edge-1", RuleID: "listener:tls",
		Severity: event.SeverityMedium, Source: event.Endpoint{IP: "1.1.1.1"},
		Dest: event.Endpoint{IP: "10.0.0.1", Port: 443}, Proto: "tcp",
		Meta: map[string]any{"ja3": "abc123", "geo_country": "RU"},
	}
	if err := st.Insert(ctx, ev); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, tmpl: uiTmpl(t)}

	// Index lists the fingerprint and links to its detail.
	rr := httptest.NewRecorder()
	s.handleFingerprints(rr, httptest.NewRequest("GET", "/fingerprints", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `href="/fingerprints/ja3/abc123"`) {
		t.Fatalf("index: code=%d body=%q", rr.Code, rr.Body.String())
	}

	// Detail renders the reputation dossier.
	rr = httptest.NewRecorder()
	s.handleFingerprint(rr, httptest.NewRequest("GET", "/fingerprints/ja3/abc123", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "fleet correlation") {
		t.Fatalf("detail: code=%d body=%q", rr.Code, rr.Body.String())
	}

	// Unknown kind → 404 (and the bad kind never reaches SQL).
	rr = httptest.NewRecorder()
	s.handleFingerprint(rr, httptest.NewRequest("GET", "/fingerprints/evil/abc123", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("unknown kind: code=%d; want 404", rr.Code)
	}

	// Known kind, absent value → 404.
	rr = httptest.NewRecorder()
	s.handleFingerprint(rr, httptest.NewRequest("GET", "/fingerprints/ja3/does-not-exist", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing value: code=%d; want 404", rr.Code)
	}
}

func TestFingerprintsEmptyPlaceholder(t *testing.T) {
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "fingerprints", fingerprintsPage{Window: "30d"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No fingerprints recorded yet") {
		t.Errorf("empty index should show placeholder")
	}
}
