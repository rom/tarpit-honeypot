package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestClassifyInteraction(t *testing.T) {
	cases := []struct {
		name string
		ev   *event.Event
		want string
	}{
		{"creds", &event.Event{Meta: map[string]any{"auth_user": "root", "auth_pass": "x"}}, "Authentication / credential attempt"},
		{"login-intent", &event.Event{Meta: map[string]any{"intent": "Telnet login — credential brute force"}}, "Authentication / credential attempt"},
		{"control", &event.Event{Meta: map[string]any{"intent": "Modbus write single coil — actuating an output"}}, "Command / control action"},
		{"discovery", &event.Event{Meta: map[string]any{"intent": "EtherNet/IP ListIdentity — device discovery"}}, "Service discovery / enumeration"},
		{"session", &event.Event{Anomalies: []string{"ics-iccp-association"}, Meta: map[string]any{"intent": "ICCP/TASE.2 association established"}}, "Session establishment"},
		{"probe", &event.Event{BannerSent: "220 ready"}, "Probe / banner grab"},
		{"empty", &event.Event{}, ""},
	}
	for _, c := range cases {
		if got := classifyInteraction(c.ev); got != c.want {
			t.Errorf("%s: classifyInteraction = %q, want %q", c.name, got, c.want)
		}
	}
}

// The pcap 404 fix: an event whose capture file is named off a different
// connection id (so the <id>_*.pcap glob misses it) must still resolve + serve
// via its capture_path; an event with no capture must 404, not link to nothing.
func TestPcapResolveAndServe(t *testing.T) {
	dir := t.TempDir()
	capDir := filepath.Join(dir, "captures")
	if err := os.MkdirAll(capDir, 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := &Server{store: st, dataDir: dir}
	ctx := t.Context()

	pcapName := "deadbeef_10_0_0_9_22.pcap" // does NOT start with the event id
	if err := os.WriteFile(filepath.Join(capDir, pcapName), []byte("PCAP1"), 0o600); err != nil {
		t.Fatal(err)
	}
	evCap := &event.Event{
		ID: "aaaa", Time: time.Now(), RuleID: "r", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "10.0.0.9"}, Dest: event.Endpoint{IP: "192.0.2.5", Port: 22},
		Meta: map[string]any{"capture_path": "/var/lib/tarpit-honeypot/captures/" + pcapName},
	}
	evNone := &event.Event{
		ID: "bbbb", Time: time.Now(), RuleID: "r", Severity: event.SeverityLow,
		Source: event.Endpoint{IP: "10.0.0.9"}, Dest: event.Endpoint{IP: "192.0.2.5", Port: 23},
	}
	for _, e := range []*event.Event{evCap, evNone} {
		if err := st.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	if _, name, ok := s.resolveEventPcap(evCap); !ok || name != pcapName {
		t.Errorf("resolveEventPcap(cap) = %q,%v; want %s,true", name, ok, pcapName)
	}
	if _, _, ok := s.resolveEventPcap(evNone); ok {
		t.Errorf("resolveEventPcap(none) = true; want false")
	}

	// handlePcap serves the capture_path file (the old code 404'd here).
	w := httptest.NewRecorder()
	s.handlePcap(w, httptest.NewRequest("GET", "/pcap/aaaa", nil))
	if w.Code != 200 || w.Body.String() != "PCAP1" {
		t.Errorf("handlePcap cap = %d %q; want 200 PCAP1", w.Code, w.Body.String())
	}
	// No capture → 404.
	w = httptest.NewRecorder()
	s.handlePcap(w, httptest.NewRequest("GET", "/pcap/bbbb", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("handlePcap none = %d; want 404", w.Code)
	}
}

// End-to-end render of the event detail page: interpretation section, prev/next
// conversation nav, and the pcap link shown only when a capture exists.
func TestRenderEventDetailSections(t *testing.T) {
	dir := t.TempDir()
	capDir := filepath.Join(dir, "captures")
	if err := os.MkdirAll(capDir, 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := t.Context()
	base := time.Now().Add(-time.Hour)

	pcapName := "e1_10_0_0_9_502.pcap"
	if err := os.WriteFile(filepath.Join(capDir, pcapName), []byte("PCAP"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Two events between the same peers, so the conversation nav appears.
	e1 := &event.Event{
		ID: "e1", Time: base.Add(time.Minute), Sensor: "t", RuleID: "modbus:write",
		Severity: event.SeverityCritical, Source: event.Endpoint{IP: "10.0.0.9", Port: 5000},
		Dest: event.Endpoint{IP: "192.0.2.5", Port: 502}, Proto: "tcp", Handler: "modbus",
		BannerSent: "modbus-response", Anomalies: []string{"ics-modbus-write"},
		Meta: map[string]any{"intent": "Modbus write single coil — actuating an output", "capture_path": "/x/captures/" + pcapName},
	}
	e2 := &event.Event{
		ID: "e2", Time: base.Add(2 * time.Minute), Sensor: "t", RuleID: "modbus:read",
		Severity: event.SeverityHigh, Source: event.Endpoint{IP: "10.0.0.9", Port: 5001},
		Dest: event.Endpoint{IP: "192.0.2.5", Port: 502}, Proto: "tcp", Handler: "modbus",
	}
	for _, e := range []*event.Event{e1, e2} {
		if err := st.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{store: st, dataDir: dir, tmpl: uiTmpl(t)}

	// e1: capture + intent + anomaly + a next sibling (e2).
	w := httptest.NewRecorder()
	s.handleEvent(w, httptest.NewRequest("GET", "/events/e1", nil))
	if w.Code != 200 {
		t.Fatalf("e1 status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"interpretation", "Command / control action",
		"Modbus write single coil", "ics-modbus-write",
		"decoy response sent", "/pcap/e1", pcapName,
		"/events/e2", "exchange 1 of 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("e1 detail missing %q", want)
		}
	}

	// e2: no capture → no pcap link; a previous link back to e1.
	w = httptest.NewRecorder()
	s.handleEvent(w, httptest.NewRequest("GET", "/events/e2", nil))
	body = w.Body.String()
	if strings.Contains(body, "/pcap/e2") {
		t.Errorf("e2 should not show a pcap link (no capture)")
	}
	if !strings.Contains(body, "/events/e1") {
		t.Errorf("e2 missing previous link to e1")
	}
}
