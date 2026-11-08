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

func TestProtocolFields(t *testing.T) {
	// DNS event: curated fields surface; absent ones are skipped.
	dns := &event.Event{Handler: "dns", Meta: map[string]any{
		"qname": "example.com", "qtype_name": "ANY", "zone_transfer_served": true,
		"read_err": "ignored-scalar", // not in the DNS spec → stays in meta table
	}}
	groups := protocolFields(dns)
	if len(groups) != 1 || groups[0].Title != "DNS query" {
		t.Fatalf("DNS groups = %+v", groups)
	}
	var labels []string
	for _, f := range groups[0].Fields {
		labels = append(labels, f.Label+"="+f.Value)
	}
	joined := strings.Join(labels, "|")
	if !strings.Contains(joined, "query name=example.com") || !strings.Contains(joined, "AXFR zone transfer served=yes") {
		t.Errorf("DNS fields wrong: %s", joined)
	}

	// dns_tcp folds onto the dns spec.
	if g := protocolFields(&event.Event{Handler: "dns_tcp", Meta: map[string]any{"qname": "x"}}); len(g) != 1 {
		t.Errorf("dns_tcp did not normalize to dns spec: %+v", g)
	}
	// ssh_interactive folds onto ssh.
	if g := protocolFields(&event.Event{Handler: "ssh_interactive", Meta: map[string]any{"client_id": "SSH-2.0-libssh"}}); len(g) != 1 || g[0].Title != "SSH handshake & client" {
		t.Errorf("ssh_interactive normalization: %+v", g)
	}
	// A handler with no spec yields nothing (its fields stay in the meta table).
	if g := protocolFields(&event.Event{Handler: "modbus", Meta: map[string]any{"x": "y"}}); g != nil {
		t.Errorf("modbus should have no protocol group: %+v", g)
	}
	// Every surfaced key must be excluded from the generic meta table.
	for _, spec := range protoSpecs {
		for _, f := range spec.fields {
			if !protocolDetailKeys[f.key] {
				t.Errorf("key %q not in protocolDetailKeys exclusion set", f.key)
			}
		}
	}
	if metaScalar(dns.Meta)["qname"] != nil {
		t.Error("qname should be excluded from the generic meta table")
	}
}

// TestProtocolSectionAndColumnMenuRender renders a real DNS event's detail page
// (per-protocol request fields) and the events list (column show/hide menu),
// asserting the new UI surfaces reach the HTML.
func TestProtocolSectionAndColumnMenuRender(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := t.Context()
	ev := &event.Event{
		ID: "d1", Time: time.Now().Add(-time.Minute), Sensor: "t", RuleID: "dns:axfr",
		Severity: event.SeverityHigh, Source: event.Endpoint{IP: "10.0.0.5", Port: 5353},
		Dest: event.Endpoint{IP: "192.0.2.9", Port: 53}, Proto: "udp", Handler: "dns",
		Meta: map[string]any{"qname": "corp.example.com", "qtype_name": "AXFR", "zone_transfer_served": true},
	}
	if err := st.Insert(ctx, ev); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, dataDir: dir, tmpl: uiTmpl(t)}

	// Detail page: the DNS protocol section renders the decoded fields.
	w := httptest.NewRecorder()
	s.handleEvent(w, httptest.NewRequest("GET", "/events/d1", nil))
	if w.Code != 200 {
		t.Fatalf("detail status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"DNS query", "corp.example.com", "query type", "AXFR"} {
		if !strings.Contains(body, want) {
			t.Errorf("DNS detail page missing %q", want)
		}
	}

	// Events list: the column menu + per-column data attributes render.
	w = httptest.NewRecorder()
	s.handleEvents(w, httptest.NewRequest("GET", "/events", nil))
	if w.Code != 200 {
		t.Fatalf("events status %d", w.Code)
	}
	list := w.Body.String()
	for _, want := range []string{"data-col-menu", "data-col-table", `data-col="handler"`, `data-col="intent"`, "columns ▾"} {
		if !strings.Contains(list, want) {
			t.Errorf("events list missing %q", want)
		}
	}
}
