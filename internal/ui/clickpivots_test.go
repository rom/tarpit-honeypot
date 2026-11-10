package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestEventHasPhase(t *testing.T) {
	ev := evWithMeta(map[string]any{"intent": "Modbus write single coil — actuating an output"})
	if !eventHasPhase(ev, "Command / control action") {
		t.Error("control intent should classify as the control phase")
	}
	if !eventHasPhase(ev, "command / CONTROL action") {
		t.Error("phase match should be case-insensitive")
	}
	if eventHasPhase(ev, "Service discovery / enumeration") {
		t.Error("a different phase must not match")
	}
	if eventHasPhase(evWithMeta(map[string]any{}), "") {
		t.Error("empty phase must not match")
	}
}

func TestEventHasAnomaly(t *testing.T) {
	ev := &event.Event{Anomalies: []string{"ics-field-device-probe"}, Meta: map[string]any{"anomalies": []string{"modbus-write-sweep"}}}
	for _, a := range []string{"ics-field-device-probe", "ICS-FIELD-DEVICE-PROBE", "modbus-write-sweep"} {
		if !eventHasAnomaly(ev, a) {
			t.Errorf("anomaly %q should match", a)
		}
	}
	if eventHasAnomaly(ev, "tls-downgrade") {
		t.Error("absent anomaly must not match")
	}
	if eventHasAnomaly(ev, "") {
		t.Error("empty anomaly must not match")
	}
}

func TestEventHasOTPivots(t *testing.T) {
	ev := &event.Event{Handler: "fins", Meta: map[string]any{"command": "MEMORY AREA READ"}}
	if !eventHasOTProto(ev, "OMRON FINS") || !eventHasOTProto(ev, "omron fins") {
		t.Error("OT proto pivot should match the decoded protocol (case-insensitively)")
	}
	if !eventHasOTCommand(ev, "MEMORY AREA READ") {
		t.Error("OT command pivot should match the decoded command")
	}
	if eventHasOTProto(ev, "Modbus") || eventHasOTCommand(ev, "Write") {
		t.Error("a different proto/command must not match")
	}
	// A non-OT event yields neither.
	ssh := &event.Event{Handler: "ssh", Meta: map[string]any{"client_id": "x"}}
	if eventHasOTProto(ssh, "OMRON FINS") || eventHasOTCommand(ssh, "x") {
		t.Error("non-OT event must not match an OT pivot")
	}
}

// TestDetailLabelsClickable: the interaction phase, OT command/protocol, protocol
// anomalies and ATT&CK tactics render as /events pivot links, and the query
// values round-trip through URL escaping (so spaces and slashes survive).
func TestDetailLabelsClickable(t *testing.T) {
	ev := &event.Event{
		ID: "e1", Time: time.Now(), RuleID: "listener:fins", Severity: event.SeverityHigh,
		Handler: "fins", Source: event.Endpoint{IP: "1.2.3.4"},
		Anomalies:       []string{"ics-field-device-probe"},
		MitreTechniques: []string{"T0855"},
		MitreTactics:    []string{"impact"},
		Meta: map[string]any{
			"command": "MEMORY AREA READ",
			"intent":  "OMRON FINS — enumerating the RTU process image",
		},
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "event", newEventDetail(ev)); err != nil {
		t.Fatal(err)
	}
	html := b.String()

	for _, want := range []string{
		`href="/events?phase=`, `href="/events?otproto=`, `href="/events?otcmd=`,
		`href="/events?anomaly=ics-field-device-probe"`, `href="/events?tactic=impact"`,
		`href="/events?intent=`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("detail page missing clickable link %q", want)
		}
	}

	// The phase value has spaces + a slash; verify it round-trips through the
	// rendered href rather than breaking the attribute or losing characters.
	re := regexp.MustCompile(`href="(/events\?phase=[^"]*)"`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatal("no phase link found")
	}
	u, err := url.Parse(m[1])
	if err != nil {
		t.Fatalf("phase href does not parse: %v", err)
	}
	if got := u.Query().Get("phase"); got != "Service discovery / enumeration" {
		t.Errorf("phase query round-trip = %q; want %q", got, "Service discovery / enumeration")
	}
}

// TestEventsOTAndAnomalyPivots: the /events page honors the new otproto / otcmd /
// anomaly pivots end-to-end, returning only the matching events.
func TestEventsOTAndAnomalyPivots(t *testing.T) {
	s := fleetTestServer(t)
	ctx := context.Background()
	ins := func(id, handler, ip string, meta map[string]any, anoms []string) {
		ev := &event.Event{
			ID: id, Time: time.Now().UTC(), RuleID: "listener:" + handler,
			Severity: event.SeverityHigh, Handler: handler,
			Source: event.Endpoint{IP: ip}, Anomalies: anoms, Meta: meta,
		}
		if err := s.store.Insert(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	ins("fins1", "fins", "203.0.113.10", map[string]any{"command": "MEMORY AREA READ"}, []string{"ics-field-device-probe"})
	ins("mb1", "modbus", "203.0.113.11", map[string]any{"function_name": "Read Holding Registers"}, nil)
	ins("ssh1", "ssh", "203.0.113.12", map[string]any{"client_id": "libssh"}, nil)

	get := func(q string) string {
		w := httptest.NewRecorder()
		s.handleEvents(w, httptest.NewRequest(http.MethodGet, q, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", q, w.Code)
		}
		return w.Body.String()
	}

	b := get("/events?otproto=" + url.QueryEscape("OMRON FINS"))
	if !strings.Contains(b, "203.0.113.10") {
		t.Error("FINS event missing under otproto=OMRON FINS")
	}
	if strings.Contains(b, "203.0.113.11") || strings.Contains(b, "203.0.113.12") {
		t.Error("non-FINS events leaked into otproto=OMRON FINS")
	}

	b = get("/events?anomaly=ics-field-device-probe")
	if !strings.Contains(b, "203.0.113.10") || strings.Contains(b, "203.0.113.11") {
		t.Error("anomaly pivot did not isolate the matching event")
	}

	b = get("/events?otcmd=" + url.QueryEscape("Read Holding Registers"))
	if !strings.Contains(b, "203.0.113.11") || strings.Contains(b, "203.0.113.12") {
		t.Error("otcmd pivot did not isolate the modbus event")
	}
}
