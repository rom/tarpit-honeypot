package format

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

func mkEvent() *event.Event {
	return &event.Event{
		ID:       "test-id-1234",
		Time:     time.Date(2026, 5, 19, 18, 30, 45, 0, time.UTC),
		Sensor:   "sensor-1",
		RuleID:   "listener:ssh-bait",
		Severity: event.SeverityHigh,
		Source:   event.Endpoint{IP: "203.0.113.42", Port: 51234},
		Dest:     event.Endpoint{IP: "10.0.0.1", Port: 22},
		Proto:    "tcp",
		Handler:  "ssh",
		Meta: map[string]any{
			"client_id":         "SSH-2.0-BadClient",
			"honeynet":          "corp-lan",
			"honeynet_hostname": "web-prod-01",
			"asn":               13335,
			"hassh":             "abc123def456",
		},
	}
}

func TestGetUnknownErrors(t *testing.T) {
	if _, err := Get("nope"); err == nil {
		t.Error("Get(nope) should error")
	}
}

func TestJSONIsDefault(t *testing.T) {
	f, _ := Get("")
	if f.Name() != "json" {
		t.Errorf("empty format should default to json; got %s", f.Name())
	}
	b, err := f.Format(mkEvent())
	if err != nil {
		t.Fatal(err)
	}
	var back event.Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Errorf("JSON output should be valid JSON: %v", err)
	}
}

func TestCEFShape(t *testing.T) {
	f, _ := Get("cef")
	b, _ := f.Format(mkEvent())
	s := string(b)
	if !strings.HasPrefix(s, "CEF:0|tarpit-honeypot|tarpit|1.4|listener:ssh-bait|") {
		t.Errorf("CEF prefix wrong: %s", s)
	}
	// Severity 7 (high)
	if !strings.Contains(s, "|7|") {
		t.Errorf("CEF severity column should be 7 for high: %s", s)
	}
	// Extension fields
	for _, k := range []string{"src=203.0.113.42", "spt=51234", "dst=10.0.0.1", "dpt=22", "proto=TCP", "app=ssh"} {
		if !strings.Contains(s, k) {
			t.Errorf("CEF missing key %q: %s", k, s)
		}
	}
}

func TestCEFEscapesPipeInHeaders(t *testing.T) {
	f, _ := Get("cef")
	ev := mkEvent()
	ev.RuleID = "listener:weird|name"
	b, _ := f.Format(ev)
	s := string(b)
	if !strings.Contains(s, `listener:weird\|name|`) {
		t.Errorf("pipe in rule id should be escaped: %s", s)
	}
}

func TestLEEFShape(t *testing.T) {
	f, _ := Get("leef")
	b, _ := f.Format(mkEvent())
	s := string(b)
	if !strings.HasPrefix(s, "LEEF:2.0|tarpit-honeypot|tarpit|1.4|listener:ssh-bait|") {
		t.Errorf("LEEF prefix wrong: %s", s)
	}
	// Tab-separated extension
	if !strings.Contains(s, "\tsrc=203.0.113.42\t") {
		t.Errorf("LEEF should use tab delimiter: %q", s)
	}
	if !strings.Contains(s, "sev=high") {
		t.Errorf("LEEF should carry severity as sev=: %s", s)
	}
}

func TestOCSFShape(t *testing.T) {
	f, _ := Get("ocsf")
	b, _ := f.Format(mkEvent())
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("OCSF should be valid JSON: %v", err)
	}
	// Required OCSF fields
	for _, k := range []string{"class_uid", "category_uid", "activity_id", "severity_id", "time", "metadata"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("OCSF missing required field %q", k)
		}
	}
	if doc["class_uid"].(float64) != 4001 {
		t.Errorf("class_uid should be 4001 (Network Activity); got %v", doc["class_uid"])
	}
	// Endpoints
	src, ok := doc["src_endpoint"].(map[string]any)
	if !ok || src["ip"] != "203.0.113.42" {
		t.Errorf("src_endpoint.ip wrong: %v", src)
	}
}

func TestDeterministicOutput(t *testing.T) {
	for _, name := range []string{"json", "cef", "leef", "ocsf"} {
		f, _ := Get(name)
		ev := mkEvent()
		b1, _ := f.Format(ev)
		b2, _ := f.Format(ev)
		if string(b1) != string(b2) {
			t.Errorf("%s output not deterministic:\n  %s\n  %s", name, b1, b2)
		}
	}
}
