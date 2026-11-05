package sink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func testEvent() *event.Event {
	return &event.Event{
		ID: "evt-1", Time: time.Unix(1767225600, 0).UTC(), Sensor: "s1",
		RuleID: "cve:CVE-2021-44228", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "203.0.113.9"}, Dest: event.Endpoint{Port: 443},
		Handler: "http",
	}
}

// capture spins an httptest server recording the last request.
func capture(t *testing.T) (*httptest.Server, *capReq) {
	t.Helper()
	cr := &capReq{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cr.path = r.URL.Path
		cr.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		cr.body = string(b)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv, cr
}

type capReq struct{ path, auth, body string }

func TestSlackSink(t *testing.T) {
	srv, cr := capture(t)
	s, err := Build(config.Channel{ID: "sl", Type: "slack", URL: srv.URL}, t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(cr.body), &m); err != nil {
		t.Fatalf("slack body not JSON: %q", cr.body)
	}
	if txt, _ := m["text"].(string); !strings.Contains(txt, "cve:CVE-2021-44228") {
		t.Errorf("slack text missing rule: %v", m["text"])
	}
}

func TestElasticsearchSink(t *testing.T) {
	srv, cr := capture(t)
	t.Setenv("ES_KEY", "secret-api-key")
	s, err := Build(config.Channel{ID: "es", Type: "elasticsearch", URL: srv.URL, Index: "evts", AuthTokenEnv: "ES_KEY"}, t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if cr.path != "/evts/_doc/evt-1" {
		t.Errorf("es path = %q; want /evts/_doc/evt-1", cr.path)
	}
	if cr.auth != "ApiKey secret-api-key" {
		t.Errorf("es auth = %q", cr.auth)
	}
	if !strings.Contains(cr.body, "CVE-2021-44228") {
		t.Errorf("es body missing event: %q", cr.body)
	}
}

func TestSplunkHECSink(t *testing.T) {
	srv, cr := capture(t)
	t.Setenv("HEC", "hec-token")
	s, err := Build(config.Channel{ID: "sp", Type: "splunk_hec", URL: srv.URL, AuthTokenEnv: "HEC"}, t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if cr.path != "/services/collector/event" {
		t.Errorf("splunk path = %q", cr.path)
	}
	if cr.auth != "Splunk hec-token" {
		t.Errorf("splunk auth = %q", cr.auth)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(cr.body), &env); err != nil {
		t.Fatalf("splunk body not JSON: %q", cr.body)
	}
	if env["sourcetype"] != "tarpit:event" || env["event"] == nil {
		t.Errorf("splunk envelope wrong: %v", env)
	}
}

func TestSplunkHECRequiresToken(t *testing.T) {
	if _, err := Build(config.Channel{ID: "sp", Type: "splunk_hec", URL: "https://x/services/collector"}, t.TempDir(), 0); err == nil {
		t.Error("splunk_hec without a token should fail to build")
	}
}
