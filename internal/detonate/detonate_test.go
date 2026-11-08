package detonate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

const testHash = "aa00bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899"

// collect waits for one emitted event (or fails).
func waitEvent(t *testing.T, ch <-chan *event.Event) *event.Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no detonation event emitted")
		return nil
	}
}

func TestVirusTotalLookupEmitsVerdictAndIOCs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "secret" {
			t.Errorf("missing api key header")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/behaviour_summary"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"dns_lookups":        []map[string]string{{"hostname": "c2.evil.example"}},
				"ip_traffic":         []map[string]string{{"destination_ip": "203.0.113.9"}},
				"http_conversations": []map[string]string{{"url": "http://c2.evil.example/gate.php"}},
			}})
		case strings.Contains(r.URL.Path, "/files/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"attributes": map[string]any{
				"last_analysis_stats": map[string]int{"malicious": 42, "undetected": 18},
				"type_tags":           []string{"elf", "executable"},
				"popular_threat_classification": map[string]any{
					"suggested_threat_label": "trojan.mirai/gafgyt",
					"popular_threat_name":    []map[string]string{{"value": "mirai"}},
				},
			}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("TEST_VT_KEY", "secret")

	ch := make(chan *event.Event, 1)
	d, err := New(Config{
		Enabled: true, VTBaseURL: srv.URL, VTAPIKeyEnv: "TEST_VT_KEY",
		Workers: 1, RequestsPerMin: 6000,
	}, func(ev *event.Event) { ch <- ev })
	if err != nil || d == nil {
		t.Fatalf("New: d=%v err=%v", d, err)
	}
	defer d.Close()

	d.Submit(testHash, "", event.Endpoint{IP: "198.51.100.5"}, "tcp")
	ev := waitEvent(t, ch)

	if ev.RuleID != "malware:detonation" || ev.Severity != event.SeverityCritical {
		t.Errorf("event = %s sev=%v", ev.RuleID, ev.Severity)
	}
	if ev.Meta["malware_family"] != "mirai" {
		t.Errorf("family = %v", ev.Meta["malware_family"])
	}
	if ev.Meta["av_positives"].(int) != 42 || ev.Meta["av_total"].(int) != 60 {
		t.Errorf("av = %v/%v", ev.Meta["av_positives"], ev.Meta["av_total"])
	}
	if got := ev.Meta["contacted_domains"].([]string); len(got) != 1 || got[0] != "c2.evil.example" {
		t.Errorf("contacted_domains = %v", got)
	}
	if got := ev.Meta["contacted_ips"].([]string); len(got) != 1 || got[0] != "203.0.113.9" {
		t.Errorf("contacted_ips = %v", got)
	}
	if got := ev.Meta["contacted_urls"].([]string); len(got) != 1 {
		t.Errorf("contacted_urls = %v", got)
	}
}

func TestVirusTotalUnknownHashNoEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404) // VT has never seen it
	}))
	defer srv.Close()
	t.Setenv("TEST_VT_KEY", "secret")
	ch := make(chan *event.Event, 1)
	d, _ := New(Config{Enabled: true, VTBaseURL: srv.URL, VTAPIKeyEnv: "TEST_VT_KEY", Workers: 1, RequestsPerMin: 6000},
		func(ev *event.Event) { ch <- ev })
	defer d.Close()
	d.Submit(testHash, "", event.Endpoint{IP: "198.51.100.6"}, "tcp")
	select {
	case ev := <-ch:
		t.Errorf("unexpected event for unknown hash: %v", ev.RuleID)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestDedupSuppressesResubmit(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/files/") && !strings.HasSuffix(r.URL.Path, "summary") {
			hits++
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	t.Setenv("TEST_VT_KEY", "secret")
	d, _ := New(Config{Enabled: true, VTBaseURL: srv.URL, VTAPIKeyEnv: "TEST_VT_KEY", Workers: 1, RequestsPerMin: 6000},
		func(*event.Event) {})
	defer d.Close()
	for i := 0; i < 5; i++ {
		d.Submit(testHash, "", event.Endpoint{IP: "198.51.100.7"}, "tcp")
	}
	time.Sleep(300 * time.Millisecond)
	if hits != 1 {
		t.Errorf("VT queried %d times; want 1 (dedup)", hits)
	}
}

func TestCAPEDetonation(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "dropper.bin")
	if err := os.WriteFile(sample, []byte("MZ\x90\x00malware"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/tasks/create/file/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"task_ids": []int{7}}})
		case strings.Contains(r.URL.Path, "/tasks/view/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "reported"}})
		case strings.Contains(r.URL.Path, "/tasks/get/report/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"network": map[string]any{
					"domains": []map[string]string{{"domain": "evil.example"}},
					"hosts":   []string{"198.18.0.9"},
					"http":    []map[string]string{{"host": "evil.example", "uri": "/x"}},
				},
			})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	ch := make(chan *event.Event, 1)
	d, _ := New(Config{
		Enabled: true, SubmitSamples: true, Workers: 1, RequestsPerMin: 6000,
		CAPE: CAPEConfig{URL: srv.URL, PollEvery: 10 * time.Millisecond, MaxWait: 2 * time.Second},
	}, func(ev *event.Event) { ch <- ev })
	defer d.Close()

	d.Submit(testHash, sample, event.Endpoint{IP: "198.51.100.8"}, "tcp")
	ev := waitEvent(t, ch)
	if ev.Meta["detonation_source"] != "cape" {
		t.Errorf("source = %v", ev.Meta["detonation_source"])
	}
	if got := ev.Meta["contacted_domains"].([]string); len(got) != 1 || got[0] != "evil.example" {
		t.Errorf("domains = %v", got)
	}
	if got := ev.Meta["contacted_ips"].([]string); len(got) != 1 || got[0] != "198.18.0.9" {
		t.Errorf("ips = %v", got)
	}
}

func TestDisabledReturnsNil(t *testing.T) {
	d, err := New(Config{Enabled: false}, func(*event.Event) {})
	if d != nil || err != nil {
		t.Errorf("disabled New = %v %v; want nil nil", d, err)
	}
	d.Submit(testHash, "", event.Endpoint{}, "tcp") // nil-safe
	_ = d.Close()                                   // nil-safe
}

func TestValidSHA256(t *testing.T) {
	if !validSHA256(testHash) || validSHA256("short") || validSHA256(strings.Repeat("g", 64)) {
		t.Error("validSHA256 wrong")
	}
}
