package ui

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func TestBuildCapturesView(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"captures", "sessions", "payloads"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	_ = os.WriteFile(filepath.Join(dir, "captures", "abc123.pcap"), []byte("pcap"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "sessions", "s1.cast"), []byte("cast"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "payloads", "deadbeef.elf"), []byte("MZ"), 0o644)

	now := time.Now()
	evs := []*event.Event{
		{Time: now, Source: event.Endpoint{IP: "1.2.3.4"}, Handler: "ssh",
			Meta: map[string]any{"username": "root", "password": "toor"}},
	}
	v := buildCapturesView(dir, now.Add(-time.Hour), evs, "", "")
	if !v.Enabled {
		t.Fatal("expected Enabled with a data dir")
	}
	if len(v.Artifacts) != 1 || v.Artifacts[0].Name != "deadbeef.elf" {
		t.Errorf("artifacts wrong: %+v", v.Artifacts)
	}
	if len(v.Pcaps) != 1 || len(v.Sessions) != 1 {
		t.Errorf("pcaps/sessions wrong: %+v / %+v", v.Pcaps, v.Sessions)
	}
	if len(v.Creds) != 1 || v.Creds[0].User != "root" || v.Creds[0].Service != "ssh" {
		t.Errorf("creds wrong: %+v", v.Creds)
	}
}

func TestHandleLootServesAndGuards(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "payloads"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "payloads", "deadbeef.elf"), []byte("MALWARE"), 0o644)

	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetDataDir(dir)

	// Valid download.
	w := httptest.NewRecorder()
	srv.handleLoot(w, httptest.NewRequest("GET", "/loot/?kind=payload&name=deadbeef.elf", nil))
	if w.Code != 200 || w.Body.String() != "MALWARE" {
		t.Errorf("valid loot: code=%d body=%q", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Error("expected attachment Content-Disposition")
	}

	// Bad kind + traversal must be refused.
	for _, q := range []string{"/loot/?kind=etc&name=passwd", "/loot/?kind=payload&name=../config.yaml", "/loot/?kind=payload&name=a/b"} {
		w := httptest.NewRecorder()
		srv.handleLoot(w, httptest.NewRequest("GET", q, nil))
		if w.Code == 200 {
			t.Errorf("expected rejection for %q, got 200", q)
		}
	}
}

func TestHandleCapturesRenders(t *testing.T) {
	st, err := store.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.Insert(context.Background(), &event.Event{
		ID: "1", Time: time.Now(), Sensor: "s", RuleID: "listener:ssh", Severity: event.SeverityHigh,
		Source: event.Endpoint{IP: "1.2.3.4"}, Handler: "ssh",
		Meta: map[string]any{"user_attempt": "root", "pass_attempt": "toor"},
	})
	srv, err := New(config.UI{Enabled: true, Bind: "127.0.0.1:0"}, st)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetDataDir(t.TempDir())
	w := httptest.NewRecorder()
	srv.handleCaptures(w, httptest.NewRequest("GET", "/captures", nil))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("captures: code=%d", w.Code)
	}
	for _, want := range []string{"captures &amp; loot", "captured credentials", "session recordings"} {
		if !strings.Contains(body, want) {
			t.Errorf("captures page missing %q", want)
		}
	}
}

// TestCapturesArtifactVerdict: a malware:detonation event for a captured
// sample's sha256 surfaces as the artifact's family / AV ratio / IOC count.
func TestCapturesArtifactVerdict(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "payloads"), 0o755)
	const h = "aa00bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899"
	_ = os.WriteFile(filepath.Join(dir, "payloads", h+".elf"), []byte("MZ"), 0o644)

	now := time.Now()
	evs := []*event.Event{
		{ID: "evt123", Time: now, RuleID: "malware:detonation", Source: event.Endpoint{IP: "1.2.3.4"},
			Meta: map[string]any{
				"file_sha256":       h,
				"malware_family":    "mirai",
				"av_positives":      42,
				"av_total":          60,
				"detonation_source": "virustotal",
				"contacted_domains": []string{"c2.evil.example"},
				"contacted_ips":     []string{"203.0.113.9"},
			}},
	}
	v := buildCapturesView(dir, now.Add(-time.Hour), evs, "", "")
	if len(v.Artifacts) != 1 {
		t.Fatalf("artifacts = %+v", v.Artifacts)
	}
	a := v.Artifacts[0]
	if !a.Verdict || a.MalFamily != "mirai" || a.AVHits != 42 || a.AVTotal != 60 || a.DetSource != "virustotal" {
		t.Errorf("verdict not joined: %+v", a)
	}
	if a.IOCCount != 2 {
		t.Errorf("IOCCount = %d; want 2", a.IOCCount)
	}
	if a.VerdictEvent != "evt123" {
		t.Errorf("VerdictEvent = %q; want evt123 (for click-through)", a.VerdictEvent)
	}
	// Sanity: artifactSHA256 strips the extension.
	if got := artifactSHA256(h + ".elf"); got != h {
		t.Errorf("artifactSHA256 = %q", got)
	}
}

// TestScanCapRaisedByTuning: the per-page scan cap is the page default unless
// ui_scan_limit raises it (so operators can render more history per page).
func TestScanCapRaisedByTuning(t *testing.T) {
	s := &Server{scanLimit: 20000}
	if got := s.scanCap(20000); got != 20000 {
		t.Errorf("default scanCap = %d; want 20000", got)
	}
	if got := s.scanCap(50000); got != 50000 {
		t.Errorf("higher page default should win: got %d; want 50000", got)
	}
	s.scanLimit = 200000
	if got := s.scanCap(20000); got != 200000 {
		t.Errorf("raised ui_scan_limit should win: got %d; want 200000", got)
	}
}
