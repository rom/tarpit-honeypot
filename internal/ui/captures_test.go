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
	v := buildCapturesView(dir, now.Add(-time.Hour), evs)
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
