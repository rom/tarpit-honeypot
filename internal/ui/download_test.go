package ui

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

func newDownloadServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"captures", "sessions"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(dir, 50)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Server{store: st, dataDir: dir}, dir
}

func TestHandlePcapServesAndRejectsTraversal(t *testing.T) {
	s, dir := newDownloadServer(t)
	id := "abcdef0123"
	if err := os.WriteFile(filepath.Join(dir, "captures", id+".pcap"), []byte("PCAPDATA"), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.handlePcap(rr, httptest.NewRequest("GET", "/pcap/"+id, nil))
	if rr.Code != 200 || rr.Body.String() != "PCAPDATA" {
		t.Fatalf("pcap serve = %d %q", rr.Code, rr.Body.String())
	}
	if cd := rr.Header().Get("Content-Disposition"); cd == "" {
		t.Errorf("missing Content-Disposition")
	}

	// Traversal / non-hex id is rejected.
	rr2 := httptest.NewRecorder()
	s.handlePcap(rr2, httptest.NewRequest("GET", "/pcap/..%2f..%2fetc%2fpasswd", nil))
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("traversal id = %d; want 400", rr2.Code)
	}
}

func TestHandleSessionServesCast(t *testing.T) {
	s, dir := newDownloadServer(t)
	id := "cafebabe01"
	cast := "20240101T000000-1_2_3_4-0.cast"
	if err := os.WriteFile(filepath.Join(dir, "sessions", cast), []byte("CAST"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = s.store.Insert(context.Background(), &event.Event{
		ID: id, RuleID: "listener:x", Source: event.Endpoint{IP: "1.2.3.4"},
		Meta: map[string]any{"session_cast": cast},
	})

	rr := httptest.NewRecorder()
	s.handleSession(rr, httptest.NewRequest("GET", "/session/"+id, nil))
	if rr.Code != 200 || rr.Body.String() != "CAST" {
		t.Fatalf("session serve = %d %q", rr.Code, rr.Body.String())
	}
}

func TestHandleDownloadBundlesZip(t *testing.T) {
	s, dir := newDownloadServer(t)
	id := "0011223344"
	cast := "20240101T000000-9_9_9_9-0.cast"
	_ = os.WriteFile(filepath.Join(dir, "captures", id+".pcap"), []byte("PD"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "sessions", cast), []byte("CD"), 0o600)
	_ = s.store.Insert(context.Background(), &event.Event{
		ID: id, Time: time.Now(), RuleID: "listener:x", Source: event.Endpoint{IP: "9.9.9.9"},
		Meta: map[string]any{"session_cast": cast},
	})

	rr := httptest.NewRecorder()
	s.handleDownload(rr, httptest.NewRequest("GET", "/download?source=9.9.9.9&what=all", nil))
	if rr.Code != 200 {
		t.Fatalf("download = %d", rr.Code)
	}
	zr, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if err != nil {
		t.Fatalf("zip parse: %v", err)
	}
	names := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		names[f.Name] = string(b)
	}
	if names["pcaps/"+id+".pcap"] != "PD" {
		t.Errorf("pcap missing from zip: %v", names)
	}
	if names["sessions/"+cast] != "CD" {
		t.Errorf("session cast missing from zip: %v", names)
	}
}

func TestHexIDAndSafeJoin(t *testing.T) {
	if !hexID("abc123") || hexID("../x") || hexID("a/b") || hexID("") {
		t.Errorf("hexID validation wrong")
	}
	if _, ok := safeJoin("/data/sessions", "../../etc/passwd"); ok {
		t.Errorf("safeJoin allowed traversal")
	}
	if p, ok := safeJoin("/data/sessions", "good.cast"); !ok || p != "/data/sessions/good.cast" {
		t.Errorf("safeJoin good name = %q %v", p, ok)
	}
}
