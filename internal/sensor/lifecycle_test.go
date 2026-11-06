package sensor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// freePort returns a currently-free localhost TCP port. The brief close/reuse
// window is the standard test idiom and is reliable in practice.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func loadCfgYAML(t *testing.T, dir, body string) *config.Config {
	t.Helper()
	p := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load cfg: %v", err)
	}
	return cfg
}

// End-to-end lifecycle: New → Run → a real client connection produces an event
// → graceful shutdown on context cancel. Exercises Run, startListener, the
// accept loop, the bus loop, dispatch, the op-event emit, metrics and the
// accessors in one pass.
func TestSensorRunServesConnectionAndShutsDown(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	body := fmt.Sprintf(`
sensor:
  data_dir: %s
listeners:
  - { id: web, proto: tcp, bind: 127.0.0.1:%d, mode: banner, handler: http, severity: medium }
channels:
  - { id: db, type: sqlite }
  - { id: out, type: stdout, min_severity: low }
correlate:
  port_scan: { enabled: true, distinct_ports: 3, window: 30s, severity: high }
`, dir, port)
	s, err := New(loadCfgYAML(t, dir, body))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if s.Name() == "" {
		t.Error("Name() empty")
	}
	if s.Store() == nil {
		t.Error("Store() nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Wait for the listener to accept.
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var conn net.Conn
	for i := 0; i < 100; i++ {
		if conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		cancel()
		<-done
		t.Fatalf("listener never came up on %s: %v", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("GET /admin HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n"))
	_, _ = conn.Read(make([]byte, 512))
	_ = conn.Close()

	// The connection must have produced at least one dispatched event.
	var total uint64
	for i := 0; i < 100; i++ {
		if total, _, _ = s.EventCounts(); total > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if total == 0 {
		cancel()
		<-done
		t.Fatal("no events dispatched after a client connection")
	}

	if s.ListenerCount() < 1 {
		t.Errorf("ListenerCount = %d; want >= 1", s.ListenerCount())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of context cancel")
	}
}

// A richer run: devices + risk + periodic digest + first-seen enabled, a couple
// of client connections, a config reload, and every accessor called. Exercises
// the fuller Run wiring, runDigest, ReloadEnrichment, scoreRisk's live path and
// the stats accessors.
func TestSensorRichLifecycleAndAccessors(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	body := fmt.Sprintf(`
sensor:
  data_dir: %s
  alerts: { first_seen: true, digest_interval: 1s }
  forward:
    - { id: agg, url: "http://127.0.0.1:9/ingest", min_severity: low }
listeners:
  - { id: web, proto: tcp, bind: 127.0.0.1:%d, mode: banner, handler: http, severity: medium }
channels:
  - { id: db, type: sqlite }
canaries:
  - { id: loot, path: %s/canary.txt, events: [write, remove], severity: critical }
devices:
  enabled: true
  learn: true
  severity: high
risk:
  enabled: true
  half_life: 1h
  elevated: 30
  high: 75
  critical: 150
correlate:
  port_scan: { enabled: true, distinct_ports: 2, window: 30s, severity: high }
enrich:
  net_class: { enabled: true }
`, dir, port, dir)
	_ = os.WriteFile(filepath.Join(dir, "canary.txt"), []byte("bait"), 0o600)
	cfg := loadCfgYAML(t, dir, body)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer cancel() // leak guard for early-return paths

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ok := false
	for i := 0; i < 100; i++ {
		if c, e := net.DialTimeout("tcp", addr, 200*time.Millisecond); e == nil {
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = c.Write([]byte("GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.0\r\n\r\n"))
			_, _ = c.Read(make([]byte, 256))
			_ = c.Close()
			ok = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("listener never came up")
	}

	// Let the 1s digest tick fire and events settle.
	time.Sleep(1300 * time.Millisecond)

	// Every accessor must be callable without panicking.
	_, _, _ = s.EventCounts()
	_ = s.ListenerCount()
	_ = s.HoneyTokensTracked()
	_ = s.IOCWritesDropped()
	_, _, _ = s.KEVStats()
	_ = s.DetectRuleStats()
	_, _ = s.DiskUsedPercent()
	_ = s.Blocker()
	_ = s.Risk()
	_ = s.IntelStore()
	_ = s.Honeynet()
	_, _ = s.SnifferStats()
	if s.Devices() == nil {
		t.Error("Devices() should be non-nil when device learning is enabled")
	}
	if s.Store() == nil {
		t.Error("Store() should be non-nil with a sqlite channel")
	}

	// Clean shutdown. (Reload is covered by reload_race_test.go; calling it here
	// isn't safe either way — concurrent with a live Run it races Run's
	// unlocked startup s.cfg reads, and after shutdown it double-stops the
	// router. ReloadEnrichment, by contrast, is fully stateMu-guarded and
	// touches no router, so it's safe to exercise after the sensor stops.)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of context cancel")
	}

	// SIGHUP-style enrichment DB reload (safe on a stopped sensor).
	if err := s.ReloadEnrichment(); err != nil {
		t.Errorf("ReloadEnrichment: %v", err)
	}
}
