// Package capture records bidirectional bytes on TCP honeypot connections
// and writes them as both a structured session log (JSONL) and a synthesized
// pcap file Wireshark can load. We do NOT use raw sockets — every byte is
// captured from inside the application-layer goroutine via a tee'd net.Conn.
// That keeps us CGO-free and avoids needing CAP_NET_RAW, at the cost of
// synthesized TCP/IP headers in the pcap (no retransmits, no SYN/ACK shape).
package capture

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// pcapFileName builds the on-disk name "<eventID>_<srcIP>_<dstPort>.pcap" so an
// operator can see who a capture is of and which port they hit straight from
// the filename. The eventID stays the leading token (hex, no '_') so the
// /pcap/<eventID> route can still locate the file by prefix; the source IP is
// filesystem-sanitized — IPv4 keeps its dots, an IPv6 ':' becomes '-' (the UI
// reverses it).
func pcapFileName(eventID string, src, dst net.Addr) string {
	sip, _ := splitAddr(src)
	_, dport := splitAddr(dst)
	return fmt.Sprintf("%s_%s_%d.pcap", eventID, sanitizeIPForFile(sip), dport)
}

func sanitizeIPForFile(ip net.IP) string {
	s := ip.String()
	if s == "" || s == "<nil>" {
		return "0.0.0.0"
	}
	if ip.To4() == nil { // IPv6 ':' isn't a friendly filename char everywhere
		s = strings.ReplaceAll(s, ":", "-")
	}
	return s
}

// Direction marks which side wrote the bytes.
type Direction string

const (
	DirIn  Direction = "in"  // bytes from client to honeypot
	DirOut Direction = "out" // bytes from honeypot to client
)

// Manager owns the captures directory, the per-session byte caps, and the
// total directory size cap. One Manager per sensor.
type Manager struct {
	dir             string
	perSessionBytes int
	totalBytes      int64

	mu       sync.Mutex
	totalNow int64
}

// NewManager creates the directory if needed and returns a usable manager.
// perSessionKB caps the bytes written per pcap; totalMB caps the total
// directory size with oldest-first rotation when exceeded.
func NewManager(dataDir string, perSessionKB, totalMB int) (*Manager, error) {
	dir := filepath.Join(dataDir, "captures")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("capture: mkdir %s: %w", dir, err)
	}
	if perSessionKB <= 0 {
		perSessionKB = 64
	}
	if totalMB <= 0 {
		totalMB = 1024
	}
	m := &Manager{
		dir:             dir,
		perSessionBytes: perSessionKB * 1024,
		totalBytes:      int64(totalMB) * 1024 * 1024,
	}
	// Seed totalNow so prune works without a costly Walk at first Insert.
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			m.totalNow += info.Size()
		}
		return nil
	})
	return m, nil
}

// Dir is exposed so the event metadata can record where the capture lives.
func (m *Manager) Dir() string { return m.dir }

// Begin starts a new capture session keyed by eventID. The caller wraps
// its net.Conn with the returned conn — Read/Write are recorded.
func (m *Manager) Begin(eventID string, src, dst net.Addr) *Session {
	return &Session{
		mgr:     m,
		eventID: eventID,
		src:     src,
		dst:     dst,
		started: time.Now().UTC(),
	}
}

// Session collects records for one TCP connection in-memory until End,
// when it flushes a pcap to disk. We buffer rather than streaming so a
// short connection doesn't open and close an fd per session.
type Session struct {
	mgr     *Manager
	eventID string
	src     net.Addr
	dst     net.Addr
	started time.Time

	mu        sync.Mutex
	records   []record
	written   int
	truncated bool
}

type record struct {
	when time.Time
	dir  Direction
	data []byte
}

func (s *Session) recordBytes(dir Direction, p []byte) {
	if s == nil || len(p) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.written >= s.mgr.perSessionBytes {
		s.truncated = true
		return
	}
	remaining := s.mgr.perSessionBytes - s.written
	cp := p
	if len(cp) > remaining {
		cp = cp[:remaining]
		s.truncated = true
	}
	buf := make([]byte, len(cp))
	copy(buf, cp)
	s.records = append(s.records, record{time.Now().UTC(), dir, buf})
	s.written += len(buf)
}

// End writes the pcap to disk and prunes the directory if needed.
// Returns the path of the written pcap and whether the data was truncated
// (so the caller can stamp the event meta).
func (s *Session) End() (path string, truncated bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) == 0 {
		return "", false, nil
	}
	path = filepath.Join(s.mgr.dir, pcapFileName(s.eventID, s.src, s.dst))
	if err := writePcap(path, s); err != nil {
		return "", s.truncated, err
	}
	info, statErr := os.Stat(path)
	if statErr == nil {
		atomic.AddInt64(&s.mgr.totalNow, info.Size())
		s.mgr.prune()
	}
	return path, s.truncated, nil
}

// prune deletes oldest pcaps until totalNow drops under totalBytes.
// Serialized with m.mu so two sessions ending concurrently don't race on
// the directory scan + removals (which could over-delete or double-count
// the size estimate).
func (m *Manager) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if atomic.LoadInt64(&m.totalNow) <= m.totalBytes {
		return
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		size int64
		mod  time.Time
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{filepath.Join(m.dir, e.Name()), info.Size(), info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for _, f := range files {
		if atomic.LoadInt64(&m.totalNow) <= m.totalBytes {
			return
		}
		if err := os.Remove(f.path); err == nil {
			atomic.AddInt64(&m.totalNow, -f.size)
		}
	}
}
