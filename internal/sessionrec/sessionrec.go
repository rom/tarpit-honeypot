// Package sessionrec records interactive attacker sessions (telnet /
// ssh_interactive shells) as asciinema v2 cast files, so an operator can
// replay exactly what an attacker typed and what the sensor sent, with
// timing. Recording is opt-in (sensor.session_recording) and bounded by a
// per-cast byte cap and an oldest-first total-size cap on the directory.
//
// The cast format is the asciinema v2 newline-delimited JSON: a header
// object followed by [time, "o"|"i", data] event lines ("o" = output the
// sensor sent, "i" = input the attacker typed).
package sessionrec

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store creates + caps session recordings under a directory.
type Store struct {
	dir      string
	perCast  int   // per-recording byte cap
	maxTotal int64 // directory cap
	mu       sync.Mutex
	seq      uint64
}

// NewStore returns a recorder store rooted at dir. perCast<=0 defaults to
// 1 MiB; maxTotalMB<=0 to 256 MB.
func NewStore(dir string, perCastBytes, maxTotalMB int) (*Store, error) {
	if perCastBytes <= 0 {
		perCastBytes = 1 << 20
	}
	if maxTotalMB <= 0 {
		maxTotalMB = 256
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Store{dir: dir, perCast: perCastBytes, maxTotal: int64(maxTotalMB) << 20}, nil
}

// Begin starts a recording for a connection from srcIP. Returns the
// Recorder and the cast's base filename (for the event meta). The caller
// must Close the Recorder when the session ends.
func (s *Store) Begin(srcIP string) (*Recorder, string, error) {
	s.mu.Lock()
	s.seq++
	name := time.Now().UTC().Format("20060102T150405") + "-" + sanitize(srcIP) + "-" + itoa(s.seq) + ".cast"
	s.mu.Unlock()
	path := filepath.Join(s.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, "", err
	}
	hdr, _ := json.Marshal(map[string]any{
		"version": 2, "width": 80, "height": 24,
		"timestamp": time.Now().Unix(),
		"env":       map[string]string{"TERM": "xterm-256color", "SHELL": "/bin/sh"},
	})
	_, _ = f.Write(append(hdr, '\n'))
	return &Recorder{f: f, start: time.Now(), budget: s.perCast, store: s}, name, nil
}

func (s *Store) enforceCap() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		size int64
		mod  int64
	}
	var files []fi
	var total int64
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{filepath.Join(s.dir, e.Name()), info.Size(), info.ModTime().UnixNano()})
		total += info.Size()
	}
	if total <= s.maxTotal {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })
	for _, f := range files {
		if total <= s.maxTotal {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
}

// Recorder writes one cast. Reader/Writer wrap the session's I/O so every
// byte is timestamped; both are safe for concurrent use (SSH read/write
// run on separate goroutines).
type Recorder struct {
	mu     sync.Mutex
	f      *os.File
	start  time.Time
	budget int
	store  *Store
}

// Reader wraps src so bytes read from it (attacker input) are recorded.
func (r *Recorder) Reader(src io.Reader) io.Reader { return &teeReader{r: r, src: src} }

// Writer wraps dst so bytes written to it (sensor output) are recorded.
func (r *Recorder) Writer(dst io.Writer) io.Writer { return &teeWriter{r: r, dst: dst} }

func (r *Recorder) event(kind string, b []byte) {
	if len(b) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.budget <= 0 {
		return
	}
	if len(b) > r.budget {
		b = b[:r.budget]
	}
	r.budget -= len(b)
	line, err := json.Marshal([]any{time.Since(r.start).Seconds(), kind, string(b)})
	if err != nil {
		return
	}
	_, _ = r.f.Write(append(line, '\n'))
}

// Close finalizes the cast and enforces the directory size cap.
func (r *Recorder) Close() error {
	r.mu.Lock()
	err := r.f.Close()
	r.mu.Unlock()
	if r.store != nil {
		r.store.mu.Lock()
		r.store.enforceCap()
		r.store.mu.Unlock()
	}
	return err
}

type teeReader struct {
	r   *Recorder
	src io.Reader
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.src.Read(p)
	if n > 0 {
		t.r.event("i", p[:n])
	}
	return n, err
}

type teeWriter struct {
	r   *Recorder
	dst io.Writer
}

func (t *teeWriter) Write(p []byte) (int, error) {
	n, err := t.dst.Write(p)
	if n > 0 {
		t.r.event("o", p[:n])
	}
	return n, err
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
