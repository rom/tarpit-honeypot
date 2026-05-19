package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// jsonLogSink writes events as JSON-lines to events-YYYYMMDD-NN.jsonl,
// rotating by file size and pruning oldest files when totalCapBytes is exceeded.
type jsonLogSink struct {
	id            string
	dir           string
	totalCapBytes int64
	perFileBytes  int64

	mu      sync.Mutex
	file    *os.File
	written int64
}

func newJSONLog(id, dataDir string, jsonMB int) (*jsonLogSink, error) {
	dir := filepath.Join(dataDir, "events")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("jsonlog: mkdir %s: %w", dir, err)
	}
	cap := int64(jsonMB) * 1024 * 1024
	return &jsonLogSink{
		id:            id,
		dir:           dir,
		totalCapBytes: cap,
		perFileBytes:  cap / 10, // 10 rotation slots
	}, nil
}

func (j *jsonLogSink) ID() string { return j.id }

func (j *jsonLogSink) Send(_ context.Context, ev *event.Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if err := j.ensureFile(); err != nil {
		return err
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := j.file.Write(b)
	if err != nil {
		return err
	}
	j.written += int64(n)

	if j.written >= j.perFileBytes {
		_ = j.file.Close()
		j.file = nil
		j.written = 0
		// Prune asynchronously-ish (cheap; we hold the lock).
		j.pruneLocked()
	}
	return nil
}

func (j *jsonLogSink) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file != nil {
		err := j.file.Close()
		j.file = nil
		return err
	}
	return nil
}

func (j *jsonLogSink) ensureFile() error {
	if j.file != nil {
		return nil
	}
	name := fmt.Sprintf("events-%s-%d.jsonl", time.Now().UTC().Format("20060102"), time.Now().UnixNano())
	path := filepath.Join(j.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	j.file = f
	j.written = 0
	return nil
}

func (j *jsonLogSink) pruneLocked() {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return
	}
	type fi struct {
		name string
		size int64
		mod  time.Time
	}
	var files []fi
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{e.Name(), info.Size(), info.ModTime()})
		total += info.Size()
	}
	if total <= j.totalCapBytes {
		return
	}
	sort.Slice(files, func(i, k int) bool { return files[i].mod.Before(files[k].mod) })
	for _, f := range files {
		if total <= j.totalCapBytes {
			return
		}
		_ = os.Remove(filepath.Join(j.dir, f.name))
		total -= f.size
	}
}
