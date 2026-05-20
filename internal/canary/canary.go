// Package canary watches honeyfiles for modify/create/remove/rename/chmod
// events using fsnotify. It does NOT detect plain reads — that requires
// fanotify (Linux 5.x + root) or ETW on Windows and is planned for v0.3.
package canary

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Watcher struct {
	cfg        []config.Canary
	sensorName string
}

// fanotifyTarget is the per-canary view the linux fanotify code needs.
type fanotifyTarget struct {
	id   string
	path string
	sev  event.Severity
}

func New(cfg []config.Canary, sensorName string) *Watcher {
	return &Watcher{cfg: cfg, sensorName: sensorName}
}

func (w *Watcher) fanotifyTargets() []fanotifyTarget {
	out := make([]fanotifyTarget, 0, len(w.cfg))
	for _, c := range w.cfg {
		sev, err := event.ParseSeverity(c.Severity)
		if err != nil {
			continue
		}
		out = append(out, fanotifyTarget{id: c.ID, path: c.Path, sev: sev})
	}
	return out
}

// Run sets up the underlying fsnotify watcher, adds every configured canary
// path, and emits events until ctx is cancelled.
//
// On Linux, we also try to start a fanotify reader so OPEN events (i.e.
// plain reads) are detected. Failure to set up fanotify (no CAP_SYS_ADMIN,
// old kernel, etc.) is logged at warn level and we continue with fsnotify
// only — modify/remove/rename/chmod still work.
func (w *Watcher) Run(ctx context.Context, bus chan<- *event.Event) error {
	if len(w.cfg) == 0 {
		return nil
	}
	if err := startFanotify(ctx, w.fanotifyTargets(), w.sensorName, bus); err != nil {
		slog.Warn("canary: fanotify unavailable; OPEN events won't be detected (fsnotify still active)", "err", err)
	}
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("canary: %w", err)
	}
	defer fw.Close()

	// Map watch-target -> canary id so we can attribute events.
	pathToID := map[string]string{}
	sevByID := map[string]event.Severity{}
	wantedByID := map[string]map[fsnotify.Op]bool{}

	for _, ca := range w.cfg {
		sev, err := event.ParseSeverity(ca.Severity)
		if err != nil {
			return fmt.Errorf("canary %s: %w", ca.ID, err)
		}
		sevByID[ca.ID] = sev

		wantedByID[ca.ID] = map[fsnotify.Op]bool{}
		for _, e := range ca.Events {
			switch e {
			case "write":
				wantedByID[ca.ID][fsnotify.Write] = true
			case "remove":
				wantedByID[ca.ID][fsnotify.Remove] = true
			case "rename":
				wantedByID[ca.ID][fsnotify.Rename] = true
			case "create":
				wantedByID[ca.ID][fsnotify.Create] = true
			case "chmod":
				wantedByID[ca.ID][fsnotify.Chmod] = true
			}
		}

		paths, err := expandWatchTargets(ca)
		if err != nil {
			return err
		}
		for _, p := range paths {
			if err := fw.Add(p); err != nil {
				slog.Warn("canary: failed to add watch", "id", ca.ID, "path", p, "err", err)
				continue
			}
			pathToID[p] = ca.ID
			slog.Info("canary up", "id", ca.ID, "path", p, "events", ca.Events)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case fev, ok := <-fw.Events:
			if !ok {
				return nil
			}
			// Find owning canary by matching the longest prefix.
			id := matchOwner(pathToID, fev.Name)
			if id == "" {
				continue
			}
			if !opMatches(wantedByID[id], fev.Op) {
				continue
			}
			ev := &event.Event{
				ID:       event.NewID(),
				Time:     time.Now().UTC(),
				Sensor:   w.sensorName,
				RuleID:   "canary:" + id,
				Severity: sevByID[id],
				Proto:    "file",
				Meta: map[string]any{
					"path": fev.Name,
					"op":   fev.Op.String(),
				},
			}
			select {
			case bus <- ev:
			case <-ctx.Done():
				return nil
			}
		case err, ok := <-fw.Errors:
			if !ok {
				return nil
			}
			slog.Warn("canary error", "err", err)
		}
	}
}

func expandWatchTargets(ca config.Canary) ([]string, error) {
	st, err := os.Stat(ca.Path)
	if err != nil {
		// fsnotify can still watch the parent dir even if the file doesn't
		// exist yet — that's how we catch "create" events.
		parent := filepath.Dir(ca.Path)
		if _, perr := os.Stat(parent); perr == nil {
			return []string{parent}, nil
		}
		return nil, fmt.Errorf("canary %s: %s does not exist (and neither does parent)", ca.ID, ca.Path)
	}
	if !st.IsDir() {
		// Watch the parent so we still catch rename/remove of the file itself.
		return []string{filepath.Dir(ca.Path), ca.Path}, nil
	}
	if !ca.Recursive {
		return []string{ca.Path}, nil
	}
	var out []string
	err = filepath.Walk(ca.Path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func matchOwner(pathToID map[string]string, p string) string {
	best := ""
	bestLen := -1
	for watched, id := range pathToID {
		if p == watched || strings.HasPrefix(p, watched+string(os.PathSeparator)) {
			if len(watched) > bestLen {
				bestLen = len(watched)
				best = id
			}
		}
	}
	return best
}

func opMatches(wanted map[fsnotify.Op]bool, op fsnotify.Op) bool {
	for k := range wanted {
		if op.Has(k) {
			return true
		}
	}
	return false
}
