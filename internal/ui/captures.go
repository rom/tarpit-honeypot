package ui

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rom/tarpit-honeypot/internal/event"
	"github.com/rom/tarpit-honeypot/internal/store"
)

// Captures ("loot") tab: a single place to retrieve everything the sensor
// harvested from attackers — captured malware/payload artifacts, per-connection
// pcaps, recorded interactive-shell sessions, and captured credentials. Files
// are listed from the data dir and served (read-only, attachment) by the
// /loot/ route; credentials are read from the event store. Disabled when no
// data_dir is wired.

const capturesWindow = 30 * 24 * time.Hour
const capturesScanMax = 20000
const capturesMaxCreds = 300

type lootFile struct {
	Name  string    // basename (download key)
	Size  int64     // bytes
	MTime time.Time // last-modified
	Kind  string    // pcap | session | payload
}

type capturesView struct {
	Enabled   bool
	Pcaps     []lootFile
	Sessions  []lootFile
	Artifacts []lootFile
	Creds     []credRow
	Since     time.Time
	Scanned   int
}

type credRow struct {
	Time    time.Time
	Source  string
	Service string
	User    string
	Pass    string
}

// lootDir maps the UI "kind" to its subdirectory under data_dir.
var lootDir = map[string]string{
	"pcap":    "captures",
	"session": "sessions",
	"payload": "payloads",
}

// listLoot lists the files under <dataDir>/<sub> as lootFiles, newest first,
// capped. Missing/empty dirs yield an empty slice (not an error).
func listLoot(dataDir, kind string, max int) []lootFile {
	sub := lootDir[kind]
	if sub == "" || dataDir == "" {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, sub))
	if err != nil {
		return nil
	}
	out := make([]lootFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, lootFile{Name: e.Name(), Size: fi.Size(), MTime: fi.ModTime(), Kind: kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MTime.After(out[j].MTime) })
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func buildCapturesView(dataDir string, since time.Time, evs []*event.Event) capturesView {
	v := capturesView{Enabled: dataDir != "", Since: since, Scanned: len(evs)}
	if dataDir != "" {
		v.Pcaps = listLoot(dataDir, "pcap", 500)
		v.Sessions = listLoot(dataDir, "session", 500)
		v.Artifacts = listLoot(dataDir, "payload", 500)
	}
	// Captured credentials from the event store (newest first, deduped).
	seen := map[string]struct{}{}
	for _, ev := range evs {
		for _, c := range extractCreds(ev) {
			if c.User == "" && c.Pass == "" {
				continue
			}
			key := ev.Source.IP + "\x00" + c.User + "\x00" + c.Pass + "\x00" + c.Service
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			v.Creds = append(v.Creds, credRow{
				Time: ev.Time, Source: ev.Source.IP, Service: c.Service, User: c.User, Pass: c.Pass,
			})
			if len(v.Creds) >= capturesMaxCreds {
				break
			}
		}
		if len(v.Creds) >= capturesMaxCreds {
			break
		}
	}
	return v
}

func (s *Server) handleCaptures(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	since := time.Now().Add(-capturesWindow)
	var evs []*event.Event
	if e, err := s.query(ctx, store.Filter{Since: since, Limit: capturesScanMax}); err == nil {
		evs = e
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "captures", buildCapturesView(s.dataDir, since, evs)); err != nil {
		slog.Warn("ui: render captures", "err", err)
	}
}

// handleLoot serves a single captured file by kind + name, read-only and as an
// attachment. Defense in depth: kind is from a fixed allowlist, the name is
// basename-only (safeJoin) and opened without following a final-component
// symlink. Mirrors handlePcap / handleSession.
func (s *Server) handleLoot(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.NotFound(w, r)
		return
	}
	kind := r.URL.Query().Get("kind")
	sub := lootDir[kind]
	if sub == "" {
		http.Error(w, "bad kind", http.StatusBadRequest)
		return
	}
	name := r.URL.Query().Get("name")
	p, ok := safeJoin(filepath.Join(s.dataDir, sub), name)
	if !ok {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	f, err := openNoFollow(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	// Always octet-stream + attachment: these are hostile artifacts; never let
	// a browser sniff/execute a captured payload inline.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(p)))
	_, _ = io.Copy(w, f)
}
