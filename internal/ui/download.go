package ui

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// openNoFollow opens a file read-only, refusing to traverse a symlink at
// the final path component (see download_unix.go / download_windows.go for
// the per-platform implementation). Defense in depth: even though pcap/cast
// names are validated to stay inside the data dir, a symlink planted there
// (by something with local write access) must not redirect a download to an
// arbitrary file.

// SetDataDir wires the sensor data dir so the UI can serve recorded
// pcaps (<dataDir>/captures/<id>.pcap) and session casts
// (<dataDir>/sessions/<name>). Empty disables the download routes.
func (s *Server) SetDataDir(dir string) { s.dataDir = dir }

// hexID reports whether id is a plausible event id (hex only) — guards the
// pcap path against traversal.
func hexID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// safeJoin joins dir + the basename of name and confirms the result stays
// inside dir (defence in depth against traversal in cast filenames).
func safeJoin(dir, name string) (string, bool) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", false
	}
	p := filepath.Join(dir, name)
	if !strings.HasPrefix(p, filepath.Clean(dir)+string(os.PathSeparator)) {
		return "", false
	}
	return p, true
}

func (s *Server) handlePcap(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/pcap/")
	if !hexID(id) {
		http.Error(w, "bad event id", http.StatusBadRequest)
		return
	}
	p := filepath.Join(s.dataDir, "captures", id+".pcap")
	f, err := openNoFollow(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".pcap"))
	_, _ = io.Copy(w, f)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/session/")
	if !hexID(id) {
		http.Error(w, "bad event id", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ev, err := s.store.Get(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cast, _ := ev.Meta["session_cast"].(string)
	if cast == "" {
		http.Error(w, "no session recording for this event", http.StatusNotFound)
		return
	}
	p, ok := safeJoin(filepath.Join(s.dataDir, "sessions"), cast)
	if !ok {
		http.Error(w, "bad cast name", http.StatusBadRequest)
		return
	}
	f, err := openNoFollow(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(p)))
	_, _ = io.Copy(w, f)
}

// handleDownload bundles the pcaps and/or session casts for every event
// matching the same filter the /events page uses (source IP, rule, since,
// severity) into a single streamed ZIP. ?what=pcap|session|all (default
// all). This is the "give me everything from 198.51.100.42" path.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.NotFound(w, r)
		return
	}
	what := r.URL.Query().Get("what")
	if what == "" {
		what = "all"
	}
	wantPcap := what == "all" || what == "pcap"
	wantSession := what == "all" || what == "session"

	f := parseFilter(r)
	f.Limit = 2000 // bulk export cap
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	evs, err := s.store.Query(ctx, f)
	if err != nil {
		serverError(w, r.URL.Path, err)
		return
	}

	fname := "tarpit-export"
	if f.SourceIP != "" {
		fname += "-" + strings.NewReplacer(":", "_", "/", "_").Replace(f.SourceIP)
	}
	fname += ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fname))

	zw := zip.NewWriter(w)
	defer zw.Close()
	capDir := filepath.Join(s.dataDir, "captures")
	sessDir := filepath.Join(s.dataDir, "sessions")
	addedCasts := map[string]bool{}
	n := 0
	for _, ev := range evs {
		if wantPcap && hexID(ev.ID) {
			if added := copyInto(zw, filepath.Join(capDir, ev.ID+".pcap"), "pcaps/"+ev.ID+".pcap"); added {
				n++
			}
		}
		if wantSession {
			if cast, _ := ev.Meta["session_cast"].(string); cast != "" && !addedCasts[cast] {
				if p, ok := safeJoin(sessDir, cast); ok {
					if added := copyInto(zw, p, "sessions/"+filepath.Base(p)); added {
						addedCasts[cast] = true
						n++
					}
				}
			}
		}
	}
	if n == 0 {
		// Nothing matched on disk — still emit a note so the ZIP isn't empty/confusing.
		if fw, err := zw.Create("README.txt"); err == nil {
			_, _ = io.WriteString(fw, "No recorded pcaps or session casts matched the requested filter.\n")
		}
	}
}

// copyInto streams the file at path into the zip under name. Returns false
// (silently) when the source file doesn't exist.
func copyInto(zw *zip.Writer, path, name string) bool {
	f, err := openNoFollow(path)
	if err != nil {
		return false
	}
	defer f.Close()
	fw, err := zw.Create(name)
	if err != nil {
		return false
	}
	if _, err := io.Copy(fw, f); err != nil {
		return false
	}
	return true
}
