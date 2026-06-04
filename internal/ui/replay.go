package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// Session replay: an in-browser player for the asciinema v2 cast files the
// sensor records for interactive SSH/Telnet shells. The cast is parsed
// server-side into timed frames; the client (charts.js "sessionreplay")
// renders a terminal and plays them back with play/pause/seek/speed. This
// turns the downloadable .cast loot into a watchable attacker session.

const (
	replayMaxFrames = 8000
	replayMaxBytes  = 512 << 10 // total output text kept for a replay
)

// replayFrame is one timed terminal event.
type replayFrame struct {
	T    float64 `json:"t"`    // seconds since session start
	Dir  string  `json:"dir"`  // "in" (attacker typed) | "out" (sensor sent)
	Text string  `json:"text"` // raw bytes (may contain control/ANSI codes)
}

// replayView is the rendered replay page.
type replayView struct {
	Name     string
	EventID  string
	Width    int
	Height   int
	Duration float64
	Frames   chartFig // sessionreplay figure carrying the frames
	Err      string
}

// parseCast reads an asciinema v2 cast (header object line + [t,code,data]
// event lines) into frames, bounded by replayMaxFrames / replayMaxBytes.
func parseCast(r *bufio.Reader) (width, height int, frames []replayFrame) {
	width, height = 80, 24
	bytesKept := 0
	first := true
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				if first && strings.HasPrefix(trimmed, "{") {
					var hdr struct {
						Width  int `json:"width"`
						Height int `json:"height"`
					}
					if json.Unmarshal([]byte(trimmed), &hdr) == nil {
						if hdr.Width > 0 {
							width = hdr.Width
						}
						if hdr.Height > 0 {
							height = hdr.Height
						}
					}
				} else if strings.HasPrefix(trimmed, "[") {
					var ev []json.RawMessage
					if json.Unmarshal([]byte(trimmed), &ev) == nil && len(ev) == 3 {
						var t float64
						var code, data string
						_ = json.Unmarshal(ev[0], &t)
						_ = json.Unmarshal(ev[1], &code)
						_ = json.Unmarshal(ev[2], &data)
						dir := "out"
						if code == "i" {
							dir = "in"
						}
						if bytesKept+len(data) <= replayMaxBytes && len(frames) < replayMaxFrames {
							frames = append(frames, replayFrame{T: t, Dir: dir, Text: data})
							bytesKept += len(data)
						}
					}
				}
				first = false
			}
		}
		if err != nil {
			break
		}
	}
	return width, height, frames
}

// handleReplay renders the session-replay player for a cast named by ?name=
// (a sessions-dir file) or ?event= (an event whose meta carries session_cast).
func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	if s.dataDir == "" {
		http.NotFound(w, r)
		return
	}
	name := r.URL.Query().Get("name")
	eventID := r.URL.Query().Get("event")
	if name == "" && eventID != "" {
		if !hexID(eventID) {
			http.Error(w, "bad event id", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if ev, err := s.store.Get(ctx, eventID); err == nil {
			name, _ = ev.Meta["session_cast"].(string)
		}
	}
	view := replayView{Name: name, EventID: eventID}
	if name == "" {
		view.Err = "no session recording specified"
		s.renderReplay(w, view)
		return
	}
	p, ok := safeJoin(filepath.Join(s.dataDir, "sessions"), name)
	if !ok {
		http.Error(w, "bad cast name", http.StatusBadRequest)
		return
	}
	f, err := openNoFollow(p)
	if err != nil {
		view.Err = "session recording not found"
		s.renderReplay(w, view)
		return
	}
	defer f.Close()

	width, height, frames := parseCast(bufio.NewReader(f))
	view.Width, view.Height = width, height
	if len(frames) > 0 {
		view.Duration = frames[len(frames)-1].T
	}
	view.Frames = chartFigure("sessionreplay", "", map[string]any{
		"frames": frames, "width": width, "height": height,
	})
	if view.Frames.B64 == "" {
		view.Err = "no replayable frames in this recording"
	}
	s.renderReplay(w, view)
}

func (s *Server) renderReplay(w http.ResponseWriter, v replayView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "replay", v); err != nil {
		slog.Warn("ui: render replay", "err", err)
	}
}
