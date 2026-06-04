package ui

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseCast(t *testing.T) {
	cast := `{"version":2,"width":120,"height":40,"timestamp":1700000000}
[0.5,"o","login: "]
[1.2,"i","root\r"]
[1.3,"o","root\r\nPassword: "]
[2.0,"i","hunter2\r"]
[2.1,"o","\r\nWelcome\r\n$ "]
not-json-noise
[3.0,"x"]
`
	w, h, frames := parseCast(bufio.NewReader(strings.NewReader(cast)))
	if w != 120 || h != 40 {
		t.Errorf("dimensions = %dx%d, want 120x40", w, h)
	}
	if len(frames) != 5 {
		t.Fatalf("expected 5 frames, got %d: %+v", len(frames), frames)
	}
	if frames[0].Dir != "out" || frames[0].T != 0.5 || frames[0].Text != "login: " {
		t.Errorf("frame0 wrong: %+v", frames[0])
	}
	if frames[1].Dir != "in" || frames[1].Text != "root\r" {
		t.Errorf("frame1 (input) wrong: %+v", frames[1])
	}
	if frames[4].T != 2.1 {
		t.Errorf("last frame t = %v, want 2.1", frames[4].T)
	}
}

func TestParseCastNoHeader(t *testing.T) {
	// A cast missing the header still parses event lines (default 80x24).
	cast := "[0.1,\"o\",\"hi\"]\n[0.2,\"o\",\"there\"]\n"
	w, h, frames := parseCast(bufio.NewReader(strings.NewReader(cast)))
	if w != 80 || h != 24 {
		t.Errorf("defaults = %dx%d, want 80x24", w, h)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
}

func TestReplayViewRendersFigure(t *testing.T) {
	cast := "{\"version\":2,\"width\":80,\"height\":24}\n[0.5,\"o\",\"hello world\"]\n"
	w, h, frames := parseCast(bufio.NewReader(strings.NewReader(cast)))
	v := replayView{Name: "x.cast", Width: w, Height: h, Duration: frames[len(frames)-1].T}
	v.Frames = chartFigure("sessionreplay", "", map[string]any{"frames": frames, "width": w, "height": h})
	if v.Frames.B64 == "" {
		t.Fatal("frames figure not encoded")
	}
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "replay", v); err != nil {
		t.Fatalf("render replay: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "session replay") || !strings.Contains(out, `data-chart="sessionreplay"`) {
		t.Errorf("replay page missing player/figure")
	}
}

func TestReplayViewError(t *testing.T) {
	var b strings.Builder
	if err := uiTmpl(t).ExecuteTemplate(&b, "replay", replayView{Err: "no session recording specified"}); err != nil {
		t.Fatalf("render replay error view: %v", err)
	}
	if !strings.Contains(b.String(), "no session recording specified") {
		t.Errorf("error view missing message")
	}
}
