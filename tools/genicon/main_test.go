package main

import (
	"bytes"
	"image"
	"testing"
)

func TestDrawIconDimensions(t *testing.T) {
	for _, size := range []int{16, 32, 48, 256} {
		img := drawIcon(size)
		if img == nil {
			t.Fatalf("drawIcon(%d) = nil", size)
		}
		if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
			t.Errorf("drawIcon(%d) bounds = %dx%d", size, b.Dx(), b.Dy())
		}
	}
}

func TestWriteICOHeader(t *testing.T) {
	var buf bytes.Buffer
	frames := []*image.RGBA{drawIcon(16), drawIcon(32)}
	if err := writeICO(&buf, frames); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) < 6 {
		t.Fatal("ICO output too small")
	}
	// ICONDIR: reserved=0, type=1 (icon), count = number of frames.
	if b[0] != 0 || b[1] != 0 || b[2] != 1 || b[3] != 0 {
		t.Errorf("bad ICONDIR header: %v", b[:4])
	}
	if count := int(b[4]) | int(b[5])<<8; count != len(frames) {
		t.Errorf("ICO frame count = %d, want %d", count, len(frames))
	}
}
