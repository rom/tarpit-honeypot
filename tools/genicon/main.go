// genicon — generate internal/ui/static/favicon.ico from a tiny in-code icon.
//
// The web UI ships an SVG mark (static/icon.svg) for modern browsers; this
// program produces a multi-size .ico (16, 32, 48) for the browsers and tools
// that still request /favicon.ico. Re-run when the icon design changes:
//
//	go run ./tools/genicon
//
// The output is committed; the runtime sensor never executes this code.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

// drawIcon paints the same hex-cell + tar-drop motif as static/icon.svg into a
// size×size RGBA image. Anti-aliased via per-pixel coverage on the signed
// distance to each shape boundary — keeps the small 16/32 sizes legible.
func drawIcon(size int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	fSize := float64(size)
	cx := fSize / 2

	// Hex frame: matches the SVG's hexagon vertices, scaled to the bitmap.
	pts := [][2]float64{
		{0.5, 0.05}, {0.92, 0.27}, {0.92, 0.73},
		{0.5, 0.95}, {0.08, 0.73}, {0.08, 0.27},
	}
	hex := make([][2]float64, len(pts))
	for i, p := range pts {
		hex[i] = [2]float64{p[0] * fSize, p[1] * fSize}
	}

	honeyRim := color.RGBA{0xd5, 0x9a, 0x3a, 0xff}
	honeyFill := color.RGBA{0xfb, 0xe5, 0xa3, 0xff}
	tar := color.RGBA{0x1a, 0x1d, 0x23, 0xff}
	highlight := color.RGBA{0x3a, 0x3e, 0x4a, 0xff}

	// Tar-drop geometry: point at top, body circle bottom.
	dropTipY := fSize * 0.21
	dropCx, dropCy := cx, fSize*0.62
	dropR := fSize * 0.20

	// Rim thickness scales with size so 16px stays readable.
	rim := math.Max(1.0, fSize/16.0)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5

			// Hex inside test: signed distance to each edge (a point is inside
			// when all six are non-negative).
			inHex := true
			minDist := math.MaxFloat64
			for i := 0; i < len(hex); i++ {
				a := hex[i]
				b := hex[(i+1)%len(hex)]
				nx, ny := b[1]-a[1], -(b[0] - a[0])
				ln := math.Sqrt(nx*nx + ny*ny)
				nx, ny = nx/ln, ny/ln
				d := (px-a[0])*nx + (py-a[1])*ny
				if d > 0 {
					inHex = false
				}
				if -d < minDist {
					minDist = -d // distance from edge, inside positive
				}
			}

			// Tar drop: union of a circle (body) and an isoceles triangle (tip).
			ddx, ddy := px-dropCx, py-dropCy
			inBody := ddx*ddx+ddy*ddy <= dropR*dropR
			inTip := false
			if py >= dropTipY && py <= dropCy {
				progress := (py - dropTipY) / (dropCy - dropTipY)
				if math.Abs(px-dropCx) <= progress*dropR*1.05 {
					inTip = true
				}
			}
			inDrop := inBody || inTip

			switch {
			case inDrop:
				// Sample a small lighter spot inside the bottom-left of the drop
				// for the "wet" highlight (subtler than a hard ellipse).
				hx, hy := px-(dropCx-dropR*0.45), py-(dropCy+dropR*0.05)
				if hx*hx/(dropR*0.18*dropR*0.18)+hy*hy/(dropR*0.28*dropR*0.28) <= 1 {
					img.SetRGBA(x, y, highlight)
				} else {
					img.SetRGBA(x, y, tar)
				}
			case inHex:
				if minDist < rim {
					img.SetRGBA(x, y, honeyRim)
				} else {
					img.SetRGBA(x, y, honeyFill)
				}
			}
		}
	}
	return img
}

// writeICO assembles PNG-framed ICO bytes for the given image sizes.
func writeICO(out *bytes.Buffer, frames []*image.RGBA) error {
	type entry struct {
		size int
		png  []byte
	}
	var entries []entry
	for _, f := range frames {
		var b bytes.Buffer
		if err := png.Encode(&b, f); err != nil {
			return err
		}
		entries = append(entries, entry{size: f.Bounds().Dx(), png: b.Bytes()})
	}

	// ICONDIR: reserved(2) + type(2) + count(2)
	if err := binary.Write(out, binary.LittleEndian, uint16(0)); err != nil {
		return err
	}
	if err := binary.Write(out, binary.LittleEndian, uint16(1)); err != nil { // ICO
		return err
	}
	if err := binary.Write(out, binary.LittleEndian, uint16(len(entries))); err != nil {
		return err
	}

	// ICONDIRENTRY ×N: each is 16 bytes; image data follows.
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		w := byte(0)
		if e.size < 256 {
			w = byte(e.size)
		}
		out.WriteByte(w)                                       // width
		out.WriteByte(w)                                       // height
		out.WriteByte(0)                                       // color count
		out.WriteByte(0)                                       // reserved
		_ = binary.Write(out, binary.LittleEndian, uint16(1))  // planes
		_ = binary.Write(out, binary.LittleEndian, uint16(32)) // bit count
		_ = binary.Write(out, binary.LittleEndian, uint32(len(e.png)))
		_ = binary.Write(out, binary.LittleEndian, uint32(offset))
		offset += len(e.png)
	}
	for _, e := range entries {
		out.Write(e.png)
	}
	return nil
}

func main() {
	sizes := []int{16, 32, 48}
	frames := make([]*image.RGBA, 0, len(sizes))
	for _, s := range sizes {
		frames = append(frames, drawIcon(s))
	}
	var buf bytes.Buffer
	if err := writeICO(&buf, frames); err != nil {
		fmt.Fprintln(os.Stderr, "ico encode:", err)
		os.Exit(1)
	}
	const dst = "internal/ui/static/favicon.ico"
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes, sizes %v)\n", dst, buf.Len(), sizes)
}
