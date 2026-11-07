package artifactscan

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"io"
	"regexp"
	"strings"
)

// Recursive deobfuscation. Droppers wrap their real payload in layers —
// base64 → gzip/zlib → hex → single-byte XOR — and only the innermost layer
// carries the stage-2 URL / command / ELF. This peels those layers (bounded in
// depth and size, never executing anything) so IOC extraction and dropper
// classification run against what the attacker actually intended to deliver.

const (
	deobfMaxDepth = 6
	deobfMaxBytes = 4 << 20 // 4 MiB per layer ceiling
	deobfMinBlob  = 24      // ignore tiny base64/hex runs (false positives)
	deobfPreviewB = 220
)

// deobfMethods renders the layer chain as "base64 → gzip → xor:0x7f".
func deobfMethods(layers []DeobfLayer) string {
	parts := make([]string, len(layers))
	for i, l := range layers {
		parts[i] = l.Method
	}
	return strings.Join(parts, " → ")
}

// DeobfLayer is one successfully-decoded layer.
type DeobfLayer struct {
	Method  string `json:"method"`  // base64 | gzip | zlib | hex | xor:0xNN
	Size    int    `json:"size"`    // decoded byte length
	Preview string `json:"preview"` // sanitized head of the decoded bytes
}

var (
	reB64Run = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	reHexRun = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}){12,}`)
	// Markers that indicate a decode produced something meaningful (so we accept
	// an XOR key or a base64 blob rather than random noise).
	deobfMarkers = [][]byte{
		[]byte("\x7fELF"), {0x1f, 0x8b}, []byte("#!/"), []byte("/bin/"),
		[]byte("http://"), []byte("https://"), []byte("wget"), []byte("curl"),
		[]byte("chmod"), []byte("busybox"), []byte("/tmp/"), []byte("eval"),
	}
)

// Deobfuscate peels obfuscation layers from data, returning each decoded layer
// and the final revealed bytes. When nothing decodes, layers is nil and final
// is the input unchanged.
func Deobfuscate(data []byte) (layers []DeobfLayer, final []byte) {
	cur := data
	for depth := 0; depth < deobfMaxDepth; depth++ {
		method, dec := decodeOneLayer(cur)
		if dec == nil || len(dec) == 0 || bytes.Equal(dec, cur) {
			break
		}
		if len(dec) > deobfMaxBytes {
			dec = dec[:deobfMaxBytes]
		}
		layers = append(layers, DeobfLayer{Method: method, Size: len(dec), Preview: preview(dec)})
		cur = dec
	}
	return layers, cur
}

// decodeOneLayer tries the layer codecs in priority order and returns the first
// that yields meaningful output.
func decodeOneLayer(b []byte) (string, []byte) {
	// Binary-magic layers first (unambiguous).
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		if out := gunzip(b); out != nil {
			return "gzip", out
		}
	}
	if len(b) >= 2 && b[0] == 0x78 && (b[1] == 0x01 || b[1] == 0x9c || b[1] == 0xda) {
		if out := inflate(b); out != nil {
			return "zlib", out
		}
	}
	// Textual blobs embedded in a script: decode the longest run.
	if run := longest(reB64Run, b); len(run) >= deobfMinBlob {
		if out, err := base64.StdEncoding.DecodeString(strings.TrimRight(run, "=") + pad(run)); err == nil && meaningful(out) {
			return "base64", out
		}
	}
	if run := longest(reHexRun, b); len(run) >= deobfMinBlob*2 {
		if out, err := hex.DecodeString(stripNonHex(run)); err == nil && meaningful(out) {
			return "hex", out
		}
	}
	// Single-byte XOR brute force (only for smallish high-entropy blobs).
	if len(b) <= 256<<10 {
		if key, out := xorBrute(b); out != nil {
			return "xor:0x" + hex.EncodeToString([]byte{key}), out
		}
	}
	return "", nil
}

func longest(re *regexp.Regexp, b []byte) string {
	best := ""
	for _, m := range re.FindAll(b, -1) {
		if len(m) > len(best) {
			best = string(m)
		}
	}
	return best
}

func pad(s string) string {
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 2:
		return "=="
	case 3:
		return "="
	}
	return ""
}

func stripNonHex(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, s)
	if len(s)%2 == 1 {
		s = s[:len(s)-1]
	}
	return s
}

// meaningful reports whether decoded bytes look like a real payload (a marker,
// or mostly-printable text) rather than random noise.
func meaningful(b []byte) bool {
	for _, m := range deobfMarkers {
		if bytes.Contains(b, m) {
			return true
		}
	}
	if len(b) < 8 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

// xorBrute finds a single-byte key whose XOR output carries a payload marker.
func xorBrute(b []byte) (byte, []byte) {
	for k := 1; k <= 255; k++ {
		out := make([]byte, len(b))
		for i, c := range b {
			out[i] = c ^ byte(k)
		}
		for _, m := range deobfMarkers {
			if bytes.Contains(out, m) {
				return byte(k), out
			}
		}
	}
	return 0, nil
}

func gunzip(b []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, deobfMaxBytes))
	if err != nil && len(out) == 0 {
		return nil
	}
	return out
}

func inflate(b []byte) []byte {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, deobfMaxBytes))
	if err != nil && len(out) == 0 {
		return nil
	}
	return out
}

func preview(b []byte) string {
	n := len(b)
	if n > deobfPreviewB {
		n = deobfPreviewB
	}
	return sanitizePreview(b[:n])
}

func sanitizePreview(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t' || c == ' ':
			sb.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}
