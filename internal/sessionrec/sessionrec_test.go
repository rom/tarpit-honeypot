package sessionrec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecorderWritesCast(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rc, name, err := st.Begin("10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the shell: sensor writes a prompt, attacker types a command.
	out := rc.Writer(&bytes.Buffer{})
	in := rc.Reader(bytes.NewReader([]byte("whoami\n")))
	_, _ = out.Write([]byte("$ "))
	buf := make([]byte, 16)
	_, _ = in.Read(buf)
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header + 2 events, got %d lines:\n%s", len(lines), data)
	}
	// Header is a v2 object.
	var hdr map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil || hdr["version"] != float64(2) {
		t.Errorf("bad cast header: %q", lines[0])
	}
	// Events are [time, "o"|"i", data]; check one of each appears.
	var sawOut, sawIn bool
	for _, ln := range lines[1:] {
		var ev []any
		if json.Unmarshal([]byte(ln), &ev) == nil && len(ev) == 3 {
			switch ev[1] {
			case "o":
				sawOut = true
			case "i":
				sawIn = true
			}
		}
	}
	if !sawOut || !sawIn {
		t.Errorf("cast missing output/input events: out=%v in=%v\n%s", sawOut, sawIn, data)
	}
}

func TestRecorderPerCastCap(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStore(dir, 64, 0) // 64-byte per-cast budget
	rc, name, _ := st.Begin("1.1.1.1")
	out := rc.Writer(&bytes.Buffer{})
	for i := 0; i < 100; i++ {
		_, _ = out.Write(bytes.Repeat([]byte("A"), 64))
	}
	_ = rc.Close()
	info, _ := os.Stat(filepath.Join(dir, name))
	// File = header + at most ~64 bytes of recorded data + json framing;
	// the recorded payload itself is budget-capped well under the flood.
	if info.Size() > 1024 {
		t.Errorf("per-cast budget not enforced: %d bytes", info.Size())
	}
}
