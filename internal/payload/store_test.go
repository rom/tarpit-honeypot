package payload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistAndDedup(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	a := Artifact{Kind: KindELF, SHA256: sha256Hex([]byte("abc")), Bytes: []byte("abc")}
	p1, err := st.Persist(a)
	if err != nil || p1 == "" {
		t.Fatalf("persist: %v %q", err, p1)
	}
	if filepath.Ext(p1) != ".elf" {
		t.Errorf("expected .elf extension; got %q", p1)
	}
	// Persisting the same hash again returns the same path, no rewrite.
	p2, _ := st.Persist(a)
	if p2 != p1 {
		t.Errorf("dedup failed: %q vs %q", p1, p2)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file after dedup; got %d", len(entries))
	}
}

func TestStoreCapRotation(t *testing.T) {
	dir := t.TempDir()
	// 1 MB total cap via maxTotalMB=1; write several 400KB artifacts.
	st, err := NewStore(dir, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		b := make([]byte, 400*1024)
		b[0] = byte(i) // distinct content -> distinct hash
		_, _ = st.Persist(Artifact{Kind: KindShellcode, SHA256: sha256Hex(b), Bytes: b})
	}
	entries, _ := os.ReadDir(dir)
	var total int64
	for _, e := range entries {
		info, _ := e.Info()
		total += info.Size()
	}
	if total > 1<<20 {
		t.Errorf("directory cap exceeded: %d bytes across %d files", total, len(entries))
	}
}

func TestStoreTruncatesToMaxBytes(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStore(dir, 10, 0) // 10-byte per-artifact cap
	b := []byte("0123456789ABCDEF")
	p, _ := st.Persist(Artifact{Kind: KindShellcode, SHA256: sha256Hex(b), Bytes: b})
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 10 {
		t.Errorf("artifact not truncated to maxBytes: %d", info.Size())
	}
}
