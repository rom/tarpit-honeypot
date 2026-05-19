package capture

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPcapWriterFormat(t *testing.T) {
	mgr, err := NewManager(t.TempDir(), 64, 100)
	if err != nil {
		t.Fatal(err)
	}
	src, _ := net.ResolveTCPAddr("tcp", "1.2.3.4:1111")
	dst, _ := net.ResolveTCPAddr("tcp", "5.6.7.8:2222")
	sess := mgr.Begin("ev-pcap-test", src, dst)
	sess.recordBytes(DirIn, []byte("GET / HTTP/1.0\r\n\r\n"))
	sess.recordBytes(DirOut, []byte("HTTP/1.0 401 Unauthorized\r\n\r\n"))
	time.Sleep(time.Millisecond) // ensure non-zero usec
	sess.recordBytes(DirIn, []byte("more bytes"))

	path, _, err := sess.End()
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("End returned empty path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 24 {
		t.Fatalf("file too short: %d", len(b))
	}
	if magic := binary.LittleEndian.Uint32(b[0:4]); magic != 0xa1b2c3d4 {
		t.Errorf("pcap magic = %x; want a1b2c3d4", magic)
	}
	if linktype := binary.LittleEndian.Uint32(b[20:24]); linktype != 101 {
		t.Errorf("linktype = %d; want 101 (DLT_RAW)", linktype)
	}
	// Walk records: each is 16 bytes hdr + caplen bytes.
	pos := 24
	recs := 0
	for pos+16 <= len(b) {
		caplen := binary.LittleEndian.Uint32(b[pos+8 : pos+12])
		if int(caplen) > 65535 {
			t.Fatalf("rec %d caplen=%d wildly large", recs, caplen)
		}
		pos += 16 + int(caplen)
		recs++
	}
	if recs != 3 {
		t.Fatalf("expected 3 records; got %d", recs)
	}
	if pos != len(b) {
		t.Errorf("trailing bytes: pos=%d len=%d", pos, len(b))
	}
}

func TestPcapRotation(t *testing.T) {
	dir := t.TempDir()
	// 4KB cap so two ~3KB pcaps trip rotation on the third.
	mgr, err := NewManager(dir, 64, 1) // 1MB total cap
	if err != nil {
		t.Fatal(err)
	}
	mgr.totalBytes = 4000
	for i := 0; i < 6; i++ {
		src, _ := net.ResolveTCPAddr("tcp", "1.2.3.4:1111")
		dst, _ := net.ResolveTCPAddr("tcp", "5.6.7.8:2222")
		sess := mgr.Begin(timeID(i), src, dst)
		sess.recordBytes(DirIn, make([]byte, 2048))
		if _, _, err := sess.End(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "captures"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 4 {
		t.Errorf("expected pruning to keep ~few files; got %d", len(entries))
	}
}

func timeID(i int) string {
	return "ev-" + string(rune('a'+i))
}
