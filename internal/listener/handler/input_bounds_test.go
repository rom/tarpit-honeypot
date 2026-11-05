package handler

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestMongoRejectsOversizedLength: a 16-byte header declaring a huge body must
// be rejected as malformed, never allocated — the amplification→OOM guard.
func TestMongoRejectsOversizedLength(t *testing.T) {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x10000000) // ~268 MB declared length
	binary.LittleEndian.PutUint32(hdr[12:16], 2013)     // OP_MSG
	res, _ := runDevsvc(t, &mongodb{}, hdr)
	if res.Meta["mongo_bad_length"] == nil {
		t.Errorf("oversized mongo msgLen should be flagged bad, not allocated: %+v", res.Meta)
	}
}

// TestReadLineCappedCaps: an unterminated stream must stop at the cap, not grow
// an unbounded buffer.
func TestReadLineCappedCaps(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(strings.Repeat("A", 100000))) // no '\n'
	s, err := readLineCapped(br, maxLineBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != maxLineBytes {
		t.Errorf("readLineCapped returned %d bytes; want cap %d", len(s), maxLineBytes)
	}
}

// TestReadDelimCappedCaps: same guard for the NUL-delimited reader, and it must
// not fabricate a trailing delimiter when the cap is hit.
func TestReadDelimCappedCaps(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader(bytes.Repeat([]byte{'x'}, 100000))) // no NUL
	b, err := readDelimCapped(br, 0x00, maxLineBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != maxLineBytes {
		t.Errorf("readDelimCapped returned %d bytes; want cap %d", len(b), maxLineBytes)
	}
	if b[len(b)-1] == 0x00 {
		t.Error("cap-truncated result must not end in the delimiter")
	}

	// With a delimiter present it stops at (and includes) it.
	br2 := bufio.NewReader(bytes.NewReader([]byte{'a', 'b', 0x00, 'c'}))
	b2, _ := readDelimCapped(br2, 0x00, maxLineBytes)
	if len(b2) != 3 || b2[2] != 0x00 {
		t.Errorf("readDelimCapped should return [a b NUL], got %v", b2)
	}
}
