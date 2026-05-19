package safe

import (
	"bytes"
	"strings"
	"testing"
)

func TestSliceBoundsChecks(t *testing.T) {
	b := []byte("hello world")
	if _, ok := Slice(b, 0, 5); !ok {
		t.Errorf("in-range slice rejected")
	}
	if _, ok := Slice(b, -1, 5); ok {
		t.Errorf("negative off accepted")
	}
	if _, ok := Slice(b, 0, -1); ok {
		t.Errorf("negative n accepted")
	}
	if _, ok := Slice(b, 100, 5); ok {
		t.Errorf("off past end accepted")
	}
	if _, ok := Slice(b, 5, 100); ok {
		t.Errorf("off+n past end accepted")
	}
	// Integer overflow: off + n wraps to negative on a 64-bit int.
	if _, ok := Slice(b, 1, 1<<62); ok {
		t.Errorf("overflow accepted")
	}
}

func TestBoundedStringCap(t *testing.T) {
	b := make([]byte, 100)
	_, ok := BoundedString(b, 0, 100)
	if !ok {
		t.Fatal("100 bytes within cap should succeed")
	}
	// Forbidden by MaxStringBytes cap.
	huge := make([]byte, MaxStringBytes+1)
	if _, ok := BoundedString(huge, 0, MaxStringBytes+1); ok {
		t.Errorf("over-cap length accepted")
	}
}

func TestAllocBytesRejectsLarge(t *testing.T) {
	if _, ok := AllocBytes(MaxStringBytes + 1); ok {
		t.Errorf("alloc larger than cap accepted")
	}
	if _, ok := AllocBytes(-1); ok {
		t.Errorf("negative alloc accepted")
	}
	if _, ok := AllocBytes(0); !ok {
		t.Errorf("zero-byte alloc rejected")
	}
}

func TestASCIIPrintable(t *testing.T) {
	s := ASCIIPrintable("hello\x00\x1b[31mred\n\r world")
	if strings.ContainsAny(s, "\x00\x1b\n\r") {
		t.Errorf("non-printable survived: %q", s)
	}
	if !strings.Contains(s, "hello") || !strings.Contains(s, "world") {
		t.Errorf("legit bytes lost: %q", s)
	}
}

func TestSanitizeForLogEscapesAttackerBytes(t *testing.T) {
	// Classic log-injection: an attacker types a newline followed by
	// a fake-looking entry. The sanitizer must keep it on one line.
	in := "GET / HTTP/1.1\nlevel=info msg=fakeentry"
	out := SanitizeForLog(in)
	if strings.Contains(out, "\n") {
		t.Errorf("newline survived: %q", out)
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("newline not escaped: %q", out)
	}

	// ANSI sequences must escape so a `tail -f` viewer can't get
	// terminal-jacked.
	in2 := "\x1b[2J\x1b[Hpwn"
	out2 := SanitizeForLog(in2)
	if strings.ContainsAny(out2, "\x1b") {
		t.Errorf("ESC survived: %q", out2)
	}
}

func TestSanitizeForLogTruncates(t *testing.T) {
	in := strings.Repeat("A", MaxLogLength*2)
	out := SanitizeForLog(in)
	if !strings.HasSuffix(out, "...[truncated]") {
		t.Errorf("over-cap not truncated: tail=%q", out[len(out)-20:])
	}
}

func TestSanitizeUTF8RemovesBidi(t *testing.T) {
	// U+202E is the right-to-left override — used in spoofing
	// attacks where a filename "evilexe.txt" actually renders as
	// "txt.exeyrev" thanks to RLO.
	in := "evil‮cod"
	out := SanitizeUTF8ForLog(in)
	if strings.ContainsRune(out, '‮') {
		t.Errorf("RLO survived: %q", out)
	}
}

func TestSanitizeHeader(t *testing.T) {
	// HTTP response splitting attempt — an attacker submits a
	// User-Agent like "Mozilla\r\nX-Pwn: yes" so they can inject a
	// header. Our handlers echo nothing into header values, but a
	// future bug regression would catch on the sanitizer.
	in := "Mozilla\r\nX-Pwn: yes"
	out := SanitizeHeader(in)
	if strings.ContainsAny(out, "\r\n") {
		t.Errorf("CRLF survived: %q", out)
	}
}

func TestSanitizeEmailSubject(t *testing.T) {
	in := "alert\r\nBcc: attacker@example.com"
	out := SanitizeEmailSubject(in)
	if strings.ContainsAny(out, "\r\n") {
		t.Errorf("CRLF in email subject survived: %q", out)
	}
}

func TestHexDumpBounded(t *testing.T) {
	b := bytes.Repeat([]byte{0xff}, 4096)
	out := HexDump(b, 64)
	if !strings.Contains(out, "more bytes") {
		t.Errorf("HexDump did not truncate: %q", out)
	}
	// Make sure the rendering is one self-contained block (no panic
	// on truncated lines).
	if len(out) > 4096 {
		t.Errorf("HexDump output too big: %d bytes", len(out))
	}
}
