package handler

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

func TestExpandLoginEscapesCentOS6(t *testing.T) {
	arch := archetype.Lookup("centos-6")
	if arch == nil {
		t.Fatal("centos-6 archetype missing")
	}
	in := "\r\nCentOS release 6.10 (Final)\r\nKernel \\r on an \\m\r\n\r\nlogin: "
	out := expandLoginEscapes(in, arch, nil)
	if strings.Contains(out, `\r on an \m`) {
		t.Errorf("escapes not expanded: %q", out)
	}
	if !strings.Contains(out, "2.6.32-754.el6.x86_64") {
		t.Errorf("kernel release not substituted: %q", out)
	}
	if !strings.Contains(out, "on an x86_64") {
		t.Errorf("machine not substituted: %q", out)
	}
	// The real CRLF line breaks must survive (only the backslash-escapes change).
	if !strings.HasPrefix(out, "\r\nCentOS release 6.10 (Final)\r\n") {
		t.Errorf("CRLF framing corrupted: %q", out)
	}
}

func TestExpandLoginEscapesUnknownKept(t *testing.T) {
	// An unrecognized escape is preserved verbatim, not dropped.
	out := expandLoginEscapes(`x\Zy`, nil, nil)
	if out != `x\Zy` {
		t.Errorf("unknown escape mangled: %q", out)
	}
}
