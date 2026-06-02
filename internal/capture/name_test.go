package capture

import (
	"net"
	"strings"
	"testing"
)

func TestPcapFileName(t *testing.T) {
	src4 := &net.TCPAddr{IP: net.ParseIP("203.0.113.42"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if got := pcapFileName("abc123", src4, dst); got != "abc123_203.0.113.42_22.pcap" {
		t.Errorf("ipv4 name = %q", got)
	}
	// IPv6 source: colons must be sanitized to dashes (filename-safe).
	src6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9}
	got := pcapFileName("deadbeef", src6, dst)
	if strings.ContainsRune(got, ':') {
		t.Errorf("ipv6 name still has a colon: %q", got)
	}
	if !strings.HasPrefix(got, "deadbeef_") || !strings.HasSuffix(got, "_22.pcap") {
		t.Errorf("ipv6 name shape wrong: %q", got)
	}
}
