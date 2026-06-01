package fingerprint

import (
	"strings"
	"testing"
)

// A minimal ServerHello handshake message (type 0x02) reused from the JA3S
// tests: version TLS1.2, one cipher, two extensions.
func sampleServerHello() []byte {
	// handshake type(1)=0x02, len(3), body
	body := []byte{
		0x03, 0x03, // legacy_version TLS1.2
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id len 0
	body = append(body, 0xc0, 0x2f)          // cipher
	body = append(body, 0x00)                // compression
	// extensions: total len, then two extensions (type+len0)
	ext := []byte{
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions
		0x00, 0x33, 0x00, 0x00, // key_share (len 0, for brevity)
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func TestJA4SFormat(t *testing.T) {
	got := JA4S(sampleServerHello())
	if got == "" {
		t.Fatal("JA4S returned empty for a valid ServerHello")
	}
	// {proto}{nexts}00_{cipher4}_{hash12}
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4S = %q, want three underscore fields", got)
	}
	if parts[1] != "c02f" {
		t.Errorf("cipher field = %q, want c02f", parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("ext hash = %q, want 12 hex chars", parts[2])
	}
}

func TestJA4SStable(t *testing.T) {
	a := JA4S(sampleServerHello())
	b := JA4S(sampleServerHello())
	if a != b {
		t.Errorf("JA4S not deterministic: %q vs %q", a, b)
	}
}

func TestJA4SRejectsGarbage(t *testing.T) {
	if got := JA4S([]byte{0x01, 0x02, 0x03}); got != "" {
		t.Errorf("JA4S on garbage = %q, want empty", got)
	}
}

func TestJA4T(t *testing.T) {
	syn := TCPSyn{
		WindowSize:  64240,
		MSS:         1460,
		WindowScale: 7,
		Options: []TCPOpt{
			{Kind: 2}, {Kind: 4}, {Kind: 8}, {Kind: 1}, {Kind: 3},
		},
	}
	got := JA4T(syn)
	want := "64240_2-4-8-1-3_1460_7"
	if got != want {
		t.Errorf("JA4T = %q, want %q", got, want)
	}
}

func TestJA4TEmpty(t *testing.T) {
	if got := JA4T(TCPSyn{}); got != "" {
		t.Errorf("JA4T on empty SYN = %q, want empty", got)
	}
}

func TestJARMShapeAndStability(t *testing.T) {
	probes := make([]JARMProbe, 10)
	for i := range probes {
		probes[i] = JARMProbe{Cipher: 0xc02f, Version: 0x0303, ALPN: "h2", Responded: true}
	}
	a := JARM(probes)
	b := JARM(probes)
	if a != b {
		t.Errorf("JARM not deterministic")
	}
	// 10 probes * 5-char cipher seg = 50, + 32-char hash = 62.
	if len(a) != 62 {
		t.Errorf("JARM length = %d, want 62", len(a))
	}
}

func TestJARMNoResponsesDiffersFromResponses(t *testing.T) {
	none := JARM(nil)
	resp := make([]JARMProbe, 10)
	for i := range resp {
		resp[i] = JARMProbe{Cipher: 0x1301, Version: 0x0304, Responded: true}
	}
	if none == JARM(resp) {
		t.Errorf("all-silent JARM should differ from a responding server")
	}
	if len(none) != 62 {
		t.Errorf("empty JARM length = %d, want 62", len(none))
	}
}
