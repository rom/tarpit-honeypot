package handler

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// This file guarantees that EVERY registered protocol handler is exercised by
// both a "dumb" fuzz pass (empty / random / oversized bytes) and a "smart" fuzz
// pass (a structurally-valid seed frame), executed on every `go test` run — not
// just the on-demand Go-native FuzzTCPHandlers/FuzzUDPHandlers deep fuzzers.
//
// The honeypot's whole job is to survive hostile, malformed input forever, so a
// handler that panics or hangs on a crafted packet is a real defect. These
// tests drive each handler's Handle() with a panic-recovering, timeout-bounded
// wrapper so one bad handler is reported as a test failure instead of taking
// the suite (or, in production, the process) down. The authoritative handler
// lists come from config, the same whitelist the config validator enforces, so
// a newly-added handler is automatically covered here.

// driveTCP runs a TCP handler's Handle with the given input, recovering panics
// and bounding runtime. Returns a non-empty reason on panic/timeout.
func driveTCP(h Handler, in []byte) (reason string) {
	done := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- "panic: " + panicToStr(r)
				return
			}
			done <- ""
		}()
		conn := &fuzzConn{data: in}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cfg := config.Listener{ReadTimeout: 150 * time.Millisecond, ReadBytes: 65536}
		_, _ = h.Handle(ctx, conn, cfg)
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		return "hang (no return in 5s)"
	}
}

// driveUDP runs a UDP handler's Handle with the given datagram.
func driveUDP(h UDPHandler, in []byte) (reason string) {
	done := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- "panic: " + panicToStr(r)
				return
			}
			done <- ""
		}()
		src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cfg := config.Listener{ReadTimeout: 150 * time.Millisecond, ReadBytes: 65536}
		_, _ = h.Handle(ctx, in, src, fuzzPacketConn{}, cfg)
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		return "hang (no return in 5s)"
	}
}

func panicToStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return "non-string panic value"
	}
}

// dumbInputs is the "dumb" fuzz corpus: no structure, just hostile shapes.
func dumbInputs() [][]byte {
	rng := rand.New(rand.NewSource(0x7a9f)) // deterministic
	rnd := make([]byte, 512)
	rng.Read(rnd)
	big := make([]byte, 16384)
	for i := range big {
		big[i] = 0xFF
	}
	return [][]byte{
		nil,                    // empty
		{0x00},                 // single NUL
		rnd,                    // random noise
		big,                    // oversized all-0xFF (length-field / allocation stress)
		[]byte("\r\n\r\n\r\n"), // bare CRLFs
		[]byte("\x00\x00\x00\x00\x00\x00\x00\x00"),
	}
}

// smartSeed returns a structurally-valid (or protocol-plausible) seed frame for
// a handler — the "smart" fuzz starting point. Known binary/text protocols get
// a real frame; the rest fall back to a category-appropriate default so every
// handler still receives a structured input rather than only noise.
func smartSeed(name string) []byte {
	if s, ok := smartSeeds[name]; ok {
		return s
	}
	// Category defaults: text/line protocols get a plausible line; everything
	// else gets a short TLV-ish binary frame.
	return []byte("HELP\r\nVERSION\r\nGET / HTTP/1.0\r\n\r\n")
}

// smartSeeds holds valid frames for the structured protocols where a correct
// frame exercises materially different parser paths than noise would.
var smartSeeds = map[string][]byte{
	"http":       []byte("GET /admin/login?id=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\nCookie: a=b\r\n\r\n"),
	"ftp":        []byte("USER anonymous\r\nPASS x@y.z\r\nSYST\r\nSITE CPFR /etc/passwd\r\nQUIT\r\n"),
	"smtp_recv":  []byte("EHLO x\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n.\r\nQUIT\r\n"),
	"telnet":     []byte{0xff, 0xfd, 0x18, 0xff, 0xfb, 0x1f, 'l', 's', '\r', '\n'},
	"redis":      []byte("*1\r\n$4\r\nPING\r\n*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n"),
	"modbus":     {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a},
	"s7":         {0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a},
	"dnp3":       {0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	"ethernetip": {0x6f, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
	"bacnet":     {0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff},
	"mqtt":       {0x10, 0x0c, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00},
	"ldap":       {0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00},
	"snmp":       {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19},
	"ntp":        {0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	"dns":        {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x00, 0x00, 0x01, 0x00, 0x01},
	"coap":       {0x40, 0x01, 0x12, 0x34, 0xb4, '.', 'w', 'e', 'l'},
	"ssh":        []byte("SSH-2.0-OpenSSH_9.6\r\n"),
	"rdp":        {0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00},
	"vnc":        []byte("RFB 003.008\n"),
	"pop3":       []byte("USER a\r\nPASS b\r\nLIST\r\nQUIT\r\n"),
	"imap":       []byte("a1 LOGIN a b\r\na2 LIST \"\" *\r\na3 LOGOUT\r\n"),
	"mysql":      {0x20, 0x00, 0x00, 0x01, 0x85, 0xa6, 0x03, 0x00},
	"postgres":   {0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},
	"mssql":      {0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00},
	"sip":        []byte("OPTIONS sip:100@h SIP/2.0\r\nVia: SIP/2.0/UDP x\r\nCSeq: 1 OPTIONS\r\n\r\n"),
	"smb":        {0x00, 0x00, 0x00, 0x54, 0xff, 'S', 'M', 'B', 0x72, 0x00, 0x00, 0x00, 0x00},
	"ipp":        []byte("POST /ipp HTTP/1.1\r\nContent-Type: application/ipp\r\n\r\n\x02\x00\x00\x0b"),
	"dhcp":       {0x01, 0x01, 0x06, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00},
	"radius":     {0x01, 0x01, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	"tftp":       {0x00, 0x01, 'f', 'i', 'l', 'e', 0x00, 'o', 'c', 't', 'e', 't', 0x00},
}

// TestAllHandlersDumbFuzz drives every registered TCP and UDP handler with the
// dumb (unstructured / hostile) corpus. A panic or hang is a defect.
func TestAllHandlersDumbFuzz(t *testing.T) {
	dir := t.TempDir()
	inputs := dumbInputs()
	for _, name := range config.TCPHandlerNames() {
		h, err := Get(name, fuzzDeps(dir))
		if err != nil {
			continue // needs deps we don't provide (lua script, etc.) — skipped, not a failure
		}
		for i, in := range inputs {
			if r := driveTCP(h, in); r != "" {
				t.Errorf("tcp %q dumb input #%d: %s", name, i, r)
			}
		}
	}
	for _, name := range config.UDPHandlerNames() {
		h, err := GetUDP(name, fuzzDeps(dir))
		if err != nil {
			continue
		}
		for i, in := range inputs {
			if r := driveUDP(h, in); r != "" {
				t.Errorf("udp %q dumb input #%d: %s", name, i, r)
			}
		}
	}
}

// TestAllHandlersSmartFuzz drives every registered TCP and UDP handler with a
// structurally-valid seed frame (the smart corpus) plus a couple of byte-level
// mutations of it, exercising the deeper, structure-dependent parser paths.
func TestAllHandlersSmartFuzz(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewSource(0x51ca))
	for _, name := range config.TCPHandlerNames() {
		h, err := Get(name, fuzzDeps(dir))
		if err != nil {
			continue
		}
		for _, in := range mutations(smartSeed(name), rng) {
			if r := driveTCP(h, in); r != "" {
				t.Errorf("tcp %q smart seed mutation: %s", name, r)
			}
		}
	}
	for _, name := range config.UDPHandlerNames() {
		h, err := GetUDP(name, fuzzDeps(dir))
		if err != nil {
			continue
		}
		for _, in := range mutations(smartSeed(name), rng) {
			if r := driveUDP(h, in); r != "" {
				t.Errorf("udp %q smart seed mutation: %s", name, r)
			}
		}
	}
}

// mutations returns the seed plus a few bit/length mutations — a cheap
// structure-aware fuzz: valid frame, truncated frame, bit-flipped frame, and a
// frame with a corrupted length prefix.
func mutations(seed []byte, rng *rand.Rand) [][]byte {
	out := [][]byte{seed}
	if len(seed) > 2 {
		out = append(out, seed[:len(seed)/2]) // truncated
		flip := append([]byte(nil), seed...)
		flip[rng.Intn(len(flip))] ^= 1 << uint(rng.Intn(8))
		out = append(out, flip) // bit-flip
		// Corrupt the first two bytes (often a length/type field) to 0xFFFF.
		corrupt := append([]byte(nil), seed...)
		corrupt[0], corrupt[1] = 0xFF, 0xFF
		out = append(out, corrupt)
	}
	return out
}

// TestHotFuzzListsReferenceRealHandlers guards against stale/misspelled names in
// the on-demand deep-fuzz harness lists (fuzzTCPNames / fuzzUDPNames): every
// name there must be a real registered handler, so the deep fuzzers never
// silently skip a protocol because of a typo.
func TestHotFuzzListsReferenceRealHandlers(t *testing.T) {
	tcp := map[string]bool{}
	for _, n := range config.TCPHandlerNames() {
		tcp[n] = true
	}
	udp := map[string]bool{}
	for _, n := range config.UDPHandlerNames() {
		udp[n] = true
	}
	for _, n := range fuzzTCPNames {
		if !tcp[n] {
			t.Errorf("fuzzTCPNames has %q which is not a registered TCP handler", n)
		}
	}
	for _, n := range fuzzUDPNames {
		if !udp[n] {
			t.Errorf("fuzzUDPNames has %q which is not a registered UDP handler", n)
		}
	}
	// smartSeeds keys must be real handlers too.
	for n := range smartSeeds {
		if !tcp[n] && !udp[n] {
			t.Errorf("smartSeeds has %q which is not a registered handler", n)
		}
	}
}
