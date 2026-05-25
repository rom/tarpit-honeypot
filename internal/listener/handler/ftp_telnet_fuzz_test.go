package handler

// Fuzz targets for the FTP + telnet work. "Dumb" targets feed protocol-unaware
// bytes and assert the parsers/handlers never panic, hang, or exceed their
// bounds. "Smart" targets seed with protocol-valid structures (IAC option
// sub-negotiations, NEW-ENVIRON bodies, FTP navigation scripts) so mutation
// explores deep valid-state paths, and check real invariants (determinism, the
// virtual-filesystem containment property, framing bounds).
//
// The FTP control handler is not driven end-to-end here because its PASV data
// path blocks on Accept without a connecting client; FuzzTCPHandlers already
// drives ftp/ftp_files end-to-end with raw bytes. Telnet opens no sockets, so
// it is fuzzed directly.
//
// Run one for real, e.g.:
//
//	go test ./internal/listener/handler -run x -fuzz FuzzTelnetNegotiationSmart -fuzztime 60s

import (
	"bufio"
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// --- dumb (protocol-unaware) ------------------------------------------------

func FuzzTelnetHandlerDumb(f *testing.F) {
	f.Add([]byte("admin\r\nsecret\r\n"))
	f.Add([]byte{0xff, 0xfd, 0x01, 0xff, 0xfb, 0x18})
	f.Add([]byte{0xff, 0xfa, 0x18, 0x00, 'x', 0xff, 0xf0, 'u', '\r', '\n'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xfa, 0xfa, 0xf0})
	f.Add([]byte{})
	cfg := config.Listener{ReadTimeout: 200 * time.Millisecond, ReadBytes: 4096}
	f.Fuzz(func(t *testing.T, data []byte) {
		conn := &fuzzConn{data: data}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = (&telnet{}).Handle(ctx, conn, cfg) // a panic/hang fails the input
	})
}

func FuzzFTPReadLineDumb(f *testing.F) {
	f.Add([]byte("USER bob\r\n"))
	f.Add([]byte(strings.Repeat("A", 1000)))
	f.Add([]byte("no newline ever"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		line, _ := readFTPLine(bufio.NewReader(bytes.NewReader(data)), 64)
		if len(line) > 64 {
			t.Fatalf("readFTPLine returned %d bytes; the cap was 64", len(line))
		}
	})
}

func FuzzParseNewEnvironDumb(f *testing.F) {
	f.Add([]byte{0, 'A', 1, 'b'})
	f.Add([]byte{2, 2, 2, 2})
	f.Add([]byte{0, 0, 1, 1, 3, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		out := parseNewEnviron(data) // must terminate and not panic
		if _, ok := out[""]; ok {
			t.Fatalf("parseNewEnviron produced an empty key from %x", data)
		}
	})
}

func FuzzParseTelnetSubnegDumb(f *testing.F) {
	f.Add([]byte{0x1f, 0x00, 0x50, 0x00, 0x18})
	f.Add([]byte{0x27, 0x00, 0x00, 'A', 1, 'b'})
	f.Add([]byte{0x18, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		res := &Result{Meta: map[string]any{}}
		parseTelnetSubneg(data, res) // no panic on any shape
	})
}

func FuzzDataCmdIPDumb(f *testing.F) {
	f.Add("1,2,3,4,5,6")
	f.Add("|1|10.0.0.1|2121|")
	f.Add("")
	f.Fuzz(func(t *testing.T, arg string) {
		_ = dataCmdIP("PORT", arg)
		_ = dataCmdIP("EPRT", arg)
		_ = dataCmdIP("WAT", arg)
	})
}

func FuzzResolveDirDumb(f *testing.F) {
	f.Add("../../etc")
	f.Add("/a/b/../c")
	f.Add("")
	f.Add(strings.Repeat("../", 500) + "x")
	f.Fuzz(func(t *testing.T, arg string) {
		// A fixed, already-clean cwd: the result must stay absolute and must
		// never retain a ".." segment (virtual-fs containment).
		got := resolveDir("/start", arg)
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("resolveDir(/start,%q)=%q is not absolute", arg, got)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == ".." {
				t.Fatalf("resolveDir(/start,%q)=%q leaked a .. segment", arg, got)
			}
		}
	})
}

// --- smart (protocol-aware) -------------------------------------------------

func FuzzTelnetNegotiationSmart(f *testing.F) {
	concat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	ttype := concat([]byte{telIAC, telSB, telOptTType, 0x00}, []byte("xterm-256color"), []byte{telIAC, telSE})
	naws := []byte{telIAC, telSB, telOptNAWS, 0x00, 0x84, 0x00, 0x2b, telIAC, telSE}
	newenv := concat([]byte{telIAC, telSB, telOptNewEnv, 0x00, 0x00}, []byte("USER"), []byte{0x01}, []byte("root"), []byte{telIAC, telSE})
	wills := []byte{telIAC, telWILL, telOptTType, telIAC, telWILL, telOptNAWS, telIAC, telWILL, telOptNewEnv, telIAC, telDO, telOptEcho}
	f.Add(concat(wills, ttype, naws, newenv, []byte("admin\r\npassw0rd\r\n")))
	f.Add(concat(ttype, []byte("root\r\n"), []byte("toor\r\n")))
	// escaped NUL inside a NEW-ENVIRON value, plus an escaped IAC in a subneg.
	f.Add(concat([]byte{telIAC, telSB, telOptNewEnv, 0x00, 0x00}, []byte("X"), []byte{0x01, 0x02, 0x00}, []byte{telIAC, telIAC}, []byte{telIAC, telSE}, []byte("u\r\np\r\n")))
	cfg := config.Listener{ReadTimeout: 200 * time.Millisecond, ReadBytes: 4096}
	f.Fuzz(func(t *testing.T, data []byte) {
		conn := &fuzzConn{data: data}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = (&telnet{}).Handle(ctx, conn, cfg)
	})
}

func FuzzNewEnvironSmart(f *testing.F) {
	f.Add([]byte{0, 'U', 'S', 'E', 'R', 1, 'r', 'o', 'o', 't'})
	f.Add([]byte{0, 'A', 1, '1', 0, 'B', 1, '2', 3, 'C', 1, '3'})
	f.Add([]byte{0, 'X', 1, 2, 0, 'y'}) // escaped boundary byte in value
	f.Fuzz(func(t *testing.T, data []byte) {
		a := parseNewEnviron(data)
		b := parseNewEnviron(append([]byte(nil), data...))
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("parseNewEnviron is non-deterministic for %x", data)
		}
		for k := range a {
			if k == "" {
				t.Fatalf("empty variable name from %x", data)
			}
		}
	})
}

func FuzzTelnetSubnegSmart(f *testing.F) {
	f.Add([]byte{telOptNAWS, 0x00, 0x50, 0x00, 0x18})
	f.Add(append([]byte{telOptTType, 0x00}, []byte("vt100")...))
	f.Add(append([]byte{telOptNewEnv, 0x00, 0x00}, []byte("HOME\x01/root")...))
	f.Fuzz(func(t *testing.T, data []byte) {
		r1 := &Result{Meta: map[string]any{}}
		r2 := &Result{Meta: map[string]any{}}
		parseTelnetSubneg(data, r1)
		parseTelnetSubneg(data, r2)
		if !reflect.DeepEqual(r1.Meta, r2.Meta) {
			t.Fatalf("parseTelnetSubneg is non-deterministic for %x", data)
		}
		// A well-formed NAWS sub-negotiation (>=5 bytes) must yield a window size.
		if len(data) >= 5 && data[0] == telOptNAWS {
			if _, ok := r1.Meta["window_size"].(string); !ok {
				t.Fatalf("a 5+ byte NAWS subneg produced no window_size: %x", data)
			}
		}
	})
}

func FuzzFTPNavigationSmart(f *testing.F) {
	f.Add("pub\nsub\n..\n/etc\n../../root")
	f.Add("a/b/c\n..\n.\n")
	f.Add("/\n/very/deep/path\n../../../../../../etc/shadow")
	f.Fuzz(func(t *testing.T, script string) {
		cwd := "/"
		for _, arg := range strings.Split(script, "\n") {
			_, a := splitFTPCmd("CWD " + arg)
			cwd = resolveDir(cwd, a)
			// Invariant: the working directory stays absolute and can never be
			// navigated out of the virtual root via traversal.
			if !strings.HasPrefix(cwd, "/") {
				t.Fatalf("cwd became relative: %q (after arg %q)", cwd, arg)
			}
			for _, seg := range strings.Split(cwd, "/") {
				if seg == ".." {
					t.Fatalf("cwd retained a .. segment: %q (after arg %q)", cwd, arg)
				}
			}
		}
	})
}
