package handler

// Fuzz targets for the protocol parsers across the handler set (beyond the
// ftp/telnet ones). The generic FuzzTCPHandlers / FuzzUDPHandlers already drive
// every handler's Handle() with raw bytes; these target the individual
// attacker-facing decoders so mutation explores them directly and so the smart
// targets can assert real invariants (in-bounds offsets, determinism, framing).
//
// "Dumb" = protocol-unaware bytes, the only contract being "never panic / hang /
// read out of bounds". "Smart" = seeded with protocol-valid structures.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzParseDNSQuerySmart -fuzztime 60s

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

// --- dumb: parsers must never panic / hang / read OOB ----------------------

func FuzzParseDNSQueryDumb(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Add(append(make([]byte, 12), 3, 'w', 'w', 'w', 0, 0, 1, 0, 1))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseDNSQuery(data) })
}

func FuzzParseLLMNRQueryDumb(f *testing.F) {
	f.Add([]byte{})
	f.Add(append(make([]byte, 12), 4, 'h', 'o', 's', 't', 0, 0, 1, 0, 1))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = parseLLMNRQuery(data) })
}

func FuzzParseNBNSQueryDumb(f *testing.F) {
	f.Add([]byte{})
	f.Add(append(make([]byte, 12), 32))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _, _ = parseNBNSQuery(data) })
}

func FuzzParseNTLMType3Dumb(f *testing.F) {
	f.Add([]byte("NTLMSSP\x00\x03\x00\x00\x00"))
	f.Add(make([]byte, 72))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = parseNTLMType3(data) })
}

func FuzzParseLogin7UserDumb(f *testing.F) {
	f.Add(make([]byte, 48))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		res := Result{Meta: map[string]any{}}
		parseLogin7(data, &res)
	})
}

func FuzzParsePgParamsDumb(f *testing.F) {
	f.Add([]byte("user\x00bob\x00\x00"))
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _ = parsePgParams(data) })
}

func FuzzExtractTNSDescriptorDumb(f *testing.F) {
	f.Add([]byte("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=x)))"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _ = extractTNSDescriptor(data) })
}

func FuzzExtractCookieDumb(f *testing.F) {
	f.Add([]byte("Cookie: mstshash=admin\r\n"))
	f.Add([]byte("Cookie: "))
	f.Fuzz(func(t *testing.T, data []byte) { _ = extractCookie(data) })
}

func FuzzHTTPRequestLineDumb(f *testing.F) {
	f.Add("GET /a?b=1 HTTP/1.1")
	f.Add("")
	f.Add("   ")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractMethod(line)
		_ = extractPath(line)
		_ = extractTarget(line)
	})
}

func FuzzBasicAuthDumb(f *testing.F) {
	f.Add("Authorization: Basic YWRtaW46cGFzcw==")
	f.Add("Basic !!!notbase64")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseBasicAuth(line)
		_, _, _ = decodeBasic(line)
	})
}

func FuzzReadRESPCommandDumb(f *testing.F) {
	f.Add([]byte("*1\r\n$4\r\nPING\r\n"))
	f.Add([]byte("PING\r\n"))
	f.Add([]byte("*999999\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readRESPCommand(bufio.NewReader(bytes.NewReader(data)))
	})
}

func FuzzSplitSMTPCmdDumb(f *testing.F) {
	f.Add("MAIL FROM:<a@b>")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) { _, _ = splitSMTPCmd(line) })
}

func FuzzParseIMAPLoginDumb(f *testing.F) {
	f.Add(`"bob" "hunter2"`)
	f.Add("a b c")
	f.Fuzz(func(t *testing.T, arg string) { _, _ = parseIMAPLogin(arg) })
}

func FuzzParseOIDDumb(f *testing.F) {
	f.Add(".1.3.6.1.2.1")
	f.Add("...")
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseOID(s) })
}

func FuzzParseLoginFormDumb(f *testing.F) {
	f.Add([]byte("username=admin&password=secret"))
	f.Add([]byte("="))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseLoginForm(data) })
}

// --- smart: protocol-valid seeds + invariants ------------------------------

func dnsQuerySeed() []byte {
	b := make([]byte, 12)
	b[5] = 1 // qdcount = 1
	b = append(b, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	b = append(b, 0x00, 0x01, 0x00, 0x01) // qtype A, qclass IN
	return b
}

func FuzzParseDNSQuerySmart(f *testing.F) {
	f.Add(dnsQuerySeed())
	f.Add(append(dnsQuerySeed(), 0xde, 0xad)) // trailing junk
	f.Fuzz(func(t *testing.T, data []byte) {
		q, ok := parseDNSQuery(data)
		if ok && (q.questionEnd < 12 || q.questionEnd > len(data)) {
			t.Fatalf("questionEnd %d out of [12,%d] for %x", q.questionEnd, len(data), data)
		}
	})
}

func nbnsQuerySeed() []byte {
	b := make([]byte, 12)
	b = append(b, 32)                               // first label length (always 32)
	b = append(b, bytes.Repeat([]byte("A"), 32)...) // encoded name (all 'A' => 0x00 bytes)
	b = append(b, 0)                                // null terminator
	b = append(b, 0x00, 0x20, 0x00, 0x01)           // qtype=NB, qclass=IN
	return b
}

func FuzzParseNBNSQuerySmart(f *testing.F) {
	f.Add(nbnsQuerySeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		enc, dec, _, ok := parseNBNSQuery(data)
		if !ok {
			return
		}
		if len(enc) != 32 {
			t.Fatalf("encoded name len %d; want 32", len(enc))
		}
		if !strings.Contains(dec, "<") {
			t.Fatalf("decoded name %q missing the <suffix> marker", dec)
		}
	})
}

func ntlmType3Seed() []byte {
	tok := make([]byte, 72)
	copy(tok, []byte("NTLMSSP\x00"))
	tok[8] = 3                                            // message type 3
	binary.LittleEndian.PutUint32(tok[60:64], 0x00000001) // NegotiateFlags: unicode
	binary.LittleEndian.PutUint16(tok[36:38], 8)          // UserName len
	binary.LittleEndian.PutUint16(tok[38:40], 8)          // UserName maxlen
	binary.LittleEndian.PutUint32(tok[40:44], 64)         // UserName offset
	copy(tok[64:72], []byte{'u', 0, 's', 0, 'e', 0, 'r', 0})
	return tok
}

func FuzzParseNTLMType3Smart(f *testing.F) {
	f.Add(ntlmType3Seed())
	f.Fuzz(func(t *testing.T, data []byte) {
		d1, u1, h1 := parseNTLMType3(data)
		d2, u2, h2 := parseNTLMType3(append([]byte(nil), data...))
		if d1 != d2 || u1 != u2 || h1 != h2 {
			t.Fatalf("parseNTLMType3 non-deterministic for %x", data)
		}
		if len(h1)%2 != 0 {
			t.Fatalf("NT-response hex is not byte-aligned: %q", h1)
		}
	})
}

func FuzzParsePgParamsSmart(f *testing.F) {
	f.Add([]byte("user\x00postgres\x00database\x00prod\x00\x00"))
	f.Add([]byte("k\x00v\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a := parsePgParams(data)
		b := parsePgParams(append([]byte(nil), data...))
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("parsePgParams non-deterministic for %x", data)
		}
		if _, ok := a[""]; ok {
			t.Fatalf("parsePgParams produced an empty key from %x", data)
		}
	})
}
