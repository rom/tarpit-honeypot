// Package payload harvests attacker-supplied artifacts from captured
// bytes: uploaded binaries / malware, raw or base64-wrapped shellcode,
// and ingress-tool-transfer URLs. It is detection + collection only —
// nothing is ever executed or fetched.
//
// Scan is pure (no I/O); the sensor persists the artifacts it returns to
// <data_dir>/payloads/ via Store when sensor.payloads.enabled is set.
// The classifier is conservative: file-magic and shellcode heuristics
// are tuned so benign banner-grab traffic doesn't trip them, while real
// dropped binaries / encoded stagers do.
package payload

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Kind classifies a harvested artifact.
const (
	KindELF       = "elf"
	KindPE        = "pe"
	KindMachO     = "macho"
	KindArchive   = "archive"
	KindScript    = "script"
	KindShellcode = "shellcode"
	KindBase64    = "base64-blob"
)

// Artifact is one harvested binary / script / shellcode blob.
type Artifact struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
	Detail string `json:"detail,omitempty"`
	// Bytes is the raw artifact (decoded if it was base64). The sensor
	// persists this and then drops it; it is never serialized to events.
	Bytes []byte `json:"-"`
}

// Finding is the result of scanning one captured blob.
type Finding struct {
	Markers   []string   // anomaly markers, e.g. "payload-elf", "payload-shellcode"
	Artifacts []Artifact // binaries / scripts / shellcode to persist
	URLs      []string   // ingress-tool-transfer URLs harvested from the blob
}

// Empty reports whether the scan found nothing of interest.
func (f Finding) Empty() bool {
	return len(f.Markers) == 0 && len(f.Artifacts) == 0 && len(f.URLs) == 0
}

// Scan inspects data (a captured request body, shell command, FTP/TFTP
// upload, …) and returns harvestable artifacts + ingress URLs. It also
// decodes embedded base64 blobs and re-scans them, so an
// `echo <b64> | base64 -d > x; chmod +x x` dropper is caught.
func Scan(data []byte) Finding {
	var f Finding
	if len(data) == 0 {
		return f
	}
	classifyInto(&f, data, false)

	// Harvest ingress URLs from the textual view.
	text := string(data)
	for _, u := range extractURLs(text) {
		f.URLs = appendUnique(f.URLs, u)
	}
	if len(f.URLs) > 0 {
		f.Markers = appendUnique(f.Markers, "payload-ingress-url")
	}

	// Decode long base64 runs and re-classify (catches base64-wrapped
	// ELF/PE/shellcode stagers). We only follow the first few large
	// blobs to bound work.
	decoded := 0
	for _, blob := range base64Blobs(text) {
		if decoded >= 4 {
			break
		}
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil || len(raw) < 16 {
			continue
		}
		decoded++
		before := len(f.Artifacts)
		classifyInto(&f, raw, true)
		if len(f.Artifacts) > before {
			f.Markers = appendUnique(f.Markers, "payload-base64-wrapped")
		}
	}
	return f
}

// classifyInto adds an artifact + marker for data when it matches a
// known binary magic or the shellcode heuristic. fromB64 marks that the
// bytes came from a decoded base64 blob (for the artifact detail).
func classifyInto(f *Finding, data []byte, fromB64 bool) {
	kind, detail := classify(data)
	if kind == "" {
		return
	}
	art := Artifact{
		Kind:   kind,
		SHA256: sha256Hex(data),
		Size:   len(data),
		Detail: detail,
		Bytes:  append([]byte(nil), data...),
	}
	if fromB64 {
		if art.Detail != "" {
			art.Detail += "; "
		}
		art.Detail += "base64-decoded"
	}
	f.Artifacts = append(f.Artifacts, art)
	f.Markers = appendUnique(f.Markers, "payload-"+kind)
	f.Markers = appendUnique(f.Markers, "malware-capture")
}

// classify returns the artifact kind + a short detail string for a byte
// blob, or "" when it isn't a recognized executable / archive / script
// / shellcode.
func classify(b []byte) (kind, detail string) {
	switch {
	case len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F':
		return KindELF, "ELF executable"
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' && containsBytes(b, []byte("PE\x00\x00")):
		return KindPE, "PE executable"
	case len(b) >= 4 && isMachO(b):
		return KindMachO, "Mach-O executable"
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 0x03 && b[3] == 0x04:
		return KindArchive, "zip/jar archive"
	case len(b) >= 2 && b[0] == '#' && b[1] == '!':
		return KindScript, "interpreter script (" + shebang(b) + ")"
	}
	if looksLikeShellcode(b) {
		return KindShellcode, "x86 shellcode heuristic"
	}
	return "", ""
}

func isMachO(b []byte) bool {
	be := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	switch be {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE:
		return true
	}
	return false
}

func shebang(b []byte) string {
	end := len(b)
	if end > 64 {
		end = 64
	}
	line := string(b[2:end])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// looksLikeShellcode applies conservative heuristics: a long NOP sled,
// or a buffer that is mostly non-printable AND carries several
// characteristic x86/x64 stager opcodes (GetPC, syscall, int 0x80,
// xor-zero, jmp/call-pop). Requires both signals so ordinary binary
// protocol payloads don't false-trigger.
func looksLikeShellcode(b []byte) bool {
	if len(b) < 24 {
		return false
	}
	// NOP sled: >= 16 consecutive 0x90.
	run := 0
	for _, c := range b {
		if c == 0x90 {
			run++
			if run >= 16 {
				return true
			}
		} else {
			run = 0
		}
	}
	// Opcode + entropy signal.
	nonPrint := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) || c >= 0x7f {
			nonPrint++
		}
	}
	ratio := float64(nonPrint) / float64(len(b))
	if ratio < 0.30 {
		return false
	}
	sigs := [][]byte{
		{0xe8, 0x00, 0x00, 0x00, 0x00}, // call $+5 (GetPC)
		{0x0f, 0x05},                   // syscall (x64)
		{0xcd, 0x80},                   // int 0x80 (x86 syscall)
		{0x31, 0xc0},                   // xor eax,eax
		{0x31, 0xdb},                   // xor ebx,ebx
		{0x6a, 0x0b},                   // push 0x0b (execve)
		{0x68, 0x2f, 0x2f, 0x73, 0x68}, // push "//sh"
		{0x2f, 0x62, 0x69, 0x6e, 0x2f}, // "/bin/"
	}
	hits := 0
	for _, s := range sigs {
		if containsBytes(b, s) {
			hits++
		}
	}
	return hits >= 2
}

// extractURLs pulls http(s)/ftp/tftp URLs out of text (download cradles,
// wget/curl args, PowerShell DownloadString targets).
func extractURLs(s string) []string {
	var out []string
	low := s
	for _, scheme := range []string{"http://", "https://", "ftp://", "tftp://"} {
		from := 0
		for {
			i := indexFold(low[from:], scheme)
			if i < 0 {
				break
			}
			start := from + i
			end := start
			for end < len(s) && !isURLTerminator(s[end]) {
				end++
			}
			u := s[start:end]
			if len(u) > len(scheme)+2 && len(u) <= 2048 {
				out = appendUnique(out, u)
			}
			from = end
			if from >= len(low) {
				break
			}
		}
	}
	return out
}

func isURLTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '"', '\'', '`', '<', '>', ')', '(', '|', ';', ',':
		return true
	}
	return false
}

// base64Blobs returns runs of >=64 base64-alphabet characters in s.
func base64Blobs(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() >= 64 {
			out = append(out, cur.String())
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z'), (c >= 'a' && c <= 'z'), (c >= '0' && c <= '9'), c == '+', c == '/', c == '=':
			cur.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return out
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return len(needle) == 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}
