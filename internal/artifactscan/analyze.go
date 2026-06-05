package artifactscan

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Limits keep a report bounded regardless of artifact size.
const (
	maxStrings      = 120
	minStringLen    = 6
	maxIOCsPerKind  = 32
	maxSections     = 64
	maxImports      = 256
	maxSuspicious   = 32
	packedEntropy   = 7.2
	sectionSampleKB = 256 // per-section bytes hashed for entropy
)

// Report is the static-analysis result for one artifact.
type Report struct {
	SHA256       string    `json:"sha256"`
	Size         int       `json:"size"`
	Format       string    `json:"format"`        // elf|pe|macho|zip|script|shellcode|data
	FormatDetail string    `json:"format_detail"` // human description
	Arch         string    `json:"arch,omitempty"`
	Entropy      float64   `json:"entropy"`
	Packed       bool      `json:"packed,omitempty"`
	Packer       string    `json:"packer,omitempty"`
	Sections     []Section `json:"sections,omitempty"`
	Imports      []string  `json:"imports,omitempty"` // libraries / DLLs
	Strings      []string  `json:"strings,omitempty"`
	IOCs         IOCs      `json:"iocs,omitempty"`
	Suspicious   []string  `json:"suspicious,omitempty"` // human-readable trait findings
	YaraMatches  []Match   `json:"yara_matches,omitempty"`
	// KnownMalware is set when the artifact's SHA-256 matches a loaded
	// known-malware hash set (abuse.ch MalwareBazaar / ThreatFox); Family is
	// the attributed malware family when the set carried one.
	KnownMalware bool   `json:"known_malware,omitempty"`
	Family       string `json:"family,omitempty"`
	// ArchiveExecutable is set when the artifact is an archive (zip/jar/apk)
	// that contains an executable member — a classic malware-in-a-zip drop.
	ArchiveExecutable     bool   `json:"archive_executable,omitempty"`
	ArchiveExecutableName string `json:"archive_executable_name,omitempty"`
}

// Section is one parsed section/segment with its entropy.
type Section struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy,omitempty"`
}

// Analyze runs static analysis on data, returning a structured report. It is
// pure and never executes anything. yaraMatches are added when an Engine is
// supplied via AnalyzeWith.
func Analyze(data []byte) Report {
	return AnalyzeWith(data, nil)
}

// AnalyzeWith runs Analyze and additionally evaluates eng's rules.
func AnalyzeWith(data []byte, eng *Engine) Report {
	r := Report{
		Size:    len(data),
		Entropy: round2(shannonEntropy(data)),
	}
	sum := sha256.Sum256(data)
	r.SHA256 = hex.EncodeToString(sum[:])

	r.Format, r.FormatDetail = detectFormat(data)
	switch r.Format {
	case "elf":
		analyzeELF(data, &r)
	case "pe":
		analyzePE(data, &r)
	case "macho":
		analyzeMachO(data, &r)
	case "zip":
		analyzeZip(data, &r)
	}

	r.Strings = extractStrings(data, minStringLen, maxStrings)
	r.IOCs = extractIOCs(r.Strings, maxIOCsPerKind)
	r.Suspicious = suspiciousTraits(r)
	if r.ArchiveExecutable {
		r.Suspicious = append(r.Suspicious, "archive contains executable: "+r.ArchiveExecutableName)
	}

	// Whole-file packer heuristic (executables only — archives and media are
	// legitimately high-entropy).
	if isExecutable(r.Format) && r.Entropy >= packedEntropy && r.Packer == "" {
		r.Packed = true
		r.Packer = "high-entropy"
	}

	if eng != nil {
		r.YaraMatches = eng.Scan(data)
		if fam, known := eng.lookupHash(r.SHA256); known {
			r.KnownMalware = true
			r.Family = fam
		}
	}
	return r
}

// detectFormat classifies the artifact by magic bytes.
func detectFormat(b []byte) (format, detail string) {
	switch {
	case len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F':
		return "elf", "ELF executable"
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' && bytes.Contains(b, []byte("PE\x00\x00")):
		return "pe", "PE executable (Windows)"
	case len(b) >= 4 && isMachOMagic(b):
		return "macho", "Mach-O executable (macOS)"
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 0x03 && b[3] == 0x04:
		return "zip", "ZIP/JAR/APK/OOXML archive"
	case len(b) >= 2 && b[0] == '#' && b[1] == '!':
		return "script", "interpreter script"
	}
	return "data", "unclassified data"
}

func isMachOMagic(b []byte) bool {
	be := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	switch be {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA:
		return true
	}
	return false
}

func isExecutable(format string) bool {
	switch format {
	case "elf", "pe", "macho":
		return true
	}
	return false
}

func analyzeELF(data []byte, r *Report) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer f.Close()
	r.Arch = f.Machine.String()
	r.FormatDetail = fmt.Sprintf("ELF %s %s, %s", f.Class, f.Type, f.Machine)
	if libs, err := f.ImportedLibraries(); err == nil {
		r.Imports = capStrings(libs, maxImports)
	}
	for _, s := range f.Sections {
		if len(r.Sections) >= maxSections {
			break
		}
		sec := Section{Name: s.Name, Size: s.Size}
		if d := sectionData(s.Open(), s.Size); d != nil {
			sec.Entropy = round2(shannonEntropy(d))
			if isCodeOrPacked(s.Name) && sec.Entropy >= packedEntropy {
				r.Packed = true
			}
		}
		r.Sections = append(r.Sections, sec)
	}
	if bytes.Contains(data, []byte("UPX!")) {
		r.Packed, r.Packer = true, "UPX"
	}
}

func analyzePE(data []byte, r *Report) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer f.Close()
	r.Arch = peMachine(f.Machine)
	bits := "32-bit"
	if f.Machine == pe.IMAGE_FILE_MACHINE_AMD64 || f.Machine == pe.IMAGE_FILE_MACHINE_ARM64 {
		bits = "64-bit"
	}
	r.FormatDetail = fmt.Sprintf("PE %s %s", bits, r.Arch)
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		r.Imports = capStrings(libs, maxImports)
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		r.Imports = capStrings(append(r.Imports, syms...), maxImports)
	}
	for _, s := range f.Sections {
		if len(r.Sections) >= maxSections {
			break
		}
		sec := Section{Name: s.Name, Size: uint64(s.Size)}
		if d, err := s.Data(); err == nil {
			if len(d) > sectionSampleKB<<10 {
				d = d[:sectionSampleKB<<10]
			}
			sec.Entropy = round2(shannonEntropy(d))
			if isCodeOrPacked(s.Name) && sec.Entropy >= packedEntropy {
				r.Packed = true
			}
		}
		r.Sections = append(r.Sections, sec)
	}
	if bytes.Contains(data, []byte("UPX!")) {
		r.Packed, r.Packer = true, "UPX"
	}
}

func analyzeMachO(data []byte, r *Report) {
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer f.Close()
	r.Arch = f.Cpu.String()
	r.FormatDetail = fmt.Sprintf("Mach-O %s %s", f.Type, f.Cpu)
	if libs, err := f.ImportedLibraries(); err == nil {
		r.Imports = capStrings(libs, maxImports)
	}
	for _, s := range f.Sections {
		if len(r.Sections) >= maxSections {
			break
		}
		sec := Section{Name: s.Seg + "," + s.Name, Size: s.Size}
		if d := sectionData(s.Open(), s.Size); d != nil {
			sec.Entropy = round2(shannonEntropy(d))
		}
		r.Sections = append(r.Sections, sec)
	}
}

func analyzeZip(data []byte, r *Report) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	var names []string
	hasClass, hasManifest, hasDex := false, false, false
	for _, f := range zr.File {
		if len(names) < maxImports {
			names = append(names, f.Name)
		}
		switch {
		case strings.HasSuffix(f.Name, ".class"):
			hasClass = true
		case f.Name == "META-INF/MANIFEST.MF":
			hasManifest = true
		case f.Name == "classes.dex":
			hasDex = true
		}
		if !r.ArchiveExecutable && zipEntryExecutable(f) {
			r.ArchiveExecutable = true
			r.ArchiveExecutableName = f.Name
		}
	}
	r.Imports = names // archive entry names
	switch {
	case hasDex:
		r.FormatDetail = "Android APK"
	case hasClass && hasManifest:
		r.FormatDetail = "Java JAR archive"
	case hasManifest:
		r.FormatDetail = "ZIP archive (signed/manifest)"
	}
}

// zipEntryExecutable reports whether an archive member is an executable — by a
// dangerous extension or by its real magic bytes (so a renamed .jpg that is
// actually a PE/ELF is still caught). Only the first 4 bytes are read, so a zip
// bomb can't blow up the check.
func zipEntryExecutable(f *zip.File) bool {
	n := strings.ToLower(f.Name)
	for _, ext := range []string{".exe", ".dll", ".scr", ".com", ".elf", ".so", ".sys", ".cpl", ".ocx"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	rc, err := f.Open()
	if err != nil {
		return false
	}
	defer rc.Close()
	var magic [4]byte
	got, _ := io.ReadFull(rc, magic[:])
	b := magic[:got]
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		return true
	case len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F':
		return true
	case len(b) >= 4 && isMachOMagic(b):
		return true
	}
	return false
}

// sectionData reads up to sectionSampleKB from a section reader.
func sectionData(rd interface {
	Read([]byte) (int, error)
}, size uint64) []byte {
	if size == 0 {
		return nil
	}
	n := int(size)
	if n > sectionSampleKB<<10 {
		n = sectionSampleKB << 10
	}
	buf := make([]byte, n)
	read := 0
	for read < n {
		m, err := rd.Read(buf[read:])
		read += m
		if err != nil {
			break
		}
	}
	return buf[:read]
}

func isCodeOrPacked(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "text") || strings.Contains(n, "code") ||
		strings.HasPrefix(n, "upx") || n == ".data" || n == ".rdata"
}

// suspiciousAPIs maps notable imported API / library names to a finding.
var suspiciousAPIs = map[string]string{
	"virtualalloc":          "allocates executable memory (VirtualAlloc)",
	"virtualprotect":        "changes memory protections (VirtualProtect)",
	"writeprocessmemory":    "writes to another process (WriteProcessMemory)",
	"createremotethread":    "remote thread injection (CreateRemoteThread)",
	"loadlibrary":           "dynamic library loading (LoadLibrary)",
	"getprocaddress":        "dynamic API resolution (GetProcAddress)",
	"winexec":               "process execution (WinExec)",
	"shellexecute":          "process execution (ShellExecute)",
	"urldownloadtofile":     "downloads a file (URLDownloadToFile)",
	"internetopen":          "outbound HTTP (WinINet)",
	"wininet":               "outbound HTTP (WinINet)",
	"cryptencrypt":          "cryptographic encryption (CryptEncrypt)",
	"regsetvalue":           "registry persistence (RegSetValue)",
	"setwindowshookex":      "keystroke/hook installation (SetWindowsHookEx)",
	"adjusttokenprivileges": "privilege escalation (AdjustTokenPrivileges)",
	"ptrace":                "anti-debug / injection (ptrace)",
	"mprotect":              "changes memory protections (mprotect)",
	"libpcap":               "raw packet capture (libpcap)",
}

// suspiciousStrings are notable substrings in extracted strings.
var suspiciousStrings = []struct{ sub, why string }{
	{"powershell -e", "encoded PowerShell command"},
	{"/bin/sh", "shell invocation"},
	{"cmd.exe", "Windows shell invocation"},
	{"schtasks", "scheduled-task persistence"},
	{"crontab", "cron persistence"},
	{".onion", "Tor hidden-service C2"},
	{"-----begin", "embedded key/certificate"},
	{"your files have been encrypted", "ransomware note"},
}

// suspiciousTraits derives human-readable findings from imports and strings.
func suspiciousTraits(r Report) []string {
	var out []string
	add := func(s string) {
		for _, e := range out {
			if e == s {
				return
			}
		}
		if len(out) < maxSuspicious {
			out = append(out, s)
		}
	}
	for _, imp := range r.Imports {
		l := strings.ToLower(imp)
		for api, why := range suspiciousAPIs {
			if strings.Contains(l, api) {
				add(why)
			}
		}
	}
	for _, s := range r.Strings {
		l := strings.ToLower(s)
		for _, ss := range suspiciousStrings {
			if strings.Contains(l, ss.sub) {
				add(ss.why)
			}
		}
	}
	sort.Strings(out)
	return out
}

func peMachine(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "i386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	}
	return fmt.Sprintf("machine-0x%x", m)
}

func capStrings(in []string, max int) []string {
	out := dedupCap(in, max)
	return out
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
