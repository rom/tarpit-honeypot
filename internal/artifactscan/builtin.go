package artifactscan

import "fmt"

// builtinRules is the default rule set: practical, low-false-positive traits
// for the artifacts a honeypot actually captures (droppers, stagers, packers,
// webshells, ransomware notes, recon tooling). Authored in the same YARA
// subset the .yar loader accepts, so the built-ins also exercise the parser.
const builtinRuleSource = `
rule PE_Packed_UPX : packer {
    meta:
        description = "UPX-packed PE/ELF"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upxbang = "UPX!"
    condition:
        2 of them
}

rule Embedded_PE_In_NonPE : dropper {
    meta:
        description = "MZ/PE header embedded in a script or archive payload"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
        $stub = "This program cannot be run in DOS mode"
    condition:
        $stub and $pe
}

rule Shell_Dropper : dropper {
    meta:
        description = "download-and-execute shell dropper"
    strings:
        $wget = "wget " nocase
        $curl = "curl " nocase
        $chmod = "chmod +x" nocase
        $sh = "/bin/sh"
        $tmp = "/tmp/"
    condition:
        ($wget or $curl) and ($chmod or $sh or $tmp)
}

rule PowerShell_Encoded : dropper {
    meta:
        description = "encoded/obfuscated PowerShell stager"
    strings:
        $enc = "-enc" nocase
        $eb = "-EncodedCommand" nocase
        $iex = "IEX(" nocase
        $dl = "DownloadString" nocase
        $hidden = "-w hidden" nocase
    condition:
        any of ($enc, $eb) or ($iex and $dl) or $hidden
}

rule Webshell_PHP : webshell {
    meta:
        description = "PHP webshell command-exec primitives"
    strings:
        $eval = "eval(" nocase
        $b64 = "base64_decode" nocase
        $sys = "system(" nocase
        $shell = "shell_exec" nocase
        $req = "$_REQUEST"
        $post = "$_POST"
    condition:
        ($eval or $sys or $shell) and ($b64 or $req or $post)
}

rule Ransomware_Note : ransomware {
    meta:
        description = "ransom note / extortion language"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
        $d = ".onion" nocase
    condition:
        $a or ($c and ($b or $d))
}

rule Linux_Reverse_Shell : c2 {
    meta:
        description = "reverse-shell one-liners"
    strings:
        $bash = "/dev/tcp/"
        $nc = "nc -e" nocase
        $mkfifo = "mkfifo /tmp"
        $py = "socket.socket" nocase
        $pty = "pty.spawn" nocase
    condition:
        $bash or $nc or $mkfifo or ($py and $pty)
}

rule Credential_Theft : credaccess {
    meta:
        description = "credential / keystore access strings"
        severity = "high"
    strings:
        $a = "/etc/shadow"
        $b = "SAM\\Domains\\Account" nocase
        $c = "wallet.dat"
        $d = "Login Data"
        $e = "id_rsa"
    condition:
        2 of them
}

rule XOR_Decoder_Stub : obfuscation {
    meta:
        description = "x86 XOR-decoder + GetPC stub"
        severity = "high"
    strings:
        $getpc = { E8 00 00 00 00 }
        $xor = { 31 C0 }
        $loop = { E2 ?? }
    condition:
        $getpc and $xor and $loop
}

rule CobaltStrike_Beacon : c2 {
    meta:
        description = "Cobalt Strike Beacon loader/config markers"
    strings:
        $rl = "ReflectiveLoader"
        $b1 = "beacon.dll" nocase
        $b2 = "beacon.x64.dll" nocase
        $b3 = "%s as %s\\%s: %d"
        $b4 = "Could not connect to pipe"
        $b5 = "%%IMPORT%%"
    condition:
        $rl and 1 of ($b1, $b2, $b3, $b4, $b5)
}

rule Meterpreter_Payload : c2 {
    meta:
        description = "Metasploit Meterpreter stdapi / core channel markers"
    strings:
        $a = "metsrv"
        $b = "stdapi_"
        $c = "core_channel_open"
        $d = "PACKET_TYPE_"
        $e = "ReflectiveLoader"
    condition:
        2 of them
}

rule XMRig_Miner : coinminer {
    meta:
        description = "XMRig / cryptonight / randomx coin miner"
    strings:
        $x = "xmrig" nocase
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $d = "--donate-level" nocase
        $c = "cryptonight" nocase
        $r = "randomx" nocase
    condition:
        $x or ((1 of ($s1, $s2)) and (1 of ($d, $c, $r)))
}

rule JSP_Webshell : webshell {
    meta:
        description = "JSP webshell command execution"
    strings:
        $exec = "Runtime.getRuntime().exec"
        $proc = "ProcessBuilder"
        $param = "getParameter"
    condition:
        ($exec or $proc) and $param
}

rule ASPX_Webshell : webshell {
    meta:
        description = "ASP.NET webshell command execution"
    strings:
        $proc = "System.Diagnostics.Process"
        $start = "ProcessStartInfo"
        $req1 = "Request.Item"
        $req2 = "Request.Form"
        $req3 = "Request.QueryString"
        $cmd = "cmd.exe" nocase
    condition:
        (1 of ($proc, $start)) and (1 of ($req1, $req2, $req3, $cmd))
}

rule IoT_Botnet_Commands : botnet {
    meta:
        description = "Mirai / Gafgyt IoT botnet flood-command strings"
    strings:
        $a = "TSource Engine Query"
        $b = "GETLOCALIP"
        $c = "HTTPFLOOD"
        $d = "UDPFLOOD"
        $e = "/dev/watchdog"
        $f = "/bin/busybox"
    condition:
        2 of them
}

rule Linux_Cron_Persistence : persistence {
    meta:
        description = "cron/reboot persistence paired with remote fetch or reverse shell"
    strings:
        $cron = "@reboot"
        $crontab = "crontab -"
        $cronetc = "/etc/cron"
        $wget = "wget " nocase
        $curl = "curl " nocase
        $rev = "/dev/tcp/"
    condition:
        (1 of ($cron, $crontab, $cronetc)) and (1 of ($wget, $curl, $rev))
}

rule Sandbox_Evasion : evasion {
    meta:
        description = "VM / sandbox / debugger evasion strings"
        severity = "medium"
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "VirtualBox" nocase
        $d = "vmware" nocase
        $e = "SbieDll.dll" nocase
        $f = "wine_get_unix_file_name"
        $g = "vboxservice" nocase
    condition:
        2 of them
}

rule PE_Process_Injection_APIs : injection {
    meta:
        description = "classic CreateRemoteThread process-injection import triad"
    condition:
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

rule PE_Dynamic_API_Resolution : loader {
    meta:
        description = "PE that resolves APIs at runtime and flips memory to RWX (loader/packer trait)"
        severity = "high"
    condition:
        pe.imports("kernel32.dll", "LoadLibraryA") and
        pe.imports("kernel32.dll", "GetProcAddress") and
        pe.imports("kernel32.dll", "VirtualProtect")
}
`

// builtinRules is parsed once at init. A parse failure of the built-in source
// is a programming error, so it panics — the test suite catches it.
var builtinRules = mustParseBuiltins()

func mustParseBuiltins() []Rule {
	rules, errs := ParseRules(builtinRuleSource)
	if len(errs) > 0 {
		panic(fmt.Sprintf("artifactscan: built-in rules failed to compile: %v", errs))
	}
	return rules
}
