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

rule MAL_njRAT : rat {
    meta:
        description = "njRAT/Bladabindi remote access trojan"
    strings:
        $a = "njRAT" nocase
        $b = "netsh firewall add allowedprogram"
        $c = "[kl]"
    condition:
        $a or 2 of them
}

rule MAL_AsyncRAT : rat {
    meta:
        description = "AsyncRAT .NET remote access trojan"
    strings:
        $a = "AsyncClient"
        $b = "AsyncRAT"
        $c = "Server Certificate"
    condition:
        1 of ($a, $b)
}

rule MAL_QuasarRAT : rat {
    meta:
        description = "Quasar RAT (and forks) remote access trojan"
    strings:
        $a = "DoUploadAndExecute"
        $b = "get_Keylogger"
        $c = "Quasar Server CA"
    condition:
        1 of them
}

rule MAL_Remcos : rat {
    meta:
        description = "Remcos commercial RAT"
    strings:
        $a = "Breaking-Security.Net" nocase
        $b = "Remcos"
        $c = "remcos restart"
    condition:
        $a or ($b and $c)
}

rule MAL_NanoCore : rat {
    meta:
        description = "NanoCore .NET RAT"
    strings:
        $a = "NanoCore Client"
        $b = "PluginCommand"
        $c = "ClientLoaderForm"
    condition:
        $a or ($b and $c)
}

rule MAL_DarkComet : rat {
    meta:
        description = "DarkComet RAT"
    strings:
        $a = "#KCMDDC"
        $b = "#BOT#OpenUrl"
        $c = "DarkComet" nocase
    condition:
        1 of ($a, $b) or $c
}

rule MAL_RedLine_Stealer : stealer {
    meta:
        description = "RedLine information stealer"
    strings:
        $a = "ScannedWallets"
        $b = "ScannedFiles"
        $c = "GetBrowsers"
    condition:
        2 of them
}

rule MAL_AgentTesla : stealer {
    meta:
        description = "Agent Tesla keylogger / stealer"
    strings:
        $a = "get_OfflineKeyloggerEnabled"
        $b = "PostScreenshot"
        $c = "Agent Tesla" nocase
    condition:
        1 of them
}

rule MAL_Lokibot : stealer {
    meta:
        description = "Loki / Lokibot credential stealer"
    strings:
        $a = "ckav.ru"
        $b = "fuckav.ru"
        $c = "Davinci"
    condition:
        1 of them
}

rule MAL_Emotet_Maldoc : dropper {
    meta:
        description = "Office macro auto-exec download-and-run dropper (Emotet-style)"
    strings:
        $a = "AutoOpen"
        $b = "Shell(Environ"
        $c = "powershell -e" nocase
        $d = "-EncodedCommand" nocase
    condition:
        $a and (1 of ($b, $c, $d))
}

rule MAL_TrickBot : banker {
    meta:
        description = "TrickBot module configuration markers"
    strings:
        $a = "<mcconf>"
        $b = "<servconf>"
        $c = "moduleconfig"
    condition:
        2 of them
}

rule TOOL_Mimikatz : credaccess {
    meta:
        description = "Mimikatz credential-dumping tool"
    strings:
        $a = "sekurlsa::logonpasswords"
        $b = "mimikatz" nocase
        $c = "gentilkiwi"
        $d = "kuhl_m_"
    condition:
        1 of them
}

rule TOOL_LaZagne : credaccess {
    meta:
        description = "LaZagne credential-recovery tool"
    strings:
        $a = "lazagne" nocase
        $b = "LaZagne.exe"
    condition:
        1 of them
}

rule TOOL_PowerSploit : offensive {
    meta:
        description = "PowerSploit offensive PowerShell module"
        severity = "high"
    strings:
        $a = "Invoke-Mimikatz"
        $b = "Invoke-Shellcode"
        $c = "Invoke-DllInjection"
        $d = "Invoke-ReflectivePEInjection"
    condition:
        1 of them
}

rule TOOL_Empire_Agent : c2 {
    meta:
        description = "PowerShell Empire / Starkiller agent"
        severity = "high"
    strings:
        $a = "Invoke-Empire"
        $b = "/login/process.php"
        $c = "System.Net.WebClient"
        $d = "[System.Convert]::FromBase64String"
    condition:
        $a or ($b and $c and $d)
}

rule TOOL_SharpHound : recon {
    meta:
        description = "SharpHound / BloodHound AD collector"
        severity = "high"
    strings:
        $a = "SharpHound"
        $b = "BloodHound"
        $c = "DCOnly"
    condition:
        1 of ($a, $b)
}

rule TOOL_Rubeus : credaccess {
    meta:
        description = "Rubeus Kerberos abuse toolkit"
        severity = "high"
    strings:
        $a = "Rubeus"
        $b = "asktgt"
        $c = "kerberoast"
    condition:
        $a or ($b and $c)
}

rule TOOL_Chisel_Tunnel : tunnel {
    meta:
        description = "Chisel TCP/UDP tunneling proxy"
        severity = "high"
    strings:
        $a = "jpillora/chisel"
        $b = "chisel"
        $c = "x-chisel"
    condition:
        $a or ($b and $c)
}

rule TOOL_Ngrok : tunnel {
    meta:
        description = "ngrok reverse tunnel client"
        severity = "high"
    strings:
        $a = "ngrok.io"
        $b = "ngrok-agent"
        $c = "tunnel.us.ngrok.com"
    condition:
        1 of them
}

rule TOOL_FRP_Proxy : tunnel {
    meta:
        description = "fast reverse proxy (frp) client/server"
        severity = "high"
    strings:
        $a = "frpc.ini"
        $b = "fatedier/frp"
        $c = "[common]"
        $d = "server_addr"
    condition:
        1 of ($a, $b) or ($c and $d)
}

rule TOOL_Sliver_Implant : c2 {
    meta:
        description = "Sliver C2 implant"
    strings:
        $a = "sliverpb"
        $b = "SliverRPC"
        $c = ".(*Sliver"
    condition:
        1 of them
}

rule TOOL_Havoc_Demon : c2 {
    meta:
        description = "Havoc framework Demon agent"
    strings:
        $a = "DemonGate"
        $b = "Havoc Framework"
        $c = "KaynLdr"
    condition:
        1 of them
}

rule TOOL_BruteRatel : c2 {
    meta:
        description = "Brute Ratel C4 badger"
    strings:
        $a = "badger_"
        $b = "BruteRatel"
        $c = "b-r-a-d-1"
    condition:
        1 of them
}

rule TOOL_PsExec : lateral {
    meta:
        description = "Sysinternals PsExec lateral-movement tool"
        severity = "high"
    strings:
        $a = "PSEXESVC"
        $b = "psexec" nocase
        $c = "Sysinternals"
    condition:
        $a or ($b and $c)
}

rule TOOL_WinPEAS : recon {
    meta:
        description = "PEASS-ng (winPEAS/linPEAS) privilege-escalation scanner"
        severity = "high"
    strings:
        $a = "winPEAS" nocase
        $b = "linpeas" nocase
        $c = "PEASS-ng"
    condition:
        1 of them
}

rule TOOL_Nishang : offensive {
    meta:
        description = "Nishang offensive PowerShell framework"
        severity = "high"
    strings:
        $a = "Invoke-PowerShellTcp"
        $b = "Nishang"
        $c = "Out-Minidump"
    condition:
        1 of them
}

rule TOOL_Covenant_Grunt : c2 {
    meta:
        description = "Covenant C2 Grunt implant"
    strings:
        $a = "GruntStager"
        $b = "Covenant"
        $c = "GruntHTTP"
    condition:
        1 of them
}

rule TOOL_Metasploit_Stager : shellcode {
    meta:
        description = "Metasploit x86/x64 block-API stager prologue"
    strings:
        $x86 = { FC E8 ?? 00 00 00 60 89 E5 }
        $x64 = { FC 48 83 E4 F0 E8 ?? 00 00 00 41 51 41 50 }
    condition:
        1 of them
}

rule TOOL_Potato_PrivEsc : privesc {
    meta:
        description = "Potato-family SeImpersonate privilege escalation tools"
        severity = "high"
    strings:
        $a = "JuicyPotato"
        $b = "RoguePotato"
        $c = "GodPotato"
        $d = "PrintSpoofer"
    condition:
        1 of them
}

rule WEBSHELL_ChinaChopper : webshell {
    meta:
        description = "China Chopper one-liner webshell"
    strings:
        $a = "eval(Request.Item" nocase
        $b = "<%eval request(" nocase
        $c = "@eval($_POST"
        $d = "execute(request(" nocase
    condition:
        1 of them
}

rule WEBSHELL_WSO : webshell {
    meta:
        description = "WSO PHP webshell"
    strings:
        $a = "WSO Shell"
        $b = "wsoEx"
        $c = "$default_action"
        $d = "wso_version"
    condition:
        2 of them
}

rule WEBSHELL_b374k : webshell {
    meta:
        description = "b374k PHP webshell"
    strings:
        $a = "b374k" nocase
    condition:
        $a
}

rule WEBSHELL_c99 : webshell {
    meta:
        description = "c99 PHP webshell"
    strings:
        $a = "c99shell" nocase
        $b = "!C99Shell"
    condition:
        1 of them
}

rule WEBSHELL_r57 : webshell {
    meta:
        description = "r57 PHP webshell"
    strings:
        $a = "r57shell" nocase
    condition:
        $a
}

rule WEBSHELL_Behinder : webshell {
    meta:
        description = "Behinder (rebeyond) encrypted webshell"
    strings:
        $a = "rebeyond"
        $b = "Behinder"
    condition:
        1 of them
}

rule WEBSHELL_Antsword : webshell {
    meta:
        description = "AntSword webshell client artifacts"
    strings:
        $a = "antSword"
        $b = "asenc("
    condition:
        1 of them
}

rule WEBSHELL_Weevely : webshell {
    meta:
        description = "Weevely PHP webshell"
    strings:
        $a = ".weevely"
        $b = "weevely"
    condition:
        1 of them
}

rule PACKER_VMProtect : packer {
    meta:
        description = "VMProtect-protected executable"
        severity = "medium"
    strings:
        $a = ".vmp0"
        $b = ".vmp1"
        $c = "VMProtect"
    condition:
        2 of them
}

rule PACKER_Themida : packer {
    meta:
        description = "Themida / WinLicense-protected executable"
        severity = "medium"
    strings:
        $a = ".themida"
        $b = ".winlice"
        $c = "Themida"
    condition:
        1 of them
}

rule PACKER_ASPack : packer {
    meta:
        description = "ASPack-packed executable"
        severity = "medium"
    strings:
        $a = ".aspack"
        $b = ".adata"
    condition:
        1 of them
}

rule SCRIPT_PowerShell_Downloader : dropper {
    meta:
        description = "PowerShell download cradle"
        severity = "high"
    strings:
        $a = "Net.WebClient"
        $b = "DownloadString"
        $c = "DownloadFile"
        $d = "DownloadData"
    condition:
        $a and (1 of ($b, $c, $d))
}

rule SCRIPT_PowerShell_AMSI_Bypass : evasion {
    meta:
        description = "PowerShell AMSI bypass"
        severity = "high"
    strings:
        $a = "amsiInitFailed"
        $b = "AmsiUtils"
        $c = "amsiContext"
    condition:
        2 of them
}

rule SCRIPT_LOLBIN_Download : dropper {
    meta:
        description = "certutil / bitsadmin living-off-the-land download"
        severity = "high"
    strings:
        $a = "bitsadmin /transfer" nocase
        $b = "certutil -urlcache" nocase
        $c = "certutil.exe -urlcache" nocase
        $d = "certutil -decode" nocase
    condition:
        1 of them
}

rule SCRIPT_Mshta_Execution : execution {
    meta:
        description = "mshta remote/script execution"
        severity = "high"
    strings:
        $a = "mshta http" nocase
        $b = "mshta vbscript:" nocase
        $c = "mshta javascript:" nocase
    condition:
        1 of them
}

rule SCRIPT_Regsvr32_Squiblydoo : execution {
    meta:
        description = "regsvr32 scriptlet (Squiblydoo) execution"
        severity = "high"
    strings:
        $a = "regsvr32 /s /n /u /i:http" nocase
        $b = "scrobj.dll" nocase
    condition:
        $a
}

rule MINER_Generic_Stratum : coinminer {
    meta:
        description = "generic stratum mining-pool client"
        severity = "high"
    strings:
        $a = "stratum+tcp://"
        $b = "stratum+ssl://"
        $c = "cryptonight"
    condition:
        1 of them
}

rule LINUX_XorDDoS : ddos {
    meta:
        description = "XorDDoS Linux DDoS trojan"
    strings:
        $a = "xorddos"
        $b = "BB2FA36AAA9541F0"
        $c = "/lib/libudev.so"
        $d = "hostname -s"
    condition:
        $a or $b or ($c and $d)
}

rule LINUX_Diamorphine_Rootkit : rootkit {
    meta:
        description = "Diamorphine Linux kernel rootkit"
    strings:
        $a = "diamorphine"
        $b = "module_hide"
        $c = "give_root"
        $d = "hacked_getdents"
    condition:
        $a or (2 of ($b, $c, $d))
}

rule PE_Keylogger_APIs : spyware {
    meta:
        description = "PE installing a keyboard hook and polling key state (keylogger)"
        severity = "high"
    condition:
        pe.imports("user32.dll", "SetWindowsHookExA") and
        pe.imports("user32.dll", "GetAsyncKeyState")
}

rule PE_Service_Persistence : persistence {
    meta:
        description = "PE creating/starting a Windows service (persistence)"
        severity = "high"
    condition:
        pe.imports("advapi32.dll", "OpenSCManagerA") and
        pe.imports("advapi32.dll", "CreateServiceA") and
        pe.imports("advapi32.dll", "StartServiceA")
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
