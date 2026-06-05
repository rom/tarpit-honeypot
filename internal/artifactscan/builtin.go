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

// ---------------------------------------------------------------------------
// Ransomware families (ransom-note / extension / marker strings).
// ---------------------------------------------------------------------------
rule RANSOM_LockBit : ransomware {
    meta:
        description = "LockBit ransomware"
    strings:
        $a = "Restore-My-Files.txt"
        $b = ".lockbit"
        $c = "lockbitsupp"
        $d = "LockBit_"
    condition:
        1 of them
}

rule RANSOM_Conti : ransomware {
    meta:
        description = "Conti ransomware"
    strings:
        $a = "CONTI_README.txt"
        $b = "CONTI_LOG.txt"
        $c = "conti_recovery"
    condition:
        1 of them
}

rule RANSOM_REvil : ransomware {
    meta:
        description = "REvil / Sodinokibi ransomware"
    strings:
        $a = "Sodinokibi"
        $b = "sodinokibi"
        $c = "-HOW-TO-DECRYPT.txt"
    condition:
        1 of them
}

rule RANSOM_BlackCat : ransomware {
    meta:
        description = "BlackCat / ALPHV ransomware"
    strings:
        $a = "RECOVER-"
        $b = "ALPHV"
        $c = "alphv"
        $d = "bsStatusUpdate"
    condition:
        1 of ($b, $c) or ($a and $d)
}

rule RANSOM_Hive : ransomware {
    meta:
        description = "Hive ransomware"
    strings:
        $a = "HOW_TO_DECRYPT.txt"
        $b = "hive ransomware"
        $c = ".hive"
    condition:
        1 of them
}

rule RANSOM_Ryuk : ransomware {
    meta:
        description = "Ryuk ransomware"
    strings:
        $a = "RyukReadMe"
        $b = "UNIQUE_ID_DO_NOT_REMOVE"
        $c = "No system is safe"
    condition:
        1 of them
}

rule RANSOM_WannaCry : ransomware {
    meta:
        description = "WannaCry ransomware"
    strings:
        $a = "WANACRY!"
        $b = "@WanaDecryptor@"
        $c = "tasksche.exe"
        $d = "mssecsvc.exe"
    condition:
        1 of ($a, $b) or ($c and $d)
}

rule RANSOM_Phobos : ransomware {
    meta:
        description = "Phobos ransomware"
    strings:
        $a = "info.hta"
        $b = ".phobos"
        $c = "Phobos"
        $d = "encrypted by Phobos"
    condition:
        1 of ($b, $d) or ($a and $c)
}

rule RANSOM_Dharma : ransomware {
    meta:
        description = "Dharma / CrySiS ransomware"
    strings:
        $a = ".dharma"
        $b = ".crysis"
        $c = "FILES ENCRYPTED.txt"
    condition:
        1 of them
}

rule RANSOM_STOP_Djvu : ransomware {
    meta:
        description = "STOP/Djvu ransomware"
    strings:
        $a = "_readme.txt"
        $b = "djvu"
        $c = "personal ID"
        $d = "support@freshmail.top"
    condition:
        1 of ($b, $d) or ($a and $c)
}

rule RANSOM_Maze : ransomware {
    meta:
        description = "Maze ransomware"
    strings:
        $a = "DECRYPT-FILES.txt"
        $b = "Maze Ransomware"
        $c = "mazedecrypt"
    condition:
        1 of them
}

rule RANSOM_Clop : ransomware {
    meta:
        description = "Cl0p ransomware"
    strings:
        $a = "ClopReadMe.txt"
        $b = "Cl0p^_-"
        $c = ".clop"
    condition:
        1 of them
}

rule RANSOM_BlackBasta : ransomware {
    meta:
        description = "Black Basta ransomware"
    strings:
        $a = "readme.txt"
        $b = ".basta"
        $c = "aaaaaaaa.basta"
        $d = "Your data are stolen and encrypted"
    condition:
        1 of ($b, $c) or ($a and $d)
}

rule RANSOM_Akira : ransomware {
    meta:
        description = "Akira ransomware"
    strings:
        $a = "akira_readme.txt"
        $b = ".akira"
        $c = "akira-tools"
    condition:
        1 of them
}

rule RANSOM_Royal : ransomware {
    meta:
        description = "Royal ransomware"
    strings:
        $a = "README.TXT"
        $b = ".royal"
        $c = "Royal ransomware"
        $d = "royal_w"
    condition:
        1 of ($b, $c, $d)
}

// ---------------------------------------------------------------------------
// Remote-access trojans / backdoors.
// ---------------------------------------------------------------------------
rule MAL_Gh0stRAT : rat {
    meta:
        description = "Gh0st RAT"
    strings:
        $a = { 47 68 30 73 74 }
        $b = "Gh0st RAT"
        $c = "Gh0stRAT"
    condition:
        $b or $c or ($a and $b)
}

rule MAL_PlugX : rat {
    meta:
        description = "PlugX RAT"
    strings:
        $a = "X-PLUG"
        $b = "PLUGX_"
        $c = "Th2.dll"
    condition:
        1 of them
}

rule MAL_OrcusRAT : rat {
    meta:
        description = "Orcus RAT"
    strings:
        $a = "Orcus.exe"
        $b = "OrcusRAT"
        $c = "Orcus.Commands"
    condition:
        1 of them
}

rule MAL_NetWire : rat {
    meta:
        description = "NetWire RAT"
    strings:
        $a = "NetWire"
        $b = "HostId-%Rand%"
        $c = "[Scroll Lock]"
    condition:
        1 of ($b, $c) or $a
}

rule MAL_Adwind : rat {
    meta:
        description = "Adwind / jRAT cross-platform Java RAT"
    strings:
        $a = "Adwind"
        $b = "JSocket"
        $c = "operational/Operational.class"
    condition:
        1 of them
}

rule MAL_BitRAT : rat {
    meta:
        description = "BitRAT"
    strings:
        $a = "BitRAT"
        $b = "bitrat"
    condition:
        1 of them
}

rule MAL_XWorm : rat {
    meta:
        description = "XWorm RAT"
    strings:
        $a = "XWorm"
        $b = "Xwormmm"
        $c = "XLogger"
    condition:
        1 of ($a, $b)
}

rule MAL_VenomRAT : rat {
    meta:
        description = "VenomRAT"
    strings:
        $a = "VenomRAT"
        $b = "Venom RAT"
    condition:
        1 of them
}

rule MAL_Pupy : rat {
    meta:
        description = "Pupy cross-platform RAT"
    strings:
        $a = "PupyConfig"
        $b = "pupy"
        $c = "reflective_inject_dll"
    condition:
        $a or ($b and $c)
}

rule MAL_AveMaria : rat {
    meta:
        description = "AveMaria / Warzone RAT"
    strings:
        $a = "Ave_Maria"
        $b = "WarzoneRAT"
        $c = "warzone160"
    condition:
        1 of them
}

rule MAL_Houdini : rat {
    meta:
        description = "Houdini / H-Worm VBS RAT"
    strings:
        $a = "Houdini"
        $b = "is-ready"
        $c = "houdini"
    condition:
        ($a or $c) and $b
}

rule MAL_CrimsonRAT : rat {
    meta:
        description = "CrimsonRAT (Transparent Tribe)"
    strings:
        $a = "CrimsonRAT"
        $b = "Crimson.exe"
    condition:
        1 of them
}

rule MAL_Sakula : rat {
    meta:
        description = "Sakula RAT"
    strings:
        $a = "Sakula"
        $b = "MicroPlayerUpdate.exe"
    condition:
        1 of them
}

rule MAL_PoisonIvy : rat {
    meta:
        description = "Poison Ivy RAT"
    strings:
        $a = "Poison Ivy"
        $b = "poisonivy"
        $c = "PI3.4"
    condition:
        1 of them
}

rule MAL_ZeroAccess : rat {
    meta:
        description = "ZeroAccess / Sirefef rootkit-bot"
    strings:
        $a = "ZeroAccess"
        $b = "!!!ACCESS!!!"
        $c = "max++"
    condition:
        1 of them
}

// ---------------------------------------------------------------------------
// Stealers / loaders.
// ---------------------------------------------------------------------------
rule MAL_Vidar : stealer {
    meta:
        description = "Vidar information stealer"
    strings:
        $a = "Vidar"
        $b = "screenshot.jpg"
        $c = "passwords.txt"
    condition:
        $a and (1 of ($b, $c))
}

rule MAL_Raccoon : stealer {
    meta:
        description = "Raccoon stealer"
    strings:
        $a = "raccoon"
        $b = "/gate/log"
        $c = "record_log"
    condition:
        ($a and (1 of ($b, $c))) or $b
}

rule MAL_Azorult : stealer {
    meta:
        description = "Azorult stealer"
    strings:
        $a = "Azorult"
        $b = "azorult"
    condition:
        1 of them
}

rule MAL_Xloader : stealer {
    meta:
        description = "Xloader / FormBook stealer"
    strings:
        $a = "Xloader"
        $b = "xloader"
        $c = "formbook"
    condition:
        $a or ($b and $c)
}

rule MAL_Rhadamanthys : stealer {
    meta:
        description = "Rhadamanthys stealer"
    strings:
        $a = "Rhadamanthys"
        $b = "rhadamanthys"
    condition:
        1 of them
}

rule MAL_Lumma : stealer {
    meta:
        description = "Lumma (LummaC2) stealer"
    strings:
        $a = "LummaC2"
        $b = "lumma"
        $c = "HWID:"
    condition:
        $a or ($b and $c)
}

rule MAL_StealC : stealer {
    meta:
        description = "StealC stealer"
    strings:
        $a = "StealC"
        $b = "stealc"
        $c = "browser_extensions"
    condition:
        $a or ($b and $c)
}

rule MAL_Amadey : stealer {
    meta:
        description = "Amadey bot / loader"
    strings:
        $a = "Amadey"
        $b = "amadey"
        $c = "&av="
    condition:
        $a or ($b and $c)
}

rule MAL_SmokeLoader : loader {
    meta:
        description = "SmokeLoader"
    strings:
        $a = "SmokeLoader"
        $b = "smokeloader"
    condition:
        1 of them
}

rule MAL_GuLoader : loader {
    meta:
        description = "GuLoader / CloudEyE"
    strings:
        $a = "GuLoader"
        $b = "guloader"
    condition:
        1 of them
}

rule MAL_BazarLoader : loader {
    meta:
        description = "BazarLoader / BazarBackdoor"
    strings:
        $a = "BazarLoader"
        $b = "BazarBackdoor"
        $c = "bazarloader"
    condition:
        1 of them
}

rule MAL_IcedID : loader {
    meta:
        description = "IcedID / BokBot banking loader"
    strings:
        $a = "IcedID"
        $b = "BokBot"
    condition:
        1 of them
}

rule MAL_Qakbot : banker {
    meta:
        description = "Qakbot / QBot"
    strings:
        $a = "Qakbot"
        $b = "QakBot"
        $c = "qbot"
    condition:
        1 of them
}

rule MAL_Dridex : banker {
    meta:
        description = "Dridex banking trojan"
    strings:
        $a = "Dridex"
        $b = "dridex"
    condition:
        1 of them
}

rule MAL_Ramnit : banker {
    meta:
        description = "Ramnit banking worm"
    strings:
        $a = "Ramnit"
        $b = "RMNetwork"
        $c = "ramnit"
    condition:
        1 of them
}

// ---------------------------------------------------------------------------
// Document / script droppers.
// ---------------------------------------------------------------------------
rule MAL_VBA_AutoExec : dropper {
    meta:
        description = "Office VBA auto-exec macro spawning a shell"
        severity = "high"
    strings:
        $a = "Document_Open"
        $b = "Auto_Open"
        $c = "AutoExec"
        $d = "CreateObject"
        $e = "WScript.Shell"
    condition:
        (1 of ($a, $b, $c)) and (1 of ($d, $e))
}

rule MAL_VBS_Dropper : dropper {
    meta:
        description = "VBScript download-and-run dropper"
        severity = "high"
    strings:
        $a = "WScript.Shell"
        $b = "MSXML2.XMLHTTP"
        $c = "ADODB.Stream"
        $d = ".Run"
    condition:
        $a and (1 of ($b, $c)) and $d
}

rule MAL_HTA_Dropper : dropper {
    meta:
        description = "HTA application dropper"
        severity = "high"
    strings:
        $a = "<hta:application"
        $b = "ActiveXObject"
        $c = "WScript.Shell"
    condition:
        $a and (1 of ($b, $c))
}

rule MAL_JS_Dropper : dropper {
    meta:
        description = "JScript ActiveX dropper"
        severity = "high"
    strings:
        $a = "new ActiveXObject"
        $b = "WScript.Shell"
        $c = "WScript.Network"
    condition:
        $a and (1 of ($b, $c))
}

rule MAL_Office_DDE : dropper {
    meta:
        description = "Office DDE auto-execution"
        severity = "high"
    strings:
        $a = "DDEAUTO"
        $b = "DDE c:"
        $c = "cmd.exe"
        $d = "powershell"
    condition:
        (1 of ($a, $b)) and (1 of ($c, $d))
}

rule DOC_RTF_EquationEditor : exploit {
    meta:
        description = "RTF Equation Editor exploit object (CVE-2017-11882 class)"
        severity = "high"
    strings:
        $a = "objupdate"
        $b = "Equation.3"
        $c = "objdata"
        $d = "OLE10nATIVE"
    condition:
        $b or ($a and $c) or ($c and $d)
}

rule DOC_XLL_AddIn : dropper {
    meta:
        description = "Malicious Excel XLL add-in (xlAutoOpen export)"
        severity = "high"
    strings:
        $a = "xlAutoOpen"
    condition:
        $a
}

// ---------------------------------------------------------------------------
// Additional webshells.
// ---------------------------------------------------------------------------
rule WEBSHELL_Godzilla : webshell {
    meta:
        description = "Godzilla encrypted webshell"
    strings:
        $a = "Godzilla" nocase
        $b = "3c6e0b8a9c15224a"
        $c = "payloadName"
    condition:
        $a or $b or ($c and $a)
}

rule WEBSHELL_AspxSpy : webshell {
    meta:
        description = "AspxSpy ASP.NET webshell"
    strings:
        $a = "AspxSpy"
        $b = "ASPXSpy"
    condition:
        1 of them
}

rule WEBSHELL_Caidao : webshell {
    meta:
        description = "Chinese Caidao / Chopper webshell client artifacts"
    strings:
        $a = "caidao"
        $b = "Chopper"
    condition:
        1 of them
}

rule WEBSHELL_reGeorg : webshell {
    meta:
        description = "reGeorg SOCKS tunneling webshell"
    strings:
        $a = "Georg says"
        $b = "reGeorg"
        $c = "tunnel.nosocket"
    condition:
        1 of them
}

rule WEBSHELL_Tunna : webshell {
    meta:
        description = "Tunna HTTP tunneling webshell"
    strings:
        $a = "Tunna"
        $b = "buffersize"
        $c = "conn.php"
    condition:
        $a and (1 of ($b, $c))
}

rule WEBSHELL_p0wny : webshell {
    meta:
        description = "p0wny-shell PHP webshell"
    strings:
        $a = "p0wny"
        $b = "@shell:"
    condition:
        1 of them
}

rule WEBSHELL_PHPFileManager : webshell {
    meta:
        description = "PHP file-manager webshell"
    strings:
        $a = "PHP File Manager"
        $b = "FilesMan"
    condition:
        1 of them
}

rule WEBSHELL_Obfuscated_Eval : webshell {
    meta:
        description = "obfuscated PHP eval(decompress(base64)) webshell"
        severity = "high"
    strings:
        $a = "eval(gzinflate(base64_decode("
        $b = "eval(gzuncompress(base64_decode("
        $c = "eval(str_rot13(base64_decode("
        $d = "eval(base64_decode("
    condition:
        1 of them
}

// ---------------------------------------------------------------------------
// Offensive / recon / cracking tools.
// ---------------------------------------------------------------------------
rule TOOL_Responder : credaccess {
    meta:
        description = "Responder LLMNR/NBT-NS poisoner"
        severity = "high"
    strings:
        $a = "Responder"
        $b = "Poisoners"
        $c = "Analyzer"
    condition:
        2 of them
}

rule TOOL_Impacket : lateral {
    meta:
        description = "Impacket toolkit (secretsdump/wmiexec/smbexec)"
        severity = "high"
    strings:
        $a = "impacket"
        $b = "secretsdump"
        $c = "wmiexec"
        $d = "smbexec"
    condition:
        1 of them
}

rule TOOL_CrackMapExec : lateral {
    meta:
        description = "CrackMapExec / NetExec"
        severity = "high"
    strings:
        $a = "crackmapexec"
        $b = "NetExec"
        $c = "cme_"
    condition:
        1 of them
}

rule TOOL_Nmap : recon {
    meta:
        description = "Nmap port scanner output/binary"
        severity = "medium"
    strings:
        $a = "Nmap scan report"
        $b = "Insecure.Com LLC"
        $c = "nmap -p"
    condition:
        1 of them
}

rule TOOL_Masscan : recon {
    meta:
        description = "Masscan port scanner"
        severity = "medium"
    strings:
        $a = "Masscan/1."
        $b = "masscan -p"
        $c = "robmurdoch"
    condition:
        1 of ($a, $b)
}

rule TOOL_SQLMap : offensive {
    meta:
        description = "sqlmap SQL injection tool"
        severity = "high"
    strings:
        $a = "(http://sqlmap.org)"
        $b = "sqlmap/1."
        $c = "sqlmap identified"
    condition:
        1 of them
}

rule TOOL_Hydra : offensive {
    meta:
        description = "THC-Hydra brute-force tool"
        severity = "high"
    strings:
        $a = "THC-Hydra"
        $b = "Hydra (http"
        $c = "hydra -l"
    condition:
        1 of them
}

rule TOOL_Hashcat : cracking {
    meta:
        description = "hashcat password cracker"
        severity = "medium"
    strings:
        $a = "hashcat"
        $b = "oclHashcat"
    condition:
        1 of them
}

rule TOOL_JohnTheRipper : cracking {
    meta:
        description = "John the Ripper password cracker"
        severity = "medium"
    strings:
        $a = "John the Ripper"
        $b = "john --format"
        $c = "Loaded %d password hash"
    condition:
        1 of them
}

rule TOOL_Gobuster : recon {
    meta:
        description = "Gobuster directory/DNS brute-forcer"
        severity = "high"
    strings:
        $a = "OJ/gobuster"
        $b = "gobuster dir"
    condition:
        1 of them
}

rule TOOL_Ffuf : recon {
    meta:
        description = "ffuf web fuzzer"
        severity = "medium"
    strings:
        $a = "Fuzz Faster U Fool"
        $b = "ffuf/"
    condition:
        1 of them
}

rule TOOL_PowerCat : offensive {
    meta:
        description = "PowerCat netcat-style PowerShell tool"
        severity = "high"
    strings:
        $a = "powercat"
        $b = "Invoke-PowerShellTcpOneLine"
    condition:
        1 of them
}

rule TOOL_Socat_Relay : tunnel {
    meta:
        description = "socat exec relay (reverse-shell pattern)"
        severity = "high"
    strings:
        $a = "socat"
        $b = "EXEC:'/bin/sh'"
        $c = "EXEC:'bash"
        $d = "exec:'/bin/bash'"
    condition:
        $a and (1 of ($b, $c, $d))
}

rule TOOL_Plink_Tunnel : tunnel {
    meta:
        description = "PuTTY plink port-forward tunnel"
        severity = "high"
    strings:
        $a = "plink.exe"
        $b = " -R "
        $c = " -L "
    condition:
        $a and (1 of ($b, $c))
}

rule TOOL_AdFind : recon {
    meta:
        description = "AdFind AD enumeration tool"
        severity = "high"
    strings:
        $a = "AdFind.exe"
        $b = "-gcb -sc trustdmp"
        $c = "adfind"
    condition:
        1 of ($a, $b)
}

rule TOOL_Seatbelt : recon {
    meta:
        description = "Seatbelt host-survey tool"
        severity = "high"
    strings:
        $a = "Seatbelt"
        $b = "Seatbelt.exe"
    condition:
        1 of them
}

// ---------------------------------------------------------------------------
// Persistence / defense-evasion command patterns.
// ---------------------------------------------------------------------------
rule PERSIST_Schtasks : persistence {
    meta:
        description = "scheduled-task persistence"
        severity = "high"
    strings:
        $a = "schtasks /create"
        $b = "schtasks.exe /create"
        $c = "/sc onlogon"
        $d = "/ru system"
    condition:
        (1 of ($a, $b)) and (1 of ($c, $d))
}

rule PERSIST_Reg_Run_Key : persistence {
    meta:
        description = "registry Run-key persistence"
        severity = "high"
    strings:
        $a = "reg add"
        $b = "CurrentVersion\\Run"
        $c = "CurrentVersion\\RunOnce"
    condition:
        $a and (1 of ($b, $c))
}

rule PERSIST_WMI_Subscription : persistence {
    meta:
        description = "WMI event-subscription persistence"
        severity = "high"
    strings:
        $a = "__EventFilter"
        $b = "CommandLineEventConsumer"
        $c = "ActiveScriptEventConsumer"
    condition:
        1 of ($b, $c)
}

rule PERSIST_Startup_Folder : persistence {
    meta:
        description = "Startup-folder persistence"
        severity = "high"
    strings:
        $a = "\\Start Menu\\Programs\\Startup"
    condition:
        $a
}

rule PERSIST_Systemd_Service : persistence {
    meta:
        description = "Linux systemd service unit dropped for persistence"
        severity = "medium"
    strings:
        $a = "ExecStart="
        $b = "WantedBy=multi-user.target"
        $c = "[Service]"
    condition:
        all of them
}

rule EVASION_Disable_Defender : evasion {
    meta:
        description = "disables Microsoft Defender"
        severity = "high"
    strings:
        $a = "Set-MpPreference"
        $b = "DisableRealtimeMonitoring"
        $c = "Add-MpPreference -ExclusionPath"
        $d = "MpCmdRun.exe -RemoveDefinitions"
    condition:
        ($a and (1 of ($b, $c))) or $d
}

rule EVASION_Disable_Firewall : evasion {
    meta:
        description = "disables host firewall"
        severity = "high"
    strings:
        $a = "netsh advfirewall set allprofiles state off"
        $b = "netsh firewall set opmode disable"
        $c = "Set-NetFirewallProfile -Enabled False"
    condition:
        1 of them
}

rule EVASION_Clear_EventLog : evasion {
    meta:
        description = "clears Windows event logs"
        severity = "high"
    strings:
        $a = "wevtutil cl "
        $b = "wevtutil clear-log"
        $c = "Clear-EventLog"
    condition:
        1 of them
}

rule EVASION_BCDEdit_Recovery : evasion {
    meta:
        description = "disables Windows recovery (ransomware pre-step)"
        severity = "high"
    strings:
        $a = "bcdedit"
        $b = "recoveryenabled no"
        $c = "bootstatuspolicy ignoreallfailures"
    condition:
        $a and (1 of ($b, $c))
}

rule EVASION_Shadow_Copy_Delete : evasion {
    meta:
        description = "deletes volume shadow copies / backups (ransomware pre-step)"
        severity = "high"
    strings:
        $a = "vssadmin delete shadows"
        $b = "vssadmin.exe delete shadows"
        $c = "shadowcopy delete"
        $d = "wbadmin delete catalog"
    condition:
        1 of them
}

rule EVASION_ETW_Patch : evasion {
    meta:
        description = "ETW tampering (EtwEventWrite patch)"
        severity = "high"
    strings:
        $a = "EtwEventWrite"
        $b = "EtwpEventWriteFull"
        $c = "ntdll.dll"
    condition:
        ($a and $c) or $b
}

rule EVASION_Timestomp : evasion {
    meta:
        description = "timestomping / file timestamp manipulation"
        severity = "medium"
    strings:
        $a = "timestomp"
        $b = "SetFileTime"
        $c = "-c -m -a -e"
    condition:
        1 of ($a, $c)
}

// ---------------------------------------------------------------------------
// Exploit / recon payload patterns (fire on captured script/text artifacts).
// ---------------------------------------------------------------------------
rule EXPLOIT_SQLi_Union : exploit {
    meta:
        description = "UNION-based SQL injection"
        severity = "high"
    strings:
        $a = "union select" nocase
        $b = "union all select" nocase
        $c = "information_schema" nocase
    condition:
        (1 of ($a, $b)) and $c
}

rule EXPLOIT_SQLi_TimeBased : exploit {
    meta:
        description = "time-based blind SQL injection"
        severity = "high"
    strings:
        $a = "waitfor delay" nocase
        $b = "pg_sleep(" nocase
        $c = "benchmark(" nocase
        $d = "sleep(__time" nocase
    condition:
        1 of them
}

rule EXPLOIT_XSS_Script : exploit {
    meta:
        description = "reflected/stored XSS payload"
        severity = "medium"
    strings:
        $a = "<script>alert(" nocase
        $b = "onerror=alert(" nocase
        $c = "<img src=x onerror=" nocase
        $d = "<svg onload=" nocase
    condition:
        1 of them
}

rule EXPLOIT_Path_Traversal : exploit {
    meta:
        description = "directory traversal to sensitive files"
        severity = "high"
    strings:
        $a = "../../../../etc/passwd"
        $b = "..%2f..%2f..%2f"
        $c = "..%5c..%5c..%5c"
        $d = "....//....//"
    condition:
        1 of them
}

rule EXPLOIT_LFI_PHP_Wrapper : exploit {
    meta:
        description = "PHP wrapper local file inclusion / RCE"
        severity = "high"
    strings:
        $a = "php://filter/convert.base64-encode"
        $b = "php://input"
        $c = "data://text/plain;base64"
        $d = "expect://"
    condition:
        1 of them
}

rule EXPLOIT_Command_Injection : exploit {
    meta:
        description = "OS command injection markers"
        severity = "high"
    strings:
        $a = "$(id)"
        $b = ";cat /etc/passwd"
        $c = "|| whoami"
        $d = "; ping -c "
    condition:
        1 of ($a, $b) or 2 of them
}

rule EXPLOIT_SSRF_Cloud_Metadata : exploit {
    meta:
        description = "SSRF to cloud instance-metadata endpoints"
        severity = "high"
    strings:
        $a = "169.254.169.254"
        $b = "metadata.google.internal"
        $c = "/computeMetadata/v1/"
        $d = "/latest/meta-data/"
    condition:
        1 of them
}

rule EXPLOIT_XXE : exploit {
    meta:
        description = "XML external entity injection"
        severity = "high"
    strings:
        $a = "<!ENTITY" nocase
        $b = "SYSTEM \"file:" nocase
        $c = "SYSTEM \"http" nocase
        $d = "SYSTEM \"php://" nocase
    condition:
        $a and (1 of ($b, $c, $d))
}

rule EXPLOIT_SSTI : exploit {
    meta:
        description = "server-side template injection probe"
        severity = "medium"
    strings:
        $a = "${7*7}"
        $b = "{{7*7}}"
        $c = "<%= 7*7 %>"
        $d = "#{7*7}"
    condition:
        1 of them
}

rule EXPLOIT_Java_Deserialization : exploit {
    meta:
        description = "Java deserialization gadget payload"
        severity = "high"
    strings:
        $a = "rO0AB"
        $b = "aced0005"
        $c = "ysoserial"
        $d = "CommonsCollections"
    condition:
        1 of them
}

// ---------------------------------------------------------------------------
// Miners / Linux malware (tail).
// ---------------------------------------------------------------------------
rule MINER_CoinHive_JS : coinminer {
    meta:
        description = "in-browser CoinHive/cryptonight miner"
        severity = "medium"
    strings:
        $a = "coinhive" nocase
        $b = "CoinHive.Anonymous"
        $c = "coin-hive.com"
        $d = "cryptonight.wasm"
    condition:
        1 of them
}

rule LINUX_Kinsing : coinminer {
    meta:
        description = "Kinsing Linux crypto-mining malware"
    strings:
        $a = "kinsing"
        $b = "kdevtmpfsi"
        $c = "/etc/kinsing"
    condition:
        1 of them
}

// ===========================================================================
// APT / nation-state implants.
// ===========================================================================
rule APT_Sunburst : apt {
    meta:
        description = "SUNBURST / Solorigate (SolarWinds supply-chain backdoor)"
    strings:
        $a = "OrionImprovementBusinessLayer"
        $b = "SolarWinds.Orion.Core.BusinessLayer"
        $c = "avsvmcloud.com"
    condition:
        1 of them
}

rule APT_Stuxnet : apt {
    meta:
        description = "Stuxnet ICS sabotage worm"
    strings:
        $a = "s7otbxdx.dll"
        $b = "Stuxnet"
        $c = "~WTR4132.tmp"
    condition:
        1 of them
}

rule APT_Flame : apt {
    meta:
        description = "Flame / Skywiper espionage platform"
    strings:
        $a = "mssecmgr.ocx"
        $b = "Skywiper"
        $c = "advnetcfg.ocx"
    condition:
        1 of them
}

rule APT_Winnti : apt {
    meta:
        description = "Winnti / APT41 implant"
    strings:
        $a = "Winnti"
        $b = "skipper"
        $c = "winnti"
    condition:
        $a or $c or ($b and $a)
}

rule APT_ShadowPad : apt {
    meta:
        description = "ShadowPad modular backdoor"
    strings:
        $a = "ShadowPad"
        $b = "shadowpad"
    condition:
        1 of them
}

rule APT_Derusbi : apt {
    meta:
        description = "Derusbi backdoor"
    strings:
        $a = "Derusbi"
        $b = "derusbi"
        $c = "PCC_IDENT_STRING"
    condition:
        1 of them
}

rule APT_XAgent : apt {
    meta:
        description = "Sofacy/APT28 X-Agent implant"
    strings:
        $a = "XAgentOSX"
        $b = "X-Agent"
        $c = "Sofacy"
    condition:
        1 of them
}

rule APT_Zebrocy : apt {
    meta:
        description = "Zebrocy (Sednit) downloader"
    strings:
        $a = "Zebrocy"
        $b = "zebrocy"
    condition:
        1 of them
}

rule APT_Lazarus_Bankshot : apt {
    meta:
        description = "Lazarus Bankshot implant"
    strings:
        $a = "Bankshot"
        $b = "bankshot"
        $c = "Lazarus"
    condition:
        1 of ($a, $b) or ($c and $a)
}

rule APT_Kimsuky_BabyShark : apt {
    meta:
        description = "Kimsuky BabyShark malware"
    strings:
        $a = "BabyShark"
        $b = "babyshark"
        $c = "Kimsuky"
    condition:
        1 of them
}

rule APT_Carbanak : apt {
    meta:
        description = "Carbanak / Anunak financial APT backdoor"
    strings:
        $a = "Carbanak"
        $b = "Anunak"
        $c = "carbanak"
    condition:
        1 of them
}

rule APT_Equation : apt {
    meta:
        description = "Equation Group toolset"
    strings:
        $a = "DoubleFantasy"
        $b = "EquationDrug"
        $c = "GrayFish"
    condition:
        1 of them
}

// ===========================================================================
// Linux / Unix malware & rootkits.
// ===========================================================================
rule LINUX_Mirai_Satori : botnet {
    meta:
        description = "Mirai variant (Satori/Okiru/Masuta)"
    strings:
        $a = "satori"
        $b = "okiru"
        $c = "masuta"
    condition:
        1 of them
}

rule LINUX_Mozi : botnet {
    meta:
        description = "Mozi P2P IoT botnet"
    strings:
        $a = "Mozi.m"
        $b = "Mozi.a"
        $c = "/Mozi"
    condition:
        1 of them
}

rule LINUX_Tsunami_Kaiten : botnet {
    meta:
        description = "Tsunami / Kaiten IRC DDoS bot"
    strings:
        $a = "TSUNAMI"
        $b = "Kaiten"
        $c = "GETSPOOFS"
    condition:
        1 of them
}

rule LINUX_Bashlite_Gafgyt : botnet {
    meta:
        description = "Bashlite / Gafgyt / Lizkebab IoT bot"
    strings:
        $a = "gafgyt"
        $b = "bashlite"
        $c = "lizkebab"
    condition:
        1 of them
}

rule LINUX_BPFDoor : backdoor {
    meta:
        description = "BPFDoor passive Linux backdoor"
    strings:
        $a = "bpfdoor"
        $b = "/dev/shm/kdmtmpflush"
        $c = "justtryit"
    condition:
        1 of them
}

rule LINUX_Symbiote : rootkit {
    meta:
        description = "Symbiote shared-object Linux malware"
    strings:
        $a = "certbotx64"
        $b = "certbotx86"
        $c = "symbiote"
    condition:
        1 of them
}

rule LINUX_RotaJakiro : backdoor {
    meta:
        description = "RotaJakiro Linux backdoor"
    strings:
        $a = "rotajakiro"
        $b = "RotaJakiro"
    condition:
        1 of them
}

rule LINUX_Reptile_Rootkit : rootkit {
    meta:
        description = "Reptile LKM rootkit"
    strings:
        $a = "reptile_module"
        $b = "reptile_shell"
        $c = "/reptile/"
    condition:
        1 of them
}

rule LINUX_Drovorub : rootkit {
    meta:
        description = "Drovorub Linux rootkit (APT28)"
    strings:
        $a = "Drovorub"
        $b = "drovorub"
    condition:
        1 of them
}

rule LINUX_Sysrv_Botnet : coinminer {
    meta:
        description = "Sysrv-hello cryptomining botnet"
    strings:
        $a = "sysrvhello"
        $b = "sysrv-hello"
    condition:
        1 of them
}

rule LINUX_Outlaw_Shellbot : botnet {
    meta:
        description = "Outlaw / Shellbot Perl IRC bot"
    strings:
        $a = "Outlaw"
        $b = "shellbot"
        $c = "b0t v"
    condition:
        1 of them
}

rule LINUX_Perl_IRC_Bot : botnet {
    meta:
        description = "Perl IRC flood/backdoor bot"
    strings:
        $a = "Net::IRC"
        $b = "PRIVMSG"
        $c = "use IO::Socket"
    condition:
        $b and (1 of ($a, $c))
}

rule LINUX_LdPreload_Hider : rootkit {
    meta:
        description = "userland LD_PRELOAD process/file hider"
        severity = "high"
    strings:
        $a = "/etc/ld.so.preload"
        $b = "libprocesshider"
        $c = "readdir"
    condition:
        $b or ($a and $c)
}

rule LINUX_Coinminer_Generic : coinminer {
    meta:
        description = "generic Linux CPU miner binary"
        severity = "medium"
    strings:
        $a = "cpuminer"
        $b = "minerd"
        $c = "xmr-stak"
    condition:
        1 of them
}

// ===========================================================================
// macOS malware.
// ===========================================================================
rule MACOS_Shlayer : trojan {
    meta:
        description = "OSX Shlayer adware/dropper"
    strings:
        $a = "Shlayer"
        $b = "ZShlayer"
        $c = "VSearch"
    condition:
        1 of them
}

rule MACOS_XCSSET : trojan {
    meta:
        description = "XCSSET macOS malware"
    strings:
        $a = "XCSSET"
        $b = "xcassets/agent"
    condition:
        1 of them
}

rule MACOS_KeRanger : ransomware {
    meta:
        description = "KeRanger macOS ransomware"
    strings:
        $a = "KeRanger"
        $b = "kernel_time"
        $c = "README_FOR_DECRYPT.txt"
    condition:
        $a or ($b and $c)
}

rule MACOS_Atomic_Stealer : stealer {
    meta:
        description = "Atomic macOS Stealer (AMOS)"
    strings:
        $a = "Atomic macOS Stealer"
        $b = "AMOS stealer"
        $c = "atomic_stealer"
    condition:
        1 of them
}

rule MACOS_Bundlore : trojan {
    meta:
        description = "Bundlore macOS adware loader"
    strings:
        $a = "Bundlore"
        $b = "mughthesec"
    condition:
        1 of them
}

rule MACOS_CoinTicker : trojan {
    meta:
        description = "CoinTicker macOS backdoor"
    strings:
        $a = "CoinTicker"
        $b = "cointicker"
    condition:
        1 of them
}

rule MACOS_Macma : trojan {
    meta:
        description = "Macma / CDDS macOS implant"
    strings:
        $a = "Macma"
        $b = "CDDS"
        $c = "kAgent"
    condition:
        $a or ($b and $c)
}

rule MACOS_SilverSparrow : trojan {
    meta:
        description = "Silver Sparrow macOS malware"
    strings:
        $a = "com.apple.insu"
        $b = "silver sparrow"
        $c = "verx_updater"
    condition:
        1 of them
}

// ===========================================================================
// Android malware (APK artifacts).
// ===========================================================================
rule ANDROID_Cerberus : android {
    meta:
        description = "Cerberus Android banking trojan"
    strings:
        $a = "com.cerberus"
        $b = "Cerberus banker"
        $c = "cerberus_panel"
    condition:
        1 of them
}

rule ANDROID_Anubis : android {
    meta:
        description = "Anubis Android banking trojan"
    strings:
        $a = "anubisdropper"
        $b = "com.anubis"
        $c = "Anubis banker"
    condition:
        1 of them
}

rule ANDROID_Joker : android {
    meta:
        description = "Joker Android fleeceware/spyware"
    strings:
        $a = "com.joker"
        $b = "Joker malware"
    condition:
        1 of them
}

rule ANDROID_FluBot : android {
    meta:
        description = "FluBot / Cabassous Android malware"
    strings:
        $a = "cabassous"
        $b = "flubot"
    condition:
        1 of them
}

rule ANDROID_SpyNote : android {
    meta:
        description = "SpyNote Android RAT"
    strings:
        $a = "SpyNote"
        $b = "com.spynote"
    condition:
        1 of them
}

rule ANDROID_GodFather : android {
    meta:
        description = "GodFather Android banking trojan"
    strings:
        $a = "com.godfather"
        $b = "godfather_inject"
    condition:
        1 of them
}

// ===========================================================================
// Phishing kits / exfiltration channels.
// ===========================================================================
rule PHISH_16Shop : phishing {
    meta:
        description = "16Shop phishing kit"
        severity = "high"
    strings:
        $a = "16Shop"
        $b = "16shop"
    condition:
        1 of them
}

rule PHISH_Evilginx : phishing {
    meta:
        description = "Evilginx2 reverse-proxy phishing framework"
        severity = "high"
    strings:
        $a = "evilginx"
        $b = "lures edit"
        $c = "phishlet"
    condition:
        $a or ($b and $c)
}

rule PHISH_Modlishka : phishing {
    meta:
        description = "Modlishka reverse-proxy phishing tool"
        severity = "high"
    strings:
        $a = "modlishka"
        $b = "Modlishka"
    condition:
        1 of them
}

rule PHISH_Office365_Kit : phishing {
    meta:
        description = "Office365 credential-phishing kit"
        severity = "medium"
    strings:
        $a = "antibot"
        $b = "validate.php"
        $c = "Sign in to your account"
        $d = "office365"
    condition:
        2 of them
}

rule EXFIL_Telegram_Bot : exfil {
    meta:
        description = "Telegram Bot API exfiltration channel"
        severity = "high"
    strings:
        $a = "api.telegram.org/bot"
        $b = "/sendMessage"
        $c = "chat_id="
    condition:
        $a and (1 of ($b, $c))
}

rule EXFIL_Discord_Webhook : exfil {
    meta:
        description = "Discord webhook exfiltration channel"
        severity = "high"
    strings:
        $a = "discord.com/api/webhooks/"
        $b = "discordapp.com/api/webhooks/"
        $c = "ptb.discord.com/api/webhooks/"
    condition:
        1 of them
}

// ===========================================================================
// LOLBins / suspicious shell & script patterns.
// ===========================================================================
rule SCRIPT_Curl_Pipe_Shell : dropper {
    meta:
        description = "curl piped directly into a shell"
        severity = "high"
    strings:
        $a = "curl "
        $b = "| bash"
        $c = "|bash"
        $d = "| sh"
        $e = "|sh"
    condition:
        $a and (1 of ($b, $c, $d, $e))
}

rule SCRIPT_Wget_Pipe_Shell : dropper {
    meta:
        description = "wget piped directly into a shell"
        severity = "high"
    strings:
        $a = "wget "
        $b = "| bash"
        $c = "|bash"
        $d = "| sh"
        $e = "|sh"
    condition:
        $a and (1 of ($b, $c, $d, $e))
}

rule SCRIPT_Base64_Pipe_Shell : dropper {
    meta:
        description = "base64-decoded payload piped to a shell"
        severity = "high"
    strings:
        $a = "base64 -d"
        $b = "base64 --decode"
        $c = "| bash"
        $d = "|bash"
        $e = "| sh"
    condition:
        (1 of ($a, $b)) and (1 of ($c, $d, $e))
}

rule SCRIPT_Bash_DevTcp_Shell : c2 {
    meta:
        description = "bash /dev/tcp reverse shell"
        severity = "high"
    strings:
        $a = "bash -i >& /dev/tcp/"
        $b = "sh -i >& /dev/tcp/"
        $c = "0<&196;exec 196<>/dev/tcp/"
    condition:
        1 of them
}

rule SCRIPT_Python_ReverseShell : c2 {
    meta:
        description = "Python reverse shell"
        severity = "high"
    strings:
        $a = "import socket"
        $b = "subprocess.call"
        $c = "pty.spawn"
        $d = "os.dup2"
    condition:
        $a and (1 of ($b, $c, $d))
}

rule SCRIPT_Perl_ReverseShell : c2 {
    meta:
        description = "Perl reverse shell"
        severity = "high"
    strings:
        $a = "use Socket"
        $b = "exec(\"/bin/sh"
        $c = "connect(S,sockaddr_in"
    condition:
        $a and (1 of ($b, $c))
}

rule SCRIPT_PHP_ReverseShell : c2 {
    meta:
        description = "PHP reverse shell"
        severity = "high"
    strings:
        $a = "fsockopen("
        $b = "/bin/sh -i"
        $c = "proc_open("
    condition:
        (1 of ($a, $c)) and $b
}

rule SCRIPT_Ruby_ReverseShell : c2 {
    meta:
        description = "Ruby reverse shell"
        severity = "medium"
    strings:
        $a = "TCPSocket.open"
        $b = "/bin/sh"
        $c = "exec sprintf"
    condition:
        $a and (1 of ($b, $c))
}

rule SCRIPT_Rundll32_Script : execution {
    meta:
        description = "rundll32 script (JS/VBS) execution"
        severity = "high"
    strings:
        $a = "rundll32"
        $b = "javascript:"
        $c = "vbscript:"
        $d = "mshtml,RunHTMLApplication"
    condition:
        $a and (1 of ($b, $c, $d))
}

rule SCRIPT_Wmic_XSL : execution {
    meta:
        description = "wmic XSL script execution"
        severity = "high"
    strings:
        $a = "wmic"
        $b = "/format:"
        $c = ".xsl"
    condition:
        $a and $b and $c
}

rule SCRIPT_Cmstp_Bypass : evasion {
    meta:
        description = "cmstp UAC/AppLocker bypass"
        severity = "high"
    strings:
        $a = "cmstp"
        $b = "/s /ns"
    condition:
        $a and $b
}

rule SCRIPT_Msbuild_Inline : execution {
    meta:
        description = "MSBuild inline-task code execution"
        severity = "medium"
    strings:
        $a = "MSBuild"
        $b = "CodeTaskFactory"
        $c = "Microsoft.Build.Framework"
    condition:
        2 of them
}

rule SCRIPT_InstallUtil_Bypass : evasion {
    meta:
        description = "InstallUtil application-whitelisting bypass"
        severity = "medium"
    strings:
        $a = "installutil"
        $b = "/logfile="
        $c = "/U"
    condition:
        $a and (1 of ($b, $c))
}

rule SCRIPT_Pastebin_Download : dropper {
    meta:
        description = "fetch payload from a paste/raw host"
        severity = "medium"
    strings:
        $a = "pastebin.com/raw/"
        $b = "raw.githubusercontent.com"
        $c = "Invoke-WebRequest"
        $d = "DownloadString"
    condition:
        (1 of ($a, $b)) and (1 of ($c, $d))
}

// ===========================================================================
// Additional exploit / injection payloads.
// ===========================================================================
rule EXPLOIT_Shellshock : exploit {
    meta:
        description = "Shellshock bash function-definition injection"
        severity = "high"
    strings:
        $a = "() { :;};"
        $b = "() {:;};"
        $c = "() { :; };"
    condition:
        1 of them
}

rule EXPLOIT_Spring4Shell : exploit {
    meta:
        description = "Spring4Shell class.module.classLoader binding"
        severity = "high"
    strings:
        $a = "class.module.classLoader"
        $b = "class.module.classloader"
    condition:
        1 of them
}

rule EXPLOIT_Log4Shell_JNDI : exploit {
    meta:
        description = "Log4Shell JNDI lookup payload"
        severity = "high"
    strings:
        $a = "${jndi:ldap"
        $b = "${jndi:rmi"
        $c = "${jndi:dns"
        $d = "${lower:jndi"
    condition:
        1 of them
}

rule EXPLOIT_Struts_OGNL : exploit {
    meta:
        description = "Apache Struts OGNL injection"
        severity = "high"
    strings:
        $a = "ognl.OgnlContext"
        $b = "%{(#_='multipart/form-data')"
        $c = "#context['com.opensymphony"
    condition:
        1 of them
}

rule EXPLOIT_JNDI_Reference : exploit {
    meta:
        description = "JNDI/LDAP deserialization reference factory"
        severity = "medium"
    strings:
        $a = "javaSerializedData"
        $b = "javaClassName"
        $c = "objectClass"
        $d = "javaFactory"
    condition:
        2 of them
}

rule EXPLOIT_NoSQL_Injection : exploit {
    meta:
        description = "NoSQL (Mongo) operator injection"
        severity = "medium"
    strings:
        $a = "[$ne]"
        $b = "[$gt]"
        $c = "$where:"
        $d = "[$regex]"
    condition:
        1 of them
}

rule EXPLOIT_CRLF_Injection : exploit {
    meta:
        description = "CRLF HTTP response splitting"
        severity = "medium"
    strings:
        $a = "%0d%0aset-cookie"
        $b = "%0aset-cookie"
        $c = "%0d%0alocation:"
    condition:
        1 of them
}

rule EXPLOIT_SSRF_Gopher_Dict : exploit {
    meta:
        description = "SSRF via gopher/dict scheme"
        severity = "high"
    strings:
        $a = "gopher://"
        $b = "dict://"
    condition:
        1 of them
}

rule EXPLOIT_PHP_Dynamic_Eval : exploit {
    meta:
        description = "PHP dynamic code-eval primitives"
        severity = "high"
    strings:
        $a = "create_function("
        $b = "call_user_func("
        $c = "assert($_"
        $d = "preg_replace"
    condition:
        $c or ($a and $d) or ($b and $d)
}

rule EXPLOIT_Tomcat_Ghostcat : exploit {
    meta:
        description = "Tomcat AJP Ghostcat (CVE-2020-1938 class)"
        severity = "medium"
    strings:
        $a = "javax.servlet.include.servlet_path"
        $b = "javax.servlet.include.path_info"
    condition:
        1 of them
}

rule EXPLOIT_GraphQL_Introspection : recon {
    meta:
        description = "GraphQL introspection enumeration"
        severity = "medium"
    strings:
        $a = "IntrospectionQuery"
        $b = "__schema"
        $c = "__typename"
    condition:
        2 of them
}

rule EXPLOIT_Heap_Spray_JS : exploit {
    meta:
        description = "browser heap-spray shellcode pattern"
        severity = "high"
    strings:
        $a = "%u9090%u9090"
        $b = "\\u9090\\u9090"
        $c = "unescape("
        $d = "0c0c0c0c"
    condition:
        1 of ($a, $b) or ($c and $d)
}

// ===========================================================================
// Packers / protectors / obfuscators.
// ===========================================================================
rule PACKER_Enigma : packer {
    meta:
        description = "Enigma Protector"
        severity = "medium"
    strings:
        $a = ".enigma1"
        $b = ".enigma2"
        $c = "Enigma protector"
    condition:
        1 of them
}

rule PACKER_PECompact : packer {
    meta:
        description = "PECompact"
        severity = "medium"
    strings:
        $a = ".pec1"
        $b = "PECompact2"
        $c = "PEC2"
    condition:
        1 of them
}

rule PACKER_Petite : packer {
    meta:
        description = "Petite packer"
        severity = "medium"
    strings:
        $a = ".petite"
    condition:
        $a
}

rule PACKER_MEW : packer {
    meta:
        description = "MEW packer"
        severity = "medium"
    strings:
        $a = ".MEW"
        $b = "MEW Packer"
    condition:
        1 of them
}

rule PACKER_FSG : packer {
    meta:
        description = "FSG packer"
        severity = "medium"
    strings:
        $a = "FSG!"
    condition:
        $a
}

rule PACKER_NSPack : packer {
    meta:
        description = "NsPack"
        severity = "medium"
    strings:
        $a = ".nsp0"
        $b = ".nsp1"
        $c = "NSPack"
    condition:
        1 of them
}

rule PACKER_MoleBox : packer {
    meta:
        description = "MoleBox packer"
        severity = "medium"
    strings:
        $a = "MoleBox"
    condition:
        $a
}

rule PACKER_Obsidium : packer {
    meta:
        description = "Obsidium protector"
        severity = "medium"
    strings:
        $a = ".obsidium"
        $b = "Obsidium"
    condition:
        1 of them
}

rule PACKER_NetReactor : packer {
    meta:
        description = ".NET Reactor protector"
        severity = "medium"
    strings:
        $a = ".NET Reactor"
        $b = "NetReactor"
    condition:
        1 of them
}

rule PACKER_ConfuserEx : packer {
    meta:
        description = "ConfuserEx .NET obfuscator"
        severity = "medium"
    strings:
        $a = "ConfuserEx"
        $b = "ConfusedByAttribute"
    condition:
        1 of them
}

rule PACKER_SmartAssembly : packer {
    meta:
        description = "SmartAssembly .NET obfuscator"
        severity = "medium"
    strings:
        $a = "SmartAssembly"
        $b = "PoweredByAttribute"
    condition:
        1 of them
}

rule PACKER_PyArmor : packer {
    meta:
        description = "PyArmor Python obfuscator"
        severity = "medium"
    strings:
        $a = "pyarmor"
        $b = "__pyarmor__"
        $c = "pytransform"
    condition:
        1 of them
}

// ===========================================================================
// Behavioral traits (strings + pe-module).
// ===========================================================================
rule TRAIT_Process_Hollowing : injection {
    meta:
        description = "process hollowing / RunPE API set"
        severity = "high"
    strings:
        $a = "NtUnmapViewOfSection"
        $b = "ZwUnmapViewOfSection"
        $c = "SetThreadContext"
        $d = "WriteProcessMemory"
    condition:
        (1 of ($a, $b)) and (1 of ($c, $d))
}

rule TRAIT_UAC_Bypass : privesc {
    meta:
        description = "known UAC-bypass binaries / hijacks"
        severity = "high"
    strings:
        $a = "fodhelper.exe"
        $b = "eventvwr.exe"
        $c = "sdclt.exe"
        $d = "ms-settings\\shell\\open\\command"
    condition:
        1 of them
}

rule TRAIT_LSASS_Dump : credaccess {
    meta:
        description = "LSASS memory dumping"
        severity = "high"
    strings:
        $a = "MiniDumpWriteDump"
        $b = "comsvcs.dll, MiniDump"
        $c = "lsass.dmp"
        $d = "lsass.exe"
    condition:
        $a or $b or $c or ($a and $d)
}

rule TRAIT_AMSI_Memory_Patch : evasion {
    meta:
        description = "in-memory AMSI bypass (AmsiScanBuffer patch)"
        severity = "high"
    strings:
        $a = "AmsiScanBuffer"
        $b = "amsi.dll"
        $c = "VirtualProtect"
    condition:
        $a and (1 of ($b, $c))
}

rule TRAIT_AntiVM_Strings : evasion {
    meta:
        description = "hypervisor CPUID/brand anti-VM strings"
        severity = "medium"
    strings:
        $a = "VMwareVMware"
        $b = "KVMKVMKVM"
        $c = "Microsoft Hv"
        $d = "VBoxVBoxVBox"
    condition:
        2 of them
}

rule TRAIT_Token_Impersonation : privesc {
    meta:
        description = "access-token theft / impersonation"
        severity = "medium"
    strings:
        $a = "SeDebugPrivilege"
        $b = "ImpersonateLoggedOnUser"
        $c = "DuplicateTokenEx"
    condition:
        2 of them
}

rule TRAIT_Raw_Keylogger : spyware {
    meta:
        description = "raw-input keylogger API set"
        severity = "high"
    strings:
        $a = "GetRawInputData"
        $b = "RegisterRawInputDevices"
    condition:
        $a and $b
}

rule PE_QueueUserAPC_Injection : injection {
    meta:
        description = "PE using QueueUserAPC remote-injection import set"
        severity = "high"
    condition:
        pe.imports("kernel32.dll", "OpenProcess") and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "QueueUserAPC")
}

rule PE_Crypto_Ransom_APIs : ransomware {
    meta:
        description = "PE importing the CryptoAPI set used for file encryption"
        severity = "high"
    condition:
        pe.imports("advapi32.dll", "CryptAcquireContextA") and
        pe.imports("advapi32.dll", "CryptEncrypt") and
        pe.imports("advapi32.dll", "CryptGenKey")
}

rule PE_Anti_Debug_APIs : evasion {
    meta:
        description = "PE importing multiple anti-debug checks"
        severity = "medium"
    condition:
        pe.imports("kernel32.dll", "IsDebuggerPresent") and
        pe.imports("kernel32.dll", "CheckRemoteDebuggerPresent")
}

// ===========================================================================
// Banking trojans / clippers.
// ===========================================================================
rule MAL_Clipper : stealer {
    meta:
        description = "clipboard cryptocurrency-address hijacker"
        severity = "high"
    strings:
        $a = "SetClipboardData"
        $b = "GetClipboardData"
        $c = "bc1q"
        $d = "0x"
        $e = "wallet"
    condition:
        (1 of ($a, $b)) and (1 of ($c, $e))
}

rule MAL_Ursnif : banker {
    meta:
        description = "Ursnif / Gozi-ISFB banking trojan"
    strings:
        $a = "Ursnif"
        $b = "ursnif"
        $c = "gozi_isfb"
    condition:
        1 of them
}

rule MAL_Zeus_Zbot : banker {
    meta:
        description = "Zeus / Zbot banking trojan"
    strings:
        $a = "ZeusVM"
        $b = "Zeus Trojan"
        $c = "zbot"
    condition:
        1 of them
}

rule MAL_SpyEye : banker {
    meta:
        description = "SpyEye banking trojan"
    strings:
        $a = "SpyEye"
        $b = "spyeye"
    condition:
        1 of them
}

rule MAL_Citadel : banker {
    meta:
        description = "Citadel banking trojan"
    strings:
        $a = "Citadel builder"
        $b = "citadel_"
        $c = "Citadel Trojan"
    condition:
        1 of them
}

rule MAL_Tinba : banker {
    meta:
        description = "Tinba (Tiny Banker) trojan"
    strings:
        $a = "Tinba"
        $b = "tinybanker"
    condition:
        1 of them
}

// ###########################################################################
// IoT / IIoT / OT / building-automation focused rules.
// ###########################################################################

// --- IoT botnet families (MIPS/ARM ELF droppers) ---------------------------
rule IOT_Hajime : botnet {
    meta:
        description = "Hajime IoT worm"
    strings:
        $a = "hajime"
        $b = "Hajime"
        $c = "atk.conf"
    condition:
        1 of them
}

rule IOT_HideNSeek : botnet {
    meta:
        description = "Hide and Seek (HNS) IoT botnet"
    strings:
        $a = "hidenseek"
        $b = "Hide N Seek"
        $c = "hns_bot"
    condition:
        1 of them
}

rule IOT_DarkNexus : botnet {
    meta:
        description = "dark_nexus IoT botnet"
    strings:
        $a = "dark_nexus"
        $b = "darknexus"
    condition:
        1 of them
}

rule IOT_Torii : botnet {
    meta:
        description = "Torii IoT botnet"
    strings:
        $a = "torii_bot"
        $b = "/.tmp/Torii"
        $c = "Torii botnet"
    condition:
        1 of them
}

rule IOT_Persirai : botnet {
    meta:
        description = "Persirai IP-camera botnet"
    strings:
        $a = "persirai"
        $b = "Persirai"
    condition:
        1 of them
}

rule IOT_Reaper_IoTroop : botnet {
    meta:
        description = "Reaper / IoTroop botnet"
    strings:
        $a = "IoTroop"
        $b = "IoTReaper"
        $c = "reaper_bot"
    condition:
        1 of them
}

rule IOT_BrickerBot : botnet {
    meta:
        description = "BrickerBot permanent-DoS malware"
    strings:
        $a = "BrickerBot"
        $b = "brickerbot"
    condition:
        1 of them
}

rule IOT_VPNFilter : botnet {
    meta:
        description = "VPNFilter router malware"
    strings:
        $a = "vpnfilter"
        $b = "VPNFilter"
        $c = "/var/run/vpnfilterw"
        $d = "ndbr"
    condition:
        1 of ($a, $b, $c)
}

rule IOT_CyclopsBlink : botnet {
    meta:
        description = "Cyclops Blink router botnet (Sandworm)"
    strings:
        $a = "Cyclops Blink"
        $b = "cyclopsblink"
    condition:
        1 of them
}

rule IOT_QSnatch : backdoor {
    meta:
        description = "QSnatch QNAP NAS malware"
    strings:
        $a = "QSnatch"
        $b = "qsnatch"
        $c = "/share/MD0_DATA/Qsync"
    condition:
        1 of ($a, $b)
}

rule IOT_Moobot : botnet {
    meta:
        description = "Moobot (Mirai-based) botnet"
    strings:
        $a = "Moobot"
        $b = "moobot"
        $c = "w5q6he3dbrsgmclkiu4t"
    condition:
        1 of them
}

rule IOT_Enemybot : botnet {
    meta:
        description = "EnemyBot IoT botnet (Keksec)"
    strings:
        $a = "EnemyBot"
        $b = "enemybot"
        $c = "ENEMScanner"
    condition:
        1 of them
}

rule IOT_Zerobot : botnet {
    meta:
        description = "Zerobot Go-based IoT botnet"
    strings:
        $a = "zerobot"
        $b = "Zerobot"
        $c = "selfRepo/zero"
    condition:
        1 of them
}

rule IOT_RapperBot : botnet {
    meta:
        description = "RapperBot SSH brute-force IoT botnet"
    strings:
        $a = "RapperBot"
        $b = "rapperbot"
    condition:
        1 of them
}

rule IOT_Mukashi : botnet {
    meta:
        description = "Mukashi Mirai variant (Zyxel NAS)"
    strings:
        $a = "Mukashi"
        $b = "mukashi"
    condition:
        1 of them
}

rule IOT_Echobot : botnet {
    meta:
        description = "Echobot Mirai variant"
    strings:
        $a = "Echobot"
        $b = "echobot"
    condition:
        1 of them
}

rule IOT_Fbot : botnet {
    meta:
        description = "Fbot Satori-derived botnet"
    strings:
        $a = "Fbot"
        $b = "fbot_"
        $c = "musl-Fbot"
    condition:
        1 of ($b, $c) or $a
}

rule IOT_Matryosh : botnet {
    meta:
        description = "Matryosh Android-ADB botnet"
    strings:
        $a = "Matryosh"
        $b = "matryosh"
    condition:
        1 of them
}

rule IOT_Condi : botnet {
    meta:
        description = "Condi Mirai-based botnet"
    strings:
        $a = "condi_botnet"
        $b = "Condi by"
        $c = "CondiNetwork"
    condition:
        1 of them
}

rule IOT_Kaiji : botnet {
    meta:
        description = "Kaiji Go-based Linux/IoT DDoS bot"
    strings:
        $a = "kaiji"
        $b = "Kaiji"
        $c = "demo.bot"
    condition:
        1 of ($a, $b)
}

rule IOT_BotenaGo : botnet {
    meta:
        description = "BotenaGo multi-exploit IoT botnet"
    strings:
        $a = "BotenaGo"
        $b = "botenago"
    condition:
        1 of them
}

rule IOT_Chalubo : botnet {
    meta:
        description = "Chalubo (ChaCha) Linux DDoS bot"
    strings:
        $a = "Chalubo"
        $b = "chalubo"
    condition:
        1 of them
}

rule IOT_Katana : botnet {
    meta:
        description = "Katana (Mirai-based) botnet"
    strings:
        $a = "katana_bot"
        $b = "Katana botnet"
        $c = "KATANA_"
    condition:
        1 of them
}

rule IOT_Pinkbot : botnet {
    meta:
        description = "Pink (Pinkbot) IoT botnet"
    strings:
        $a = "pink_bot"
        $b = "Pinkbot"
    condition:
        1 of them
}

// --- IoT loader / dropper / device-exploit patterns ------------------------
rule IOT_MultiArch_Loader : dropper {
    meta:
        description = "multi-architecture IoT download-and-run loader"
        severity = "high"
    strings:
        $w = "wget http"
        $t = "tftp -g"
        $c = "chmod 777"
        $b = "busybox"
        $arch = "mips mpsl arm"
    condition:
        (1 of ($w, $t)) and $c and ($b or $arch)
}

rule IOT_Busybox_Wget_Chmod : dropper {
    meta:
        description = "busybox wget/tftp + chmod IoT dropper"
        severity = "high"
    strings:
        $a = "/bin/busybox wget"
        $b = "/bin/busybox tftp"
        $c = "chmod 777"
    condition:
        (1 of ($a, $b)) and $c
}

rule IOT_TFTP_Dropper : dropper {
    meta:
        description = "TFTP-based IoT payload retrieval"
        severity = "high"
    strings:
        $a = "tftp -g -r"
        $b = "tftp -r "
        $c = "tftp -g "
        $d = "chmod +x"
    condition:
        (1 of ($a, $b, $c)) and $d
}

rule IOT_HNAP_CmdInjection : exploit {
    meta:
        description = "D-Link HNAP command injection"
        severity = "high"
    strings:
        $a = "HNAP1"
        $b = "GetDeviceSettings"
        $c = "SOAPAction"
    condition:
        $a and (1 of ($b, $c))
}

rule IOT_UPnP_SOAP_Inject : exploit {
    meta:
        description = "UPnP SOAP AddPortMapping abuse"
        severity = "medium"
    strings:
        $a = "AddPortMapping"
        $b = "NewInternalClient"
        $c = "urn:schemas-upnp-org"
    condition:
        $a and (1 of ($b, $c))
}

rule IOT_TR064_Exploit : exploit {
    meta:
        description = "TR-064 CPE WAN management exploit"
        severity = "high"
    strings:
        $a = "X_AVM-DE_"
        $b = "urn:dslforum-org"
        $c = "NewNTPServer1"
    condition:
        $b and (1 of ($a, $c))
}

rule IOT_Realtek_SDK_Inject : exploit {
    meta:
        description = "Realtek SDK formSysCmd command injection"
        severity = "high"
    strings:
        $a = "formSysCmd"
        $b = "sysCmd="
    condition:
        1 of them
}

rule IOT_GoAhead_Cam_Exploit : exploit {
    meta:
        description = "GoAhead IP-camera credential/exploit access"
        severity = "high"
    strings:
        $a = "system.ini?loginuse"
        $b = "loginpas"
        $c = "/system.ini%3F"
    condition:
        $a or ($b and $c)
}

rule IOT_Netgear_DGN_Exploit : exploit {
    meta:
        description = "Netgear DGN setup.cgi command injection"
        severity = "high"
    strings:
        $a = "setup.cgi?next_file=netgear.cfg"
        $b = "todo=syscmd"
    condition:
        $a or $b
}

rule IOT_DLink_HNAP_RCE : exploit {
    meta:
        description = "D-Link /HNAP1/ remote code execution"
        severity = "high"
    strings:
        $a = "/HNAP1/"
        $b = "RunTime"
        $c = "GetDeviceSettings"
    condition:
        $a and (1 of ($b, $c))
}

rule IOT_Jaws_Webserver : exploit {
    meta:
        description = "JAWS DVR webserver shell command"
        severity = "high"
    strings:
        $a = "/shell?"
        $b = "JAWS/1.0"
    condition:
        $b and $a
}

rule IOT_Default_Cred_List : recon {
    meta:
        description = "Mirai-style default-credential table"
        severity = "high"
    strings:
        $a = "root xc3511"
        $b = "root vizxv"
        $c = "root 7ujMko0"
        $d = "admin admin1234"
        $e = "root klv123"
    condition:
        2 of them
}

// --- OT / ICS protocols & tooling ------------------------------------------
rule OT_Modbus : icsproto {
    meta:
        description = "Modbus protocol library / client usage"
        severity = "medium"
    strings:
        $a = "pymodbus"
        $b = "libmodbus"
        $c = "modbus-cli"
        $d = "modbus_tk"
        $e = "ModbusTCP"
    condition:
        1 of them
}

rule OT_S7comm_Siemens : icsproto {
    meta:
        description = "Siemens S7comm protocol tooling"
        severity = "medium"
    strings:
        $a = "libnodave"
        $b = "Snap7"
        $c = "s7comm"
        $d = "python-snap7"
    condition:
        1 of them
}

rule OT_DNP3 : icsproto {
    meta:
        description = "DNP3 protocol tooling"
        severity = "medium"
    strings:
        $a = "opendnp3"
        $b = "pydnp3"
        $c = "dnp3_master"
    condition:
        1 of them
}

rule OT_EtherNetIP_CIP : icsproto {
    meta:
        description = "EtherNet/IP CIP protocol tooling"
        severity = "medium"
    strings:
        $a = "cpppo"
        $b = "pycomm3"
        $c = "EtherNet/IP"
        $d = "enip_cip"
    condition:
        1 of them
}

rule OT_BACnet : bas {
    meta:
        description = "BACnet building-automation protocol tooling"
        severity = "medium"
    strings:
        $a = "bacpypes"
        $b = "bacnet-stack"
        $c = "BACnet/IP"
        $d = "WhoIsRequest"
    condition:
        1 of them
}

rule OT_Profinet : icsproto {
    meta:
        description = "PROFINET protocol tooling"
        severity = "medium"
    strings:
        $a = "pn_dcp"
        $b = "p-net"
        $c = "profinet_io"
        $d = "PNIO"
    condition:
        1 of them
}

rule OT_IEC61850_MMS : icsproto {
    meta:
        description = "IEC 61850 MMS/GOOSE tooling"
        severity = "medium"
    strings:
        $a = "libiec61850"
        $b = "IEC61850"
        $c = "MmsValue"
        $d = "GoCBRef"
    condition:
        1 of them
}

rule OT_IEC104 : icsproto {
    meta:
        description = "IEC 60870-5-104 protocol tooling"
        severity = "medium"
    strings:
        $a = "lib60870"
        $b = "iec104"
        $c = "IEC 60870-5-104"
    condition:
        1 of them
}

rule OT_OPCUA : icsproto {
    meta:
        description = "OPC UA protocol tooling"
        severity = "medium"
    strings:
        $a = "open62541"
        $b = "UA_Client"
        $c = "opcua"
        $d = "OPC UA"
    condition:
        1 of them
}

rule OT_OPC_DA : icsproto {
    meta:
        description = "OPC DA (classic) protocol tooling"
        severity = "medium"
    strings:
        $a = "OPCEnum"
        $b = "opcda"
        $c = "IOPCServer"
    condition:
        1 of them
}

rule OT_Niagara_Fox : bas {
    meta:
        description = "Tridium Niagara Fox protocol"
        severity = "medium"
    strings:
        $a = "fox a 1"
        $b = "Tridium"
        $c = "niagara"
        $d = "baja"
    condition:
        1 of ($a, $b) or ($c and $d)
}

rule OT_CODESYS : icsproto {
    meta:
        description = "CODESYS PLC runtime/tooling"
        severity = "high"
    strings:
        $a = "CODESYS"
        $b = "codesys"
        $c = "3S-Smart"
        $d = "CmpApp"
    condition:
        1 of them
}

rule OT_Omron_FINS : icsproto {
    meta:
        description = "Omron FINS protocol tooling"
        severity = "medium"
    strings:
        $a = "FINS/TCP"
        $b = "finsudp"
        $c = "OMRON FINS"
    condition:
        1 of them
}

rule OT_Melsoft_Mitsubishi : icsproto {
    meta:
        description = "Mitsubishi MELSOFT/MELSEC SLMP tooling"
        severity = "medium"
    strings:
        $a = "MELSOFT"
        $b = "MELSEC"
        $c = "SLMP"
    condition:
        1 of them
}

rule OT_GE_SRTP : icsproto {
    meta:
        description = "GE SRTP protocol tooling"
        severity = "medium"
    strings:
        $a = "GE-SRTP"
        $b = "ge_srtp"
    condition:
        1 of them
}

rule OT_HART_IP : icsproto {
    meta:
        description = "HART-IP protocol tooling"
        severity = "medium"
    strings:
        $a = "HART-IP"
        $b = "hart_ip"
        $c = "WirelessHART"
    condition:
        1 of them
}

rule OT_KNX : bas {
    meta:
        description = "KNX/EIB building-automation protocol tooling"
        severity = "medium"
    strings:
        $a = "KNXnet/IP"
        $b = "knxnet"
        $c = "EIBnet"
        $d = "eibd"
    condition:
        1 of them
}

rule OT_LonWorks : bas {
    meta:
        description = "LonWorks/LonTalk building-automation tooling"
        severity = "medium"
    strings:
        $a = "LonWorks"
        $b = "LonTalk"
        $c = "Echelon"
    condition:
        1 of them
}

rule OT_MBus : icsproto {
    meta:
        description = "Meter-Bus (M-Bus) tooling"
        severity = "medium"
    strings:
        $a = "libmbus"
        $b = "Meter-Bus"
        $c = "M-Bus master"
    condition:
        1 of them
}

rule OT_PLCScan_Tool : recon {
    meta:
        description = "plcscan ICS reconnaissance tool"
        severity = "high"
    strings:
        $a = "plcscan"
        $b = "PLCScan"
    condition:
        1 of them
}

rule OT_S7Scan_Tool : recon {
    meta:
        description = "s7scan Siemens PLC scanner"
        severity = "high"
    strings:
        $a = "s7scan"
        $b = "s7-brute"
    condition:
        1 of them
}

rule OT_Modbus_Attack_Tool : offensive {
    meta:
        description = "Modbus offensive tooling (smod / MBTuninja)"
        severity = "high"
    strings:
        $a = "smod modbus"
        $b = "MBTuninja"
        $c = "modbus-cli --wr"
    condition:
        1 of them
}

// --- OT / ICS malware families ---------------------------------------------
rule OT_Industroyer : icsmalware {
    meta:
        description = "Industroyer / CrashOverride grid malware"
    strings:
        $a = "Industroyer"
        $b = "CrashOverride"
        $c = "haslo.dat"
    condition:
        1 of them
}

rule OT_Industroyer2 : icsmalware {
    meta:
        description = "Industroyer2 IEC-104 grid malware"
    strings:
        $a = "Industroyer2"
        $b = "industroyer2"
        $c = "PServiceControl.exe"
    condition:
        1 of them
}

rule OT_Triton_Trisis : icsmalware {
    meta:
        description = "TRITON / TRISIS / HatMan safety-system malware"
    strings:
        $a = "TRISIS"
        $b = "HatMan"
        $c = "trilog.exe"
        $d = "imain.bin"
        $e = "script_test.py"
    condition:
        1 of ($a, $b, $c, $d)
}

rule OT_Havex : icsmalware {
    meta:
        description = "Havex / Dragonfly OPC-scanning RAT"
    strings:
        $a = "havex"
        $b = "fertger"
        $c = "Karagany"
        $d = "sysmain.dll"
    condition:
        1 of ($a, $b, $c)
}

rule OT_BlackEnergy : icsmalware {
    meta:
        description = "BlackEnergy grid-attack malware"
    strings:
        $a = "BlackEnergy"
        $b = "blackenergy"
        $c = "dstr.dll"
        $d = "KillDisk"
    condition:
        1 of them
}

rule OT_EKANS_Snake : ransomware {
    meta:
        description = "EKANS / Snake OT-aware ransomware"
    strings:
        $a = "EKANS"
        $b = "snakekill"
        $c = "Snake ransomware"
    condition:
        1 of them
}

rule OT_PIPEDREAM : icsmalware {
    meta:
        description = "PIPEDREAM / INCONTROLLER ICS attack framework"
    strings:
        $a = "PIPEDREAM"
        $b = "INCONTROLLER"
        $c = "TAGRUN"
        $d = "OPENF1G"
    condition:
        1 of them
}

rule OT_IRONGATE : icsmalware {
    meta:
        description = "IRONGATE ICS PoC malware"
    strings:
        $a = "IRONGATE"
        $b = "irongate"
    condition:
        1 of them
}

rule OT_Fuxnet : icsmalware {
    meta:
        description = "Fuxnet ICS/sensor-gateway malware"
    strings:
        $a = "Fuxnet"
        $b = "fuxnet"
    condition:
        1 of them
}

rule OT_CosmicEnergy : icsmalware {
    meta:
        description = "CosmicEnergy IEC-104 grid malware"
    strings:
        $a = "CosmicEnergy"
        $b = "cosmicenergy"
        $c = "Lightwork"
        $d = "PieHop"
    condition:
        1 of them
}

rule OT_FrostyGoop : icsmalware {
    meta:
        description = "FrostyGoop / BUSTLEBERM Modbus malware"
    strings:
        $a = "FrostyGoop"
        $b = "BUSTLEBERM"
        $c = "frostygoop"
    condition:
        1 of them
}

rule OT_Conficker : worm {
    meta:
        description = "Conficker / Downadup worm (common on OT networks)"
    strings:
        $a = "Conficker"
        $b = "conficker"
        $c = "downadup"
    condition:
        1 of them
}

// --- Building automation / smart-building product references ---------------
rule BAS_Tridium_Niagara : bas {
    meta:
        description = "Tridium Niagara building-automation framework"
        severity = "medium"
    strings:
        $a = "Niagara Framework"
        $b = "Tridium"
        $c = "station.fox"
        $d = "niagara_home"
    condition:
        1 of them
}

rule BAS_JohnsonControls_Metasys : bas {
    meta:
        description = "Johnson Controls Metasys BAS"
        severity = "medium"
    strings:
        $a = "Metasys"
        $b = "Johnson Controls"
    condition:
        1 of them
}

rule BAS_Siemens_Desigo : bas {
    meta:
        description = "Siemens Desigo building-control system"
        severity = "medium"
    strings:
        $a = "Desigo"
        $b = "Siemens Desigo"
        $c = "PXC Modular"
    condition:
        1 of them
}

rule BAS_Honeywell_EBI : bas {
    meta:
        description = "Honeywell EBI / WEBs building system"
        severity = "medium"
    strings:
        $a = "Honeywell EBI"
        $b = "WEBs-AX"
        $c = "WEBStation-AX"
    condition:
        1 of them
}

rule BAS_Schneider_EcoStruxure : bas {
    meta:
        description = "Schneider EcoStruxure / StruxureWare BAS"
        severity = "medium"
    strings:
        $a = "EcoStruxure"
        $b = "StruxureWare"
        $c = "Andover Continuum"
        $d = "TAC Vista"
    condition:
        1 of them
}

rule BAS_AutomatedLogic_WebCTRL : bas {
    meta:
        description = "Automated Logic WebCTRL BAS"
        severity = "medium"
    strings:
        $a = "WebCTRL"
        $b = "Automated Logic"
    condition:
        1 of them
}

rule BAS_Delta_Controls : bas {
    meta:
        description = "Delta Controls ORCAview / enteliWEB BAS"
        severity = "medium"
    strings:
        $a = "Delta Controls"
        $b = "ORCAview"
        $c = "enteliWEB"
    condition:
        1 of them
}

rule BAS_Distech_ECNet : bas {
    meta:
        description = "Distech Controls EC-Net / ECLYPSE BAS"
        severity = "medium"
    strings:
        $a = "Distech Controls"
        $b = "EC-Net"
        $c = "ECLYPSE"
    condition:
        1 of them
}

rule BAS_Reliable_Controls : bas {
    meta:
        description = "Reliable Controls RC-WebView BAS"
        severity = "medium"
    strings:
        $a = "Reliable Controls"
        $b = "RC-WebView"
        $c = "MACH-ProWeb"
    condition:
        1 of them
}

rule BAS_KNX_ETS : bas {
    meta:
        description = "KNX ETS project artifacts"
        severity = "medium"
    strings:
        $a = "knxproj"
        $b = "ETS5"
        $c = "ETS6"
    condition:
        1 of them
}

rule BAS_Crestron_Control : bas {
    meta:
        description = "Crestron control-system tooling"
        severity = "medium"
    strings:
        $a = "Crestron Toolbox"
        $b = "SIMPL Windows"
        $c = "Crestron Fusion"
    condition:
        1 of them
}

rule BAS_AMX_NetLinx : bas {
    meta:
        description = "AMX NetLinx control system"
        severity = "medium"
    strings:
        $a = "AMX NetLinx"
        $b = "NetLinx Studio"
        $c = "Duet module"
    condition:
        1 of them
}

rule BAS_Lutron : bas {
    meta:
        description = "Lutron lighting/control system"
        severity = "medium"
    strings:
        $a = "Lutron HomeWorks"
        $b = "Lutron Caseta"
        $c = "QuantumLogic"
    condition:
        1 of them
}

rule BAS_DALI_Lighting : bas {
    meta:
        description = "DALI lighting-control bus tooling"
        severity = "medium"
    strings:
        $a = "DALI gateway"
        $b = "DALI-2"
        $c = "DALI bus"
    condition:
        1 of them
}

// --- Smart-home / consumer IoT & firmware ----------------------------------
rule IOT_MQTT_Abuse : iot {
    meta:
        description = "MQTT broker abuse / enumeration"
        severity = "medium"
    strings:
        $a = "mosquitto_pub"
        $b = "$SYS/broker"
        $c = "paho.mqtt"
    condition:
        1 of them
}

rule IOT_CoAP_Probe : iot {
    meta:
        description = "CoAP endpoint probing"
        severity = "medium"
    strings:
        $a = "coap://"
        $b = "coap-client"
        $c = ".well-known/core"
    condition:
        1 of ($a, $b) or ($a and $c)
}

rule IOT_Zigbee_Attack : iot {
    meta:
        description = "Zigbee attack tooling (KillerBee)"
        severity = "high"
    strings:
        $a = "KillerBee"
        $b = "zbstumbler"
        $c = "zbreplay"
    condition:
        1 of them
}

rule IOT_ZWave_Attack : iot {
    meta:
        description = "Z-Wave attack tooling"
        severity = "medium"
    strings:
        $a = "EZ-Wave"
        $b = "Z-Wave sniffer"
        $c = "zwave_attack"
    condition:
        1 of them
}

rule IOT_BLE_Attack : iot {
    meta:
        description = "Bluetooth Low Energy attack tooling"
        severity = "medium"
    strings:
        $a = "btlejack"
        $b = "gatttool"
        $c = "hcitool lescan"
    condition:
        1 of them
}

rule IOT_RTSP_Cam_Bruteforce : offensive {
    meta:
        description = "RTSP camera brute-force tooling"
        severity = "high"
    strings:
        $a = "Cameradar"
        $b = "rtsp_brute"
        $c = "cameradar"
    condition:
        1 of them
}

rule IOT_ONVIF_Probe : iot {
    meta:
        description = "ONVIF camera enumeration"
        severity = "medium"
    strings:
        $a = "GetDeviceInformation"
        $b = "ver10/device/wsdl"
        $c = "onvif"
    condition:
        $b or ($c and $a)
}

rule IOT_UART_JTAG_Debug : iot {
    meta:
        description = "hardware UART/JTAG debugging artifacts"
        severity = "medium"
    strings:
        $a = "openocd"
        $b = "jtag newtap"
        $c = "urjtag"
    condition:
        1 of them
}

rule IOT_Firmware_Squashfs : firmware {
    meta:
        description = "SquashFS firmware filesystem image"
        severity = "medium"
    strings:
        $a = "sqsh"
        $b = "hsqs"
        $c = "squashfs"
    condition:
        1 of them
}

rule IOT_Firmware_UBoot : firmware {
    meta:
        description = "U-Boot bootloader firmware artifacts"
        severity = "medium"
    strings:
        $a = "U-Boot 20"
        $b = "bootargs="
        $c = "Uncompressing Linux"
    condition:
        1 of them
}

rule IOT_Binwalk_Analysis : recon {
    meta:
        description = "binwalk firmware analysis artifacts"
        severity = "medium"
    strings:
        $a = "binwalk"
        $b = "DECIMAL       HEXADECIMAL"
    condition:
        1 of them
}

rule IOT_GPON_Exploit : exploit {
    meta:
        description = "GPON home-router exploit (CVE-2018-10561 class)"
        severity = "high"
    strings:
        $a = "GponForm"
        $b = "/diag_Form"
        $c = "XWebPageName=diag"
    condition:
        1 of them
}

rule IOT_Dahua_Exploit : exploit {
    meta:
        description = "Dahua DVR/camera credential exploit"
        severity = "high"
    strings:
        $a = "/current_config/passwd"
        $b = "RPC2_Login"
    condition:
        1 of them
}

rule IOT_Hikvision_Exploit : exploit {
    meta:
        description = "Hikvision camera auth-bypass exploit"
        severity = "high"
    strings:
        $a = "/system/deviceInfo?auth="
        $b = "/onvif-http/snapshot?auth="
    condition:
        1 of them
}

rule IOT_Webcam_Backdoor : backdoor {
    meta:
        description = "IP-camera web backdoor endpoints"
        severity = "medium"
    strings:
        $a = "/cgi-bin/supervisor/"
        $b = "CloudSetup.htm"
        $c = "wireless_mft"
    condition:
        1 of them
}

rule IIOT_SCADA_HMI_Products : scada {
    meta:
        description = "SCADA/HMI product references (FactoryTalk/WinCC/Ignition/...)"
        severity = "medium"
    strings:
        $a = "FactoryTalk"
        $b = "Wonderware"
        $c = "WinCC"
        $d = "iFIX"
        $e = "Ignition Gateway"
        $f = "Vijeo Citect"
    condition:
        1 of them
}

// ###########################################################################
// IoT / IIoT / OT / building-automation rules (set 2).
// ###########################################################################

// --- More IoT botnet / malware families ------------------------------------
rule IOT_AESDDoS : botnet {
    meta:
        description = "AESDDoS / Dofloo Linux DDoS bot"
    strings:
        $a = "AESDDoS"
        $b = "aes.ddos"
        $c = "Dofloo"
    condition:
        1 of them
}

rule IOT_Ddostf : botnet {
    meta:
        description = "Ddostf Linux/Windows DDoS bot"
    strings:
        $a = "Ddostf"
        $b = "ddostf"
    condition:
        1 of them
}

rule IOT_Setag_Billgates : botnet {
    meta:
        description = "BillGates / Setag Linux DDoS bot"
    strings:
        $a = "BillGates"
        $b = "/tmp/gates.lod"
        $c = "Setag"
    condition:
        1 of them
}

rule IOT_Luabot : botnet {
    meta:
        description = "LuaBot IoT botnet"
    strings:
        $a = "LuaBot"
        $b = "luabot"
    condition:
        1 of them
}

rule IOT_LightAidra : botnet {
    meta:
        description = "LightAidra / Aidra IoT bot"
    strings:
        $a = "lightaidra"
        $b = "aidra"
        $c = "znaty"
    condition:
        1 of ($a, $c) or ($b and $c)
}

rule IOT_Remaiten : botnet {
    meta:
        description = "Remaiten (KTN-RM) IoT bot"
    strings:
        $a = "KTN-RM"
        $b = "KTN-Remastered"
        $c = "Remaiten"
    condition:
        1 of them
}

rule IOT_Psybot : botnet {
    meta:
        description = "psyb0t IoT worm"
    strings:
        $a = "psyb0t"
        $b = "Psybot"
    condition:
        1 of them
}

rule IOT_Nyadrop : botnet {
    meta:
        description = "Nyadrop IoT dropper"
    strings:
        $a = "Nyadrop"
        $b = "nyadrop"
    condition:
        1 of them
}

rule IOT_IRCTelnet : botnet {
    meta:
        description = "IRCTelnet (new Aidra) IoT bot"
    strings:
        $a = "IRCTelnet"
        $b = "irctelnet"
        $c = "newaidra"
    condition:
        1 of them
}

rule IOT_Wifatch : botnet {
    meta:
        description = "Linux.Wifatch vigilante IoT malware"
    strings:
        $a = "Wifatch"
        $b = "wifatch"
    condition:
        1 of them
}

rule IOT_BCMUPnPHunter : botnet {
    meta:
        description = "BCMUPnP_Hunter router botnet"
    strings:
        $a = "BCMUPnP"
        $b = "BCMPUPNP_Hunter"
        $c = "bcmupnp"
    condition:
        1 of them
}

rule IOT_Prowli : botnet {
    meta:
        description = "Prowli multi-platform botnet"
    strings:
        $a = "Prowli"
        $b = "prowli"
        $c = "r2r2"
    condition:
        1 of ($a, $c)
}

rule IOT_ADBMiner : coinminer {
    meta:
        description = "ADB.Miner Android ADB cryptominer"
    strings:
        $a = "ADB.Miner"
        $b = "adb.miner"
        $c = "android_adb_miner"
    condition:
        1 of them
}

rule IOT_Roboto : botnet {
    meta:
        description = "Roboto P2P botnet"
    strings:
        $a = "Roboto botnet"
        $b = "roboto_"
    condition:
        1 of them
}

rule IOT_DarkIoT : botnet {
    meta:
        description = "Dark.IoT botnet"
    strings:
        $a = "Dark.IoT"
        $b = "darkiot"
    condition:
        1 of them
}

rule IOT_Mirai_Wicked : botnet {
    meta:
        description = "WICKED Mirai variant"
    strings:
        $a = "WICKED"
        $b = "wicked mirai"
        $c = "SoraLOADER"
    condition:
        1 of ($b, $c) or $a
}

rule IOT_Mirai_Owari : botnet {
    meta:
        description = "Owari Mirai variant"
    strings:
        $a = "Owari"
        $b = "owari"
    condition:
        1 of them
}

rule IOT_Mirai_Josho : botnet {
    meta:
        description = "Josho Mirai variant"
    strings:
        $a = "Josho"
        $b = "josho"
    condition:
        1 of them
}

rule IOT_Mirai_Sora : botnet {
    meta:
        description = "Sora Mirai variant"
    strings:
        $a = "Sora botnet"
        $b = "SORA_"
        $c = "/bin/busybox SORA"
    condition:
        1 of them
}

rule IOT_FreakOut : botnet {
    meta:
        description = "FreakOut (N3Cr0m0rPh) Linux malware"
    strings:
        $a = "FreakOut"
        $b = "N3Cr0m0rPh"
    condition:
        1 of them
}

rule IOT_Necro : botnet {
    meta:
        description = "Necro / FreakOut Python bot"
    strings:
        $a = "N3Cr0m"
        $b = "Necro.py"
        $c = "necrobot"
    condition:
        1 of them
}

rule IOT_Gitpaste12 : botnet {
    meta:
        description = "Gitpaste-12 wormable botnet"
    strings:
        $a = "Gitpaste-12"
        $b = "gitpaste"
    condition:
        1 of them
}

rule IOT_Medusa_Botnet : botnet {
    meta:
        description = "Medusa IoT DDoS botnet (Mirai-based)"
    strings:
        $a = "Medusa IoT"
        $b = "medusa_botnet"
        $c = "MedusaHTTP"
    condition:
        1 of them
}

rule IOT_Spike_DDoS : botnet {
    meta:
        description = "Spike / Dofloo DDoS toolkit"
    strings:
        $a = "Spike DDoS"
        $b = "spike toolkit"
    condition:
        1 of them
}

// --- More router / camera device-exploit patterns --------------------------
rule IOT_Linksys_JNAP : exploit {
    meta:
        description = "Linksys Smart Wi-Fi JNAP exploit"
        severity = "high"
    strings:
        $a = "/JNAP/"
        $b = "X-JNAP-Action"
    condition:
        1 of them
}

rule IOT_MikroTik_Winbox : exploit {
    meta:
        description = "MikroTik RouterOS Winbox / nova exploit"
        severity = "high"
    strings:
        $a = "/nova/bin"
        $b = "Winbox"
        $c = "RouterOS"
    condition:
        $a or ($b and $c)
}

rule IOT_ASUS_Infosvr : exploit {
    meta:
        description = "ASUS infosvr LAN command execution"
        severity = "high"
    strings:
        $a = "infosvr"
        $b = "ASUSWRT"
        $c = "asusrouter"
    condition:
        $a or ($b and $c)
}

rule IOT_Huawei_HG_UPnP : exploit {
    meta:
        description = "Huawei HG router UPnP command injection"
        severity = "high"
    strings:
        $a = "/ctrlt/DeviceUpgrade"
        $b = "NewStatusURL"
        $c = "NewDownloadURL"
    condition:
        $a or ($b and $c)
}

rule IOT_ZTE_Router : exploit {
    meta:
        description = "ZTE router web shell command injection"
        severity = "high"
    strings:
        $a = "/web_shell_cmd.gjs"
        $b = "set_cmd_process"
    condition:
        1 of them
}

rule IOT_Vacron_NVR : exploit {
    meta:
        description = "Vacron NVR board.cgi command injection"
        severity = "high"
    strings:
        $a = "/board.cgi"
        $b = "cmd=cat"
    condition:
        $a and $b
}

rule IOT_Foscam_Cam : exploit {
    meta:
        description = "Foscam camera CGI access"
        severity = "high"
    strings:
        $a = "/decoder_control.cgi"
        $b = "/get_status.cgi"
        $c = "foscam"
    condition:
        1 of ($a, $b)
}

rule IOT_Axis_VAPIX : exploit {
    meta:
        description = "Axis camera VAPIX CGI access"
        severity = "high"
    strings:
        $a = "/axis-cgi/"
        $b = "VAPIX"
        $c = "param.cgi?action="
    condition:
        $b or ($a and $c)
}

rule IOT_Vivotek_Cam : exploit {
    meta:
        description = "Vivotek camera exploit"
        severity = "high"
    strings:
        $a = "/cgi-bin/admin/getparam.cgi"
        $b = "vivotek"
    condition:
        1 of them
}

rule IOT_Geovision_Cam : exploit {
    meta:
        description = "GeoVision camera exploit"
        severity = "high"
    strings:
        $a = "/geo-cgi/"
        $b = "geovision"
    condition:
        1 of them
}

rule IOT_Sony_IPELA : exploit {
    meta:
        description = "Sony IPELA camera backdoor"
        severity = "high"
    strings:
        $a = "/command/inquiry.cgi"
        $b = "ipela"
        $c = "primana"
    condition:
        $a or ($b and $c)
}

rule IOT_Tenda_Goform : exploit {
    meta:
        description = "Tenda router goform command injection"
        severity = "high"
    strings:
        $a = "/goform/exeCommand"
        $b = "/goform/setUsbUnload"
        $c = "/goform/telnet"
    condition:
        1 of them
}

rule IOT_Totolink_CGI : exploit {
    meta:
        description = "TOTOLINK router CGI exploit"
        severity = "high"
    strings:
        $a = "/cgi-bin/downloadFlile.cgi"
        $b = "/cgi-bin/ExportSettings.sh"
        $c = "totolink"
    condition:
        1 of ($a, $b)
}

rule IOT_Draytek_Vigor : exploit {
    meta:
        description = "DrayTek Vigor mainfunction.cgi exploit"
        severity = "high"
    strings:
        $a = "/cgi-bin/mainfunction.cgi"
        $b = "keyPath="
        $c = "draytek"
    condition:
        $a and (1 of ($b, $c)) or $c
}

rule IOT_Sapido_Router : exploit {
    meta:
        description = "Sapido router syscmd exploit"
        severity = "high"
    strings:
        $a = "/syscmd.htm"
        $b = "sapido"
    condition:
        1 of them
}

rule IOT_Netgear_SOAP : exploit {
    meta:
        description = "Netgear SOAP (genie) command injection"
        severity = "high"
    strings:
        $a = "/soap/server_sa/"
        $b = "SOAPAction: urn:NETGEAR"
    condition:
        1 of them
}

// --- More OT/ICS protocols & vendor tooling --------------------------------
rule OT_PCWorx : icsproto {
    meta:
        description = "Phoenix Contact PCWorx protocol"
        severity = "medium"
    strings:
        $a = "PCWorx"
        $b = "pcworx"
        $c = "Phoenix Contact ILC"
    condition:
        1 of them
}

rule OT_Crimson_V3 : icsproto {
    meta:
        description = "Red Lion Crimson v3 protocol"
        severity = "medium"
    strings:
        $a = "Crimson v3"
        $b = "crimson3"
        $c = "Red Lion"
    condition:
        1 of ($a, $b) or ($c and $b)
}

rule OT_ProConOS : icsproto {
    meta:
        description = "ProConOS PLC runtime protocol"
        severity = "medium"
    strings:
        $a = "ProConOS"
        $b = "proconos"
    condition:
        1 of them
}

rule OT_EtherCAT : icsproto {
    meta:
        description = "EtherCAT fieldbus tooling"
        severity = "medium"
    strings:
        $a = "EtherCAT"
        $b = "SOEM"
        $c = "ecrt_"
    condition:
        1 of ($a, $b) or $c
}

rule OT_Powerlink : icsproto {
    meta:
        description = "Ethernet POWERLINK tooling"
        severity = "medium"
    strings:
        $a = "openPOWERLINK"
        $b = "EPL_"
        $c = "POWERLINK"
    condition:
        1 of ($a) or ($c and $b)
}

rule OT_Sercos : icsproto {
    meta:
        description = "SERCOS III motion-control protocol"
        severity = "medium"
    strings:
        $a = "SERCOS III"
        $b = "sercos"
    condition:
        1 of them
}

rule OT_ROC_Emerson : icsproto {
    meta:
        description = "Emerson ROC / FloBoss protocol"
        severity = "medium"
    strings:
        $a = "ROC Plus"
        $b = "Emerson ROC"
        $c = "FloBoss"
    condition:
        1 of them
}

rule OT_FoundationFieldbus : icsproto {
    meta:
        description = "Foundation Fieldbus HSE tooling"
        severity = "medium"
    strings:
        $a = "Foundation Fieldbus"
        $b = "FF-HSE"
    condition:
        1 of them
}

rule OT_ICCP_TASE2 : icsproto {
    meta:
        description = "ICCP / TASE.2 inter-control-center protocol"
        severity = "medium"
    strings:
        $a = "TASE.2"
        $b = "tase2"
        $c = "ICCP server"
    condition:
        1 of them
}

rule OT_DLMS_COSEM : icsproto {
    meta:
        description = "DLMS/COSEM smart-meter protocol"
        severity = "medium"
    strings:
        $a = "DLMS"
        $b = "COSEM"
        $c = "gurux.dlms"
    condition:
        1 of ($c) or ($a and $b)
}

rule OT_ANSI_C12 : icsproto {
    meta:
        description = "ANSI C12.18/C12.22 smart-meter protocol"
        severity = "medium"
    strings:
        $a = "ANSI C12.18"
        $b = "C12.22"
        $c = "ansi c12"
    condition:
        1 of them
}

rule OT_TwinCAT_ADS : icsproto {
    meta:
        description = "Beckhoff TwinCAT ADS protocol"
        severity = "medium"
    strings:
        $a = "TwinCAT"
        $b = "ADS protocol"
        $c = "AdsPort"
    condition:
        $a or ($b and $c)
}

rule OT_WAGO_PLC : icsproto {
    meta:
        description = "WAGO PLC fingerprint"
        severity = "medium"
    strings:
        $a = "WAGO 750-"
        $b = "wago plc"
        $c = "PFC200"
    condition:
        1 of them
}

rule OT_PLCnext_Phoenix : icsproto {
    meta:
        description = "Phoenix Contact PLCnext controller"
        severity = "medium"
    strings:
        $a = "PLCnext"
        $b = "plcnext"
        $c = "AXC F 2152"
    condition:
        1 of them
}

rule OT_BR_Automation : icsproto {
    meta:
        description = "B&R Automation Studio / X20 PLC"
        severity = "medium"
    strings:
        $a = "B&R Automation"
        $b = "Automation Studio"
        $c = "X20 PLC"
    condition:
        1 of them
}

rule OT_Kepware_OPC : icsproto {
    meta:
        description = "Kepware KEPServerEX OPC server"
        severity = "medium"
    strings:
        $a = "KEPServerEX"
        $b = "Kepware"
        $c = "kepserver"
    condition:
        1 of them
}

rule OT_Matrikon_OPC : icsproto {
    meta:
        description = "Matrikon OPC server"
        severity = "medium"
    strings:
        $a = "Matrikon OPC"
        $b = "matrikon"
    condition:
        1 of them
}

rule OT_ICSSploit : offensive {
    meta:
        description = "ICSSploit / Industrial Exploitation Framework"
        severity = "high"
    strings:
        $a = "icssploit"
        $b = "Industrial Exploitation Framework"
        $c = "isf >"
    condition:
        1 of them
}

rule OT_Nmap_ICS_Scripts : recon {
    meta:
        description = "Nmap NSE ICS discovery scripts"
        severity = "high"
    strings:
        $a = "s7-info"
        $b = "modbus-discover"
        $c = "bacnet-info"
        $d = "enip-info"
        $e = "omron-info"
    condition:
        2 of them
}

rule OT_Redpoint_Scripts : recon {
    meta:
        description = "Redpoint / Digital Bond ICS NSE scripts"
        severity = "high"
    strings:
        $a = "Redpoint"
        $b = "digitalbond"
        $c = "pcworx-info"
    condition:
        1 of ($a, $c) or ($b and $c)
}

rule OT_GRASSMARLIN : recon {
    meta:
        description = "GRASSMARLIN ICS network mapper"
        severity = "high"
    strings:
        $a = "GRASSMARLIN"
        $b = "grassmarlin"
    condition:
        1 of them
}

rule OT_PLCinject : offensive {
    meta:
        description = "plcinject S7 code-injection tool"
        severity = "high"
    strings:
        $a = "plcinject"
        $b = "PLCinject"
    condition:
        1 of them
}

rule OT_mbtget_Tool : recon {
    meta:
        description = "mbtget / mbpoll Modbus tooling"
        severity = "high"
    strings:
        $a = "mbtget"
        $b = "mbpoll"
    condition:
        1 of them
}

rule OT_Snap7_Client : recon {
    meta:
        description = "Snap7 S7 client usage"
        severity = "high"
    strings:
        $a = "Cli_ConnectTo"
        $b = "snap7 cli"
        $c = "Cli_DBRead"
    condition:
        1 of them
}

// --- More OT/ICS malware ---------------------------------------------------
rule OT_GreyEnergy : icsmalware {
    meta:
        description = "GreyEnergy espionage malware (Sandworm)"
    strings:
        $a = "GreyEnergy"
        $b = "greyenergy"
    condition:
        1 of them
}

rule OT_Exaramel : icsmalware {
    meta:
        description = "Exaramel Linux/Windows ICS backdoor"
    strings:
        $a = "Exaramel"
        $b = "exaramel"
        $c = "centreon"
    condition:
        1 of ($a, $b)
}

rule OT_KillDisk : icsmalware {
    meta:
        description = "KillDisk wiper (ICS-impacting)"
    strings:
        $a = "KillDisk"
        $b = "killdisk"
    condition:
        1 of them
}

rule OT_AcidRain : icsmalware {
    meta:
        description = "AcidRain / AcidPour modem-router wiper"
    strings:
        $a = "AcidRain"
        $b = "AcidPour"
        $c = "acidrain"
    condition:
        1 of them
}

rule OT_LookBack : icsmalware {
    meta:
        description = "LookBack / TAManager ICS-sector RAT"
    strings:
        $a = "LookBack"
        $b = "TAManager"
        $c = "GUP.exe proxy"
    condition:
        1 of ($a, $b)
}

rule OT_LockerGoga : ransomware {
    meta:
        description = "LockerGoga ransomware (industrial impact)"
    strings:
        $a = "LockerGoga"
        $b = "lockergoga"
        $c = "README-NOW.txt"
    condition:
        1 of ($a, $b)
}

rule OT_Cring : ransomware {
    meta:
        description = "Cring ransomware (OT-impacting)"
    strings:
        $a = "Cring ransomware"
        $b = "!!!README!!!cring"
        $c = ".cring"
    condition:
        1 of them
}

rule OT_MegaCortex : ransomware {
    meta:
        description = "MegaCortex ransomware (industrial impact)"
    strings:
        $a = "MegaCortex"
        $b = "megacortex"
    condition:
        1 of them
}

// --- More building automation product references ---------------------------
rule BAS_Siemens_APOGEE : bas {
    meta:
        description = "Siemens APOGEE building automation"
        severity = "medium"
    strings:
        $a = "APOGEE Insight"
        $b = "Siemens APOGEE"
    condition:
        1 of them
}

rule BAS_Carrier_iVu : bas {
    meta:
        description = "Carrier i-Vu building automation"
        severity = "medium"
    strings:
        $a = "i-Vu"
        $b = "Carrier i-Vu"
    condition:
        1 of them
}

rule BAS_Trane_Tracer : bas {
    meta:
        description = "Trane Tracer SC building automation"
        severity = "medium"
    strings:
        $a = "Tracer SC"
        $b = "Trane Tracer"
    condition:
        1 of them
}

rule BAS_Trend_IQ : bas {
    meta:
        description = "Trend Controls IQ building automation"
        severity = "medium"
    strings:
        $a = "Trend Controls"
        $b = "963 Supervisor"
        $c = "Trend IQ"
    condition:
        1 of them
}

rule BAS_Sauter : bas {
    meta:
        description = "Sauter moduWeb building automation"
        severity = "medium"
    strings:
        $a = "moduWeb"
        $b = "EY-modulo"
        $c = "Sauter"
    condition:
        1 of ($a, $b) or ($c and $a)
}

rule BAS_Iconics_Genesis : scada {
    meta:
        description = "Iconics GENESIS64 SCADA/BAS"
        severity = "medium"
    strings:
        $a = "GENESIS64"
        $b = "Iconics"
    condition:
        1 of them
}

rule BAS_ABB_Cylon : bas {
    meta:
        description = "ABB Cylon / Aspect building controls"
        severity = "medium"
    strings:
        $a = "ABB Cylon"
        $b = "Aspect Control"
        $c = "CBXi"
    condition:
        1 of ($a, $b)
}

rule BAS_Priva : bas {
    meta:
        description = "Priva building / horticulture automation"
        severity = "medium"
    strings:
        $a = "Priva Blue ID"
        $b = "Priva Compri"
    condition:
        1 of them
}

rule BAS_Loytec : bas {
    meta:
        description = "LOYTEC building-automation controllers"
        severity = "medium"
    strings:
        $a = "LOYTEC"
        $b = "LINX-"
        $c = "loytec"
    condition:
        1 of ($a, $c) or ($b and $a)
}

rule BAS_WattStopper : bas {
    meta:
        description = "WattStopper lighting control"
        severity = "medium"
    strings:
        $a = "WattStopper"
        $b = "wattstopper"
    condition:
        1 of them
}

rule BAS_Philips_Hue : bas {
    meta:
        description = "Philips Hue smart-lighting bridge"
        severity = "medium"
    strings:
        $a = "Philips hue"
        $b = "hue bridge"
        $c = "/api/config"
    condition:
        1 of ($a, $b) or ($c and $b)
}

rule BAS_KNX_Calimero : bas {
    meta:
        description = "Calimero KNX library"
        severity = "medium"
    strings:
        $a = "calimero"
        $b = "Calimero KNX"
    condition:
        1 of them
}

rule BAS_Niagara_N4 : bas {
    meta:
        description = "Tridium Niagara 4 (N4) station"
        severity = "medium"
    strings:
        $a = "Niagara 4"
        $b = "Niagara N4"
        $c = "N4 station"
    condition:
        1 of them
}

rule BAS_Schneider_SmartX : bas {
    meta:
        description = "Schneider SmartX / EcoStruxure Building Operation"
        severity = "medium"
    strings:
        $a = "SmartX Controller"
        $b = "SmartX server"
        $c = "StruxureWare Building"
    condition:
        1 of them
}

// --- Smart-meter / automotive / medical / maritime / transport / IoT proto --
rule AMI_SmartMeter_Tools : recon {
    meta:
        description = "smart-meter assessment tooling (Termineter)"
        severity = "high"
    strings:
        $a = "Termineter"
        $b = "termineter"
        $c = "smart meter framework"
    condition:
        1 of them
}

rule AUTO_CANbus_Tools : recon {
    meta:
        description = "CAN-bus tooling (can-utils)"
        severity = "high"
    strings:
        $a = "candump"
        $b = "cansend"
        $c = "cangen"
        $d = "can-utils"
    condition:
        2 of them
}

rule AUTO_UDS_Diag : offensive {
    meta:
        description = "automotive UDS diagnostics / CaringCaribou"
        severity = "high"
    strings:
        $a = "caringcaribou"
        $b = "ISO 14229"
        $c = "uds discovery"
    condition:
        1 of them
}

rule AUTO_J1939 : icsproto {
    meta:
        description = "SAE J1939 vehicle-bus tooling"
        severity = "medium"
    strings:
        $a = "SAE J1939"
        $b = "j1939"
    condition:
        1 of them
}

rule MED_DICOM : medical {
    meta:
        description = "DICOM medical-imaging protocol/file"
        severity = "medium"
    strings:
        $a = "DICM"
        $b = "application/dicom"
        $c = "dcm4che"
    condition:
        1 of them
}

rule MED_HL7 : medical {
    meta:
        description = "HL7 v2 healthcare messaging"
        severity = "medium"
    strings:
        $a = "MSH|^~\\&"
        $b = "HL7 message"
    condition:
        1 of them
}

rule MED_FHIR : medical {
    meta:
        description = "HL7 FHIR healthcare API"
        severity = "medium"
    strings:
        $a = "application/fhir+json"
        $b = "/fhir/Patient"
        $c = "HAPI FHIR"
    condition:
        1 of them
}

rule MARITIME_NMEA_AIS : protocol {
    meta:
        description = "maritime NMEA 0183 / AIS data"
        severity = "medium"
    strings:
        $a = "!AIVDM"
        $b = "NMEA 0183"
        $c = "$GPGGA"
    condition:
        1 of them
}

rule RAIL_RaSTA_Genisys : icsproto {
    meta:
        description = "rail signalling (RaSTA / Genisys) protocol"
        severity = "medium"
    strings:
        $a = "RaSTA"
        $b = "rasta protocol"
        $c = "Genisys"
    condition:
        1 of them
}

rule IOT_SSDP_Discover : recon {
    meta:
        description = "SSDP/UPnP discovery (M-SEARCH)"
        severity = "medium"
    strings:
        $a = "M-SEARCH * HTTP/1.1"
        $b = "ssdp:discover"
    condition:
        1 of them
}

rule IOT_WSDiscovery : recon {
    meta:
        description = "WS-Discovery device enumeration"
        severity = "medium"
    strings:
        $a = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
        $b = "wsdd"
    condition:
        1 of them
}

rule IOT_mDNS_Probe : recon {
    meta:
        description = "mDNS / DNS-SD service discovery"
        severity = "medium"
    strings:
        $a = "_services._dns-sd._udp"
        $b = "_airplay._tcp"
        $c = "_googlecast._tcp"
    condition:
        1 of them
}

rule IOT_LoRaWAN : protocol {
    meta:
        description = "LoRaWAN join / device tooling"
        severity = "medium"
    strings:
        $a = "LoRaWAN"
        $b = "JoinRequest"
        $c = "DevEUI"
    condition:
        1 of ($a) or ($b and $c)
}

rule IIOT_MQTT_SparkplugB : protocol {
    meta:
        description = "MQTT Sparkplug B industrial IIoT payload"
        severity = "medium"
    strings:
        $a = "spBv1.0"
        $b = "Sparkplug B"
        $c = "NBIRTH"
    condition:
        1 of them
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
