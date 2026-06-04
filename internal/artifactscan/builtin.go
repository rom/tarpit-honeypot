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
