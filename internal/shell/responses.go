package shell

import (
	"strings"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// response is a single command -> output binding. funcs let us inject
// argument-dependent behavior (e.g. `cat /etc/passwd` vs `cat /etc/shadow`).
type response struct {
	static string
	dyn    func(argv []string) string
}

// responseTable returns the command -> response map for the supplied
// archetype family. Falls back to the POSIX table for unknown
// families.
func responseTable(p *archetype.Profile) map[string]response {
	family := ""
	if p != nil {
		family = p.Family
	}
	switch family {
	case "moxa":
		return moxaResponses(p)
	case "siemens":
		if isPLCProfile(p) {
			return plcResponses(p)
		}
		return siemensResponses(p)
	case "cisco":
		return ciscoResponses(p)
	case "windows":
		if isPowerShellProfile(p) {
			return powershellResponses(p)
		}
		return cmdResponses(p)
	default:
		return posixResponses(p)
	}
}

// isPowerShellProfile reports whether the archetype's shell should be
// PowerShell rather than cmd.exe (AD DCs + anything with a PS prompt).
func isPowerShellProfile(p *archetype.Profile) bool {
	return p != nil && (strings.HasPrefix(p.CLIPrompt(), "PS") || p.HasQuirk("powershell"))
}

// isPLCProfile reports whether a siemens-family archetype is a PLC (S7)
// rather than a SCALANCE switch — they get the PLC console, not the
// switch CLI.
func isPLCProfile(p *archetype.Profile) bool {
	return p != nil && (strings.Contains(p.Name, "s7") || p.HasQuirk("plc"))
}

// lookupResponse returns the canned output for argv[0]. Unknown
// commands get the archetype's "command not found" line so the
// engagement still feels real.
func lookupResponse(table map[string]response, cmd string, argv []string) string {
	if r, ok := table[cmd]; ok {
		if r.dyn != nil {
			return r.dyn(argv)
		}
		return r.static
	}
	// Some scanners pipe / && / ; — return the same "not found" for
	// the head token.
	return cmd + ": command not found\r\n"
}

// posixResponses covers the Linux/BSD distros (debian/ubuntu/rhel/etc.).
// The hostname, kernel version, and `cat /etc/issue` output are
// dynamically derived from the archetype so each distro shows the
// right banner.
func posixResponses(p *archetype.Profile) map[string]response {
	host := "host"
	kernel := "Linux host 5.10.0-amd64 #1 SMP x86_64 GNU/Linux"
	issue := "Linux \\n \\l\r\n"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			host = n
		}
		if d := p.SNMPSysDescr(); d != "" {
			kernel = d
		}
		if t := p.TelnetBanner(); t != "" {
			issue = strings.TrimLeft(t, "\r\n")
		}
	}
	const fakePasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash
`
	return map[string]response{
		"whoami":    {static: "root\r\n"},
		"id":        {static: "uid=0(root) gid=0(root) groups=0(root)\r\n"},
		"hostname":  {static: host + "\r\n"},
		"uname":     {static: kernel + "\r\n"},
		"pwd":       {static: "/root\r\n"},
		"uptime":    {static: " 14:23:01 up 47 days, 11:09,  1 user,  load average: 0.04, 0.05, 0.00\r\n"},
		"date":      {static: "Mon May 19 14:23:01 UTC 2025\r\n"},
		"echo":      {dyn: func(a []string) string { return strings.Join(a[1:], " ") + "\r\n" }},
		"history":   {static: "    1  ls\r\n    2  uname -a\r\n    3  whoami\r\n"},
		"w":         {static: " 14:23:01 up 47 days, 11:09,  1 user,  load average: 0.04, 0.05, 0.00\r\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\nadmin    pts/0    10.0.0.5         13:01   12:22   0.01s  0.01s -bash\r\n"},
		"who":       {static: "admin    pts/0        2025-05-19 13:01 (10.0.0.5)\r\n"},
		"ls":        {dyn: lsResponse},
		"ll":        {dyn: lsResponse},
		"dir":       {dyn: lsResponse},
		"cat":       {dyn: dynCat(fakePasswd, issue)},
		"head":      {dyn: dynCat(fakePasswd, issue)},
		"tail":      {dyn: dynCat(fakePasswd, issue)},
		"more":      {dyn: dynCat(fakePasswd, issue)},
		"less":      {dyn: dynCat(fakePasswd, issue)},
		"ps":        {static: "  PID TTY          TIME CMD\r\n 1234 pts/0    00:00:00 bash\r\n 1235 pts/0    00:00:00 ps\r\n"},
		"top":       {static: "Tasks:  87 total,   1 running,  86 sleeping\r\n%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id\r\nMiB Mem :   4096.0 total,   2548.0 free,    764.0 used\r\n"},
		"free":      {static: "               total        used        free      shared  buff/cache   available\r\nMem:         4194304      782336     2611200       12288      800768     3128448\r\nSwap:        2097148           0     2097148\r\n"},
		"df":        {static: "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n/dev/sda1       50561300 9826276  38158888  21% /\r\ntmpfs            2097152       0   2097152   0% /dev/shm\r\n"},
		"mount":     {static: "/dev/sda1 on / type ext4 (rw,relatime)\r\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\r\n"},
		"ifconfig":  {static: "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.10  netmask 255.255.255.0  broadcast 10.0.0.255\r\n        ether 02:42:ac:11:00:01  txqueuelen 1000  (Ethernet)\r\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n        inet 127.0.0.1  netmask 255.0.0.0\r\n"},
		"ip":        {static: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n    inet 10.0.0.10/24 brd 10.0.0.255 scope global eth0\r\n"},
		"netstat":   {static: "Active Internet connections (only servers)\r\nProto Recv-Q Send-Q Local Address           Foreign Address         State\r\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"},
		"ss":        {static: "Netid State  Local Address:Port  Peer Address:Port\r\ntcp   LISTEN 0.0.0.0:22          0.0.0.0:*\r\ntcp   LISTEN 0.0.0.0:80          0.0.0.0:*\r\n"},
		"env":       {static: "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nHOME=/root\r\nUSER=root\r\nSHELL=/bin/bash\r\nTERM=xterm-256color\r\n"},
		"set":       {static: "BASH=/bin/bash\r\nBASH_VERSION='5.2.15(1)-release'\r\nHISTSIZE=1000\r\nHOME=/root\r\nLANG=en_US.UTF-8\r\n"},
		"cd":        {static: ""},
		"clear":     {static: "\x1b[H\x1b[2J"},
		"sudo":      {static: "sudo: a password is required\r\n"},
		"su":        {static: "su: Authentication failure\r\n"},
		"passwd":    {static: "passwd: Authentication token manipulation error\r\n"},
		"reboot":    {static: "Failed to set wall message, ignoring: Interactive authentication required.\r\nFailed to reboot system via logind: Interactive authentication required.\r\n"},
		"shutdown":  {static: "Failed to set wall message, ignoring: Interactive authentication required.\r\nFailed to shut down system via logind: Interactive authentication required.\r\n"},
		"systemctl": {static: "Failed to list units: Interactive authentication required.\r\n"},
		"service":   {static: "Unit not found.\r\n"},
		"wget": {dyn: func(a []string) string {
			return "--2025-05-19 14:23:01--  " + lastArg(a) + "\r\nResolving host... failed: Temporary failure in name resolution.\r\n"
		}},
		"curl":    {dyn: func(a []string) string { return "curl: (6) Could not resolve host: " + lastArg(a) + "\r\n" }},
		"nc":      {static: ""}, // silent — most reverse shell tests pipe input, so nothing back looks like a stuck listener
		"ncat":    {static: ""},
		"python":  {static: "Python 3.11.2 (main, May 18 2023, 11:38:21) [GCC 12.2.0] on linux\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n>>> "},
		"python3": {static: "Python 3.11.2 (main, May 18 2023, 11:38:21) [GCC 12.2.0] on linux\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n>>> "},
		"perl":    {static: ""},
		"bash":    {static: ""},
		"sh":      {static: ""},
		"chmod":   {static: ""},
		"chown":   {static: ""},
		"rm":      {static: ""},
		"mv":      {static: ""},
		"cp":      {static: ""},
		"mkdir":   {static: ""},
		"touch":   {static: ""},
		"vi":      {static: ""},
		"vim":     {static: ""},
		"nano":    {static: ""},
		"crontab": {dyn: func(a []string) string {
			if len(a) > 1 && (a[1] == "-l" || a[1] == "--list") {
				return "no crontab for root\r\n"
			}
			return ""
		}},
		"ssh": {static: "Could not resolve hostname: Name or service not known\r\n"},
		"scp": {static: "Could not resolve hostname: Name or service not known\r\n"},
		"ftp": {static: ""},
	}
}

// moxaResponses returns a Moxa-EDS / NPort-shaped command set: a tiny
// menu-driven CLI rather than a full Unix shell.
func moxaResponses(p *archetype.Profile) map[string]response {
	model := "EDS-208"
	fw := "V1.7"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			model = n
		}
		if d := p.SNMPSysDescr(); d != "" {
			fw = d
		}
	}
	return map[string]response{
		"?":    {static: "Available commands: show, get, set, enable, exit\r\n"},
		"help": {static: "Available commands: show, get, set, enable, exit\r\n"},
		"show": {dyn: func(a []string) string {
			if len(a) < 2 {
				return "Usage: show {version|config|interface|running-config|mac-address-table}\r\n"
			}
			switch a[1] {
			case "version":
				return "Model: " + model + "\r\nFirmware: " + fw + "\r\nBootloader: 1.0\r\n"
			case "config", "running-config":
				return "! Moxa " + model + " running-config\r\n!\r\nhostname " + model + "\r\nip address 192.168.127.254/24\r\n!\r\nsnmp-server community public RO\r\n!\r\nend\r\n"
			case "interface":
				return "Port  Speed  Duplex  Status\r\n----  -----  ------  ------\r\n  1   1G     Full    Up\r\n  2   100M   Full    Up\r\n  3   --     --      Down\r\n  4   1G     Full    Up\r\n  5   --     --      Down\r\n  6   --     --      Down\r\n  7   --     --      Down\r\n  8   --     --      Down\r\n"
			case "mac-address-table":
				return "  Port  MAC Address         Type\r\n  1     00:90:E8:11:22:33   Dynamic\r\n  2     00:90:E8:44:55:66   Dynamic\r\n  4     28:63:36:aa:bb:cc   Dynamic\r\n"
			}
			return "Unknown subcommand\r\n"
		}},
		"enable": {static: "Password: "},
		"get":    {static: ""},
		"set":    {static: ""},
		"ping":   {dyn: func(a []string) string { return "PING " + lastArg(a) + ": Request timeout.\r\n" }},
	}
}

// siemensResponses returns a SCALANCE / S7-shaped command set.
func siemensResponses(p *archetype.Profile) map[string]response {
	model := "SCALANCE XB-208"
	if p != nil {
		if n := p.SNMPSysName(); n != "" {
			model = n
		}
	}
	return map[string]response{
		"?":    {static: "Available commands: show, configure, exit\r\n"},
		"help": {static: "Available commands: show, configure, exit\r\n"},
		"show": {dyn: func(a []string) string {
			if len(a) < 2 {
				return "show {device|version|ip-route|interface|users}\r\n"
			}
			switch a[1] {
			case "device":
				return "Device:        " + model + "\r\nOrder no:      6GK5208-0BA00-2AB2\r\nVersion:       V06.01.01\r\nMAC address:   28:63:36:00:11:22\r\nIP address:    192.168.0.5/24\r\n"
			case "version":
				return "SIMATIC NET, SCALANCE X-200 series\r\nFirmware V06.01.01 build 20240315\r\n"
			case "ip-route":
				return "Destination    Next-hop      Iface\r\n0.0.0.0/0      192.168.0.1   vlan1\r\n192.168.0.0/24 -             vlan1\r\n"
			case "interface":
				return "Port  Description       Status  Speed\r\n----  ----------------  ------  -----\r\n1/1   ethernet 1        up      1G\r\n1/2   ethernet 2        up      1G\r\n1/3   ethernet 3        down    --\r\n1/4   ethernet 4        up      100M\r\n"
			case "users":
				return "Username  Privilege\r\n--------  ---------\r\nadmin     admin\r\n"
			}
			return "Unknown subcommand\r\n"
		}},
		"configure": {static: "% Authentication required.\r\n"},
		"ping":      {dyn: func(a []string) string { return "PING " + lastArg(a) + " - timeout\r\n" }},
	}
}

// lsResponse fakes an `ls` listing. We track no actual filesystem; we
// just return a believable default for whatever path was requested.
func lsResponse(argv []string) string {
	dir := "/root"
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") {
			dir = a
			break
		}
	}
	switch dir {
	case "/":
		return "bin   dev  home  lib32   media  opt   root  sbin  sys  usr\r\nboot  etc  lib   lib64   mnt    proc  run   srv   tmp  var\r\n"
	case "/etc":
		return "apt        crontab        hostname  motd     passwd   resolv.conf  shadow  ssh    sudoers\r\nbash.bashrc fstab          hosts     network  profile  rsyslog.conf systemd timezone\r\n"
	case "/root", "/root/", "~":
		return ".bash_history  .bashrc  .profile  .ssh  install.sh  notes.txt\r\n"
	case "/root/.ssh":
		return "authorized_keys  config  id_rsa  id_rsa.pub  known_hosts\r\n"
	case "/var/log":
		return "alternatives.log  apt   auth.log  btmp  dpkg.log  faillog  journal  lastlog  syslog  wtmp\r\n"
	case "/home", "/home/":
		return "admin\r\n"
	case "/home/admin":
		return ".bashrc  .profile  .ssh  Desktop  Documents  Downloads\r\n"
	case "/tmp":
		return ""
	}
	return ".  ..\r\n"
}

// dynCat handles `cat <path>` (and `head`/`tail`/`more`/`less`).
// Returns:
//   - /etc/passwd      -> the fake passwd
//   - /etc/issue       -> the archetype's issue
//   - /etc/shadow      -> Permission denied (the read attempt is
//     already flagged as anomaly upstream)
//   - /etc/hostname    -> the archetype's hostname
//   - any other path   -> "No such file or directory"
func dynCat(passwd, issue string) func([]string) string {
	return func(argv []string) string {
		if len(argv) < 2 {
			return ""
		}
		path := argv[len(argv)-1]
		switch path {
		case "/etc/passwd":
			return passwd
		case "/etc/shadow":
			return "cat: /etc/shadow: Permission denied\r\n"
		case "/etc/issue":
			return issue
		case "/etc/hostname":
			return "host\r\n"
		case "/etc/os-release":
			return "PRETTY_NAME=\"Linux\"\r\nID=linux\r\n"
		case "/proc/cpuinfo":
			return "processor\t: 0\r\nvendor_id\t: GenuineIntel\r\nmodel name\t: Intel(R) Xeon(R) CPU @ 2.30GHz\r\n"
		case "/proc/version":
			return "Linux version 5.10.0 #1 SMP x86_64\r\n"
		case "/root/.bash_history":
			return "ls\r\nuname -a\r\nps aux\r\nwhoami\r\n"
		case "/root/.ssh/authorized_keys":
			return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@host\r\n"
		}
		return "cat: " + path + ": No such file or directory\r\n"
	}
}

func lastArg(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return argv[len(argv)-1]
}
