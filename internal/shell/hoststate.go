package shell

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

// hostState is a deterministic, internally-consistent set of host facts derived
// from an archetype: a stable login user, primary IP/MAC, boot time, and load.
// It exists so the interactive shell stops reporting the SAME hardcoded uptime /
// IP / MAC on every honeypot (a fingerprinting tell) — each host now looks
// distinct but consistent across commands and reconnects, and matched to its
// archetype (interfaces, services).
type hostState struct {
	host    string
	user    string
	from    string // the login source the fake session came from
	ip      string // primary IPv4
	gw      string // default gateway (.1 of the IP's /24)
	mac     string
	boot    time.Time
	load    string
	loginAt time.Time
}

// historyCommands is a believable root command history — the kind of admin
// activity a real box accumulates. numberedHistory renders it for the `history`
// builtin; rawHistory renders it for `cat ~/.bash_history`, so the two agree.
var historyCommands = []string{
	"ls -la", "cd /var/log", "tail -f syslog", "systemctl status sshd", "df -h",
	"free -m", "apt update", "apt upgrade -y", "vi /etc/ssh/sshd_config",
	"systemctl restart sshd", "journalctl -u nginx --since today", "netstat -tulpn",
	"crontab -l", "history",
}

func numberedHistory() string {
	var b strings.Builder
	for i, c := range historyCommands {
		fmt.Fprintf(&b, "%5d  %s\r\n", i+1, c)
	}
	return b.String()
}

func rawHistory() string {
	return strings.Join(historyCommands, "\r\n") + "\r\n"
}

// rng is a tiny deterministic PCG-style generator seeded from the archetype.
type rng struct{ s uint64 }

func (r *rng) next(mod int) int {
	r.s = r.s*6364136223846793005 + 1442695040888963407
	if mod <= 0 {
		return 0
	}
	return int((r.s >> 33) % uint64(mod))
}

// deriveHost computes the per-host state. The seed is the archetype identity, so
// two different archetypes differ while one archetype stays stable.
func deriveHost(p *archetype.Profile) hostState {
	h := fnv.New64a()
	host := "host"
	if p != nil {
		_, _ = h.Write([]byte(p.SNMPSysName() + "|" + p.Family + "|" + p.Name + "|" + p.SNMPSysDescr()))
		if n := p.SNMPSysName(); n != "" {
			host = n
		}
	} else {
		_, _ = h.Write([]byte("default"))
	}
	r := rng{s: h.Sum64()}

	users := []string{"admin", "ubuntu", "ops", "deploy", "svc", "sysadmin"}
	user := users[r.next(len(users))]
	ipA, ipB, ipC := 10, r.next(240)+1, r.next(240)+1
	hostOct := r.next(250) + 2
	ip := fmt.Sprintf("%d.%d.%d.%d", ipA, ipB, ipC, hostOct)
	gw := fmt.Sprintf("%d.%d.%d.1", ipA, ipB, ipC)
	from := fmt.Sprintf("%d.%d.%d.%d", ipA, ipB, ipC, r.next(250)+2)

	now := time.Now().UTC()
	upDays := r.next(395) + 5
	upDur := time.Duration(upDays)*24*time.Hour + time.Duration(r.next(24))*time.Hour + time.Duration(r.next(60))*time.Minute
	load := fmt.Sprintf("%.2f, %.2f, %.2f", float64(r.next(70))/100, float64(r.next(45))/100, float64(r.next(25))/100)

	return hostState{
		host: host, user: user, from: from, ip: ip, gw: gw,
		mac:     deriveMAC(p, &r),
		boot:    now.Add(-upDur),
		load:    load,
		loginAt: now.Add(-time.Duration(r.next(600)+5) * time.Minute),
	}
}

// unameResponse builds a flag-aware `uname`: bare uname prints the kernel name,
// -a the full string, and -s/-n/-r/-v/-m/-o (in any combination, in canonical
// order) the matching field — parsed from the archetype's full uname string so
// `uname -r` agrees with `uname -a` and `uname -n` agrees with `hostname`.
func unameResponse(full, host string) func([]string) string {
	sysname, release, version, machine, os := parseUname(full)
	return func(argv []string) string {
		flags := map[rune]bool{}
		for _, a := range argv[1:] {
			if strings.HasPrefix(a, "-") {
				for _, c := range a[1:] {
					flags[c] = true
				}
			}
		}
		if flags['a'] {
			return full + "\r\n"
		}
		var parts []string
		if flags['s'] {
			parts = append(parts, sysname)
		}
		if flags['n'] {
			parts = append(parts, host)
		}
		if flags['r'] {
			parts = append(parts, release)
		}
		if flags['v'] {
			parts = append(parts, version)
		}
		if flags['m'] || flags['p'] || flags['i'] {
			parts = append(parts, machine)
		}
		if flags['o'] {
			parts = append(parts, os)
		}
		if len(parts) == 0 { // bare uname, or only unknown flags -> kernel name
			return sysname + "\r\n"
		}
		return strings.Join(parts, " ") + "\r\n"
	}
}

// parseUname splits a full uname string
// ("<sysname> <node> <release> <version...> <machine> <os>") into fields,
// falling back to sensible Linux defaults for anything it can't find.
func parseUname(full string) (sysname, release, version, machine, os string) {
	sysname, release, version, machine, os = "Linux", "5.10.0-amd64", "#1 SMP", "x86_64", "GNU/Linux"
	fields := strings.Fields(full)
	if len(fields) == 0 {
		return
	}
	sysname = fields[0]
	if len(fields) >= 3 {
		release = fields[2]
	}
	archIdx := -1
	for i, f := range fields {
		switch f {
		case "x86_64", "aarch64", "armv7l", "armv6l", "i686", "i386", "mips", "mips64", "ppc64le", "s390x", "riscv64":
			machine = f
			archIdx = i
		}
	}
	if archIdx > 3 {
		version = strings.Join(fields[3:archIdx], " ")
	}
	if archIdx >= 0 && archIdx+1 < len(fields) {
		os = strings.Join(fields[archIdx+1:], " ")
	}
	return
}

func deriveMAC(p *archetype.Profile, r *rng) string {
	var oui [3]byte
	if p != nil && p.HasMACOUI() {
		oui = p.MACOUI()
	} else {
		oui = [3]byte{0x00, 0x50, 0x56} // VMware — a believable default
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", oui[0], oui[1], oui[2], r.next(256), r.next(256), r.next(256))
}

func (h hostState) uptime() string {
	now := time.Now().UTC()
	d := now.Sub(h.boot)
	days := int(d.Hours()) / 24
	hrs := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf(" %s up %d days, %2d:%02d,  1 user,  load average: %s\r\n",
		now.Format("15:04:05"), days, hrs, mins, h.load)
}

func (h hostState) wOutput() string {
	return h.uptime() +
		"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n" +
		fmt.Sprintf("%-8s pts/0    %-15s %s    1:02   0.04s  0.01s -bash\r\n",
			h.user, h.from, h.loginAt.Format("15:04"))
}

func (h hostState) whoOutput() string {
	return fmt.Sprintf("%-8s pts/0        %s (%s)\r\n", h.user, h.loginAt.Format("2006-01-02 15:04"), h.from)
}

func (h hostState) lastOutput() string {
	now := time.Now().UTC()
	var b strings.Builder
	fmt.Fprintf(&b, "%-8s pts/0        %-15s %s   still logged in\r\n", h.user, h.from, h.loginAt.Format("Mon Jan _2 15:04"))
	prev := h.loginAt.Add(-22 * time.Hour)
	fmt.Fprintf(&b, "%-8s pts/0        %-15s %s - %s  (01:14)\r\n", h.user, h.from, prev.Format("Mon Jan _2 15:04"), prev.Add(74*time.Minute).Format("15:04"))
	fmt.Fprintf(&b, "%-8s pts/0        %-15s %s - %s  (00:31)\r\n", "root", h.gw, prev.Add(-26*time.Hour).Format("Mon Jan _2 15:04"), prev.Add(-26*time.Hour).Add(31*time.Minute).Format("15:04"))
	fmt.Fprintf(&b, "reboot   system boot  %-15s %s   still running\r\n", strings.SplitN(h.host, ".", 2)[0], h.boot.Format("Mon Jan _2 15:04"))
	fmt.Fprintf(&b, "\r\nwtmp begins %s\r\n", now.Add(-720*time.Hour).Format("Mon Jan _2 15:04:05 2006"))
	return b.String()
}

func (h hostState) date() string {
	return time.Now().UTC().Format("Mon Jan _2 15:04:05 MST 2006") + "\r\n"
}

// ifconfig renders the archetype's up ethernet interfaces (plus lo) with this
// host's IP/MAC.
func (h hostState) ifconfig(p *archetype.Profile) string {
	first3 := h.ip[:strings.LastIndex(h.ip, ".")]
	var b strings.Builder
	for _, name := range h.ethNames(p) {
		fmt.Fprintf(&b, "%s: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n", name)
		fmt.Fprintf(&b, "        inet %s  netmask 255.255.255.0  broadcast %s.255\r\n", h.ip, first3)
		fmt.Fprintf(&b, "        ether %s  txqueuelen 1000  (Ethernet)\r\n", h.mac)
	}
	b.WriteString("lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n")
	b.WriteString("        inet 127.0.0.1  netmask 255.0.0.0\r\n")
	return b.String()
}

func (h hostState) ipCmd(p *archetype.Profile, argv []string) string {
	sub := ""
	if len(argv) > 1 {
		sub = argv[1]
	}
	switch {
	case strings.HasPrefix("route", sub) && sub != "":
		return h.ipRoute()
	case strings.HasPrefix("link", sub) && sub != "":
		return h.ipLink(p)
	case strings.HasPrefix("neighbour", sub) && sub != "", sub == "neigh", sub == "n":
		return h.arp()
	default: // addr / a / "" / show
		return h.ipAddr(p)
	}
}

func (h hostState) ipAddr(p *archetype.Profile) string {
	var b strings.Builder
	b.WriteString("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\r\n")
	b.WriteString("    inet 127.0.0.1/8 scope host lo\r\n")
	for i, name := range h.ethNames(p) {
		fmt.Fprintf(&b, "%d: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\r\n", i+2, name)
		fmt.Fprintf(&b, "    link/ether %s brd ff:ff:ff:ff:ff:ff\r\n", h.mac)
		fmt.Fprintf(&b, "    inet %s/24 brd %s.255 scope global %s\r\n", h.ip, h.ip[:strings.LastIndex(h.ip, ".")], name)
	}
	return b.String()
}

func (h hostState) ipLink(p *archetype.Profile) string {
	var b strings.Builder
	b.WriteString("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n")
	b.WriteString("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n")
	for i, name := range h.ethNames(p) {
		fmt.Fprintf(&b, "%d: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\r\n", i+2, name)
		fmt.Fprintf(&b, "    link/ether %s brd ff:ff:ff:ff:ff:ff\r\n", h.mac)
	}
	return b.String()
}

func (h hostState) ipRoute() string {
	dev := "eth0"
	first3 := h.ip[:strings.LastIndex(h.ip, ".")]
	return fmt.Sprintf("default via %s dev %s proto static\r\n%s.0/24 dev %s proto kernel scope link src %s\r\n", h.gw, dev, first3, dev, h.ip)
}

func (h hostState) route() string {
	first3 := h.ip[:strings.LastIndex(h.ip, ".")]
	return "Kernel IP routing table\r\n" +
		"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n" +
		fmt.Sprintf("0.0.0.0         %-15s 0.0.0.0         UG    100    0        0 eth0\r\n", h.gw) +
		fmt.Sprintf("%-15s 0.0.0.0         255.255.255.0   U     0      0        0 eth0\r\n", first3+".0")
}

func (h hostState) arp() string {
	return "Address                  HWtype  HWaddress           Flags Mask            Iface\r\n" +
		fmt.Sprintf("%-24s ether   %s   C                     eth0\r\n", h.gw, h.mac[:9]+"00:00:01") +
		fmt.Sprintf("%-24s ether   %s   C                     eth0\r\n", h.from, h.mac[:9]+"5a:1b:2c")
}

// ps renders a process table consistent with the archetype's services: PID 1
// systemd, kernel threads, sshd, the role daemons (nginx / mysqld / ...), the
// login shell, and ps itself.
func (h hostState) ps(p *archetype.Profile, argv []string) string {
	var b strings.Builder
	b.WriteString("  PID TTY      STAT   TIME COMMAND\r\n")
	row := func(pid int, tty, stat, cmd string) {
		fmt.Fprintf(&b, "%5d %-8s %-4s %6s %s\r\n", pid, tty, stat, "0:00", cmd)
	}
	row(1, "?", "Ss", "/sbin/init")
	row(2, "?", "S", "[kthreadd]")
	row(10, "?", "I", "[rcu_sched]")
	row(420, "?", "Ss", "/lib/systemd/systemd-journald")
	row(602, "?", "Ss", "/usr/sbin/sshd -D")
	pid := 900
	for _, proc := range roleProcesses(p) {
		row(pid, "?", "Ssl", proc)
		pid += 37
	}
	row(pid+11, "pts/0", "Ss", "-bash")
	row(pid+12, "pts/0", "R+", "ps "+strings.Join(argv[1:], " "))
	return b.String()
}

// ethNames returns the ethernet interface names from the archetype, or eth0.
func (h hostState) ethNames(p *archetype.Profile) []string {
	var names []string
	if p != nil {
		for _, ifc := range p.Interfaces() {
			if ifc.Type == 6 && ifc.OperUp { // ethernet, up
				names = append(names, ifaceShortName(ifc.Descr, len(names)))
			}
		}
	}
	if len(names) == 0 {
		names = []string{"eth0"}
	}
	return names
}

func ifaceShortName(descr string, idx int) string {
	descr = strings.TrimSpace(descr)
	if descr == "" || strings.ContainsAny(descr, " /") {
		return fmt.Sprintf("eth%d", idx)
	}
	return descr
}

// roleProcesses maps the archetype's default services to the daemons a real host
// of that role would be running.
func roleProcesses(p *archetype.Profile) []string {
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var procs []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			procs = append(procs, s)
		}
	}
	for _, svc := range p.DefaultServices() {
		add(daemonForHandler(svc.Handler))
	}
	sort.Strings(procs)
	return procs
}

func daemonForHandler(handler string) string {
	switch handler {
	case "http", "https":
		return "nginx: master process /usr/sbin/nginx"
	case "mysql", "mysql_files":
		return "/usr/sbin/mysqld"
	case "postgres":
		return "/usr/lib/postgresql/15/bin/postgres"
	case "redis":
		return "/usr/bin/redis-server *:6379"
	case "mongodb":
		return "/usr/bin/mongod --config /etc/mongod.conf"
	case "smtp", "smtp_recv", "smtps":
		return "/usr/lib/postfix/sbin/master -w"
	case "ftp", "ftp_files", "ftps":
		return "/usr/sbin/vsftpd /etc/vsftpd.conf"
	case "telnet":
		return "/usr/sbin/inetd"
	case "dockerapi":
		return "/usr/bin/dockerd -H fd://"
	case "elasticsearch":
		return "/usr/share/elasticsearch/jdk/bin/java -Xms1g -Xmx1g -Delasticsearch"
	case "ldap", "ldaps":
		return "/usr/sbin/slapd -h ldap:/// ldaps:///"
	case "snmp":
		return "/usr/sbin/snmpd -Lsd -Lf /dev/null -p /run/snmpd.pid"
	}
	return ""
}
