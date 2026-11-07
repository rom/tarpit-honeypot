package cli

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cmdFirewallRules reads the effective config and prints host-firewall rules
// that open exactly the ports the configured listeners (and honeynet host
// services) bind — so an operator never has to hand-transcribe them. firewalld
// is the default (RHEL/Alma/Fedora); nftables, ufw and iptables are available
// with --format. Output is copy-pasteable, one logical step per block.
func cmdFirewallRules(args []string) error {
	fs := flag.NewFlagSet("firewall-rules", flag.ContinueOnError)
	var f commonFlags
	f.register(fs, "/etc/tarpit-honeypot/config.yaml")
	format := fs.String("format", "firewalld", "firewalld | nftables | ufw | iptables")
	zone := fs.String("zone", "", "firewalld zone (default: the active/default zone)")
	iface := fs.String("iface", "", "restrict the rules to this ingress interface (nftables/iptables)")
	if err := parseOrUsage(fs, args); err != nil {
		if err == errHelp {
			return nil
		}
		return err
	}
	cfg, err := config.LoadManyWithOverrides(f.paths(), f.overrideSets())
	if err != nil {
		return err
	}

	ports := collectListenerPorts(cfg)
	if len(ports) == 0 {
		fmt.Println("# no listeners with a bindable port in the config")
		return nil
	}

	switch *format {
	case "firewalld":
		printFirewalld(ports, *zone)
	case "nftables":
		printNftables(ports, *iface)
	case "ufw":
		printUFW(ports)
	case "iptables":
		printIptables(ports, *iface)
	default:
		return fmt.Errorf("--format must be firewalld, nftables, ufw, or iptables (got %q)", *format)
	}
	return nil
}

// fwPort is one proto/port the sensor binds, with what runs there (for comments).
type fwPort struct {
	proto string // "tcp" | "udp"
	port  int
	note  string // listener id / handler, for an inline comment
}

// collectListenerPorts gathers the distinct (proto, port) pairs the config
// binds — from top-level listeners and from honeynet host services (which ride
// virtual IPs on this host and still need the port open) — sorted for stable
// output. The note is the first listener/service seen on that pair.
func collectListenerPorts(cfg *config.Config) []fwPort {
	seen := map[string]*fwPort{}
	key := func(proto string, port int) string { return proto + "/" + strconv.Itoa(port) }
	add := func(proto string, port int, note string) {
		if port <= 0 || port > 65535 {
			return
		}
		proto = strings.ToLower(proto)
		if proto != "tcp" && proto != "udp" {
			proto = "tcp"
		}
		k := key(proto, port)
		if _, ok := seen[k]; !ok {
			seen[k] = &fwPort{proto: proto, port: port, note: note}
		}
	}
	for _, l := range cfg.Listeners {
		_, portStr, err := net.SplitHostPort(l.Bind)
		if err != nil {
			continue
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		note := l.ID
		if l.Handler != "" {
			note = l.ID + " (" + l.Handler + ")"
		}
		add(l.Proto, p, note)
	}
	// Honeynet host services are stream handlers on virtual IPs (tcp).
	for _, hn := range cfg.Honeynets {
		for _, h := range hn.Hosts {
			for _, s := range h.Services {
				add("tcp", s.Port, "honeynet "+hn.ID+"/"+h.Hostname+" ("+s.Handler+")")
			}
		}
	}
	out := make([]fwPort, 0, len(seen))
	for _, v := range seen {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].proto != out[j].proto {
			return out[i].proto < out[j].proto
		}
		return out[i].port < out[j].port
	})
	return out
}

func printFirewalld(ports []fwPort, zone string) {
	z := ""
	if zone != "" {
		z = " --zone=" + zone
	}
	fmt.Println("# tarpit-honeypot firewall rules — firewalld (RHEL/AlmaLinux/Fedora)")
	fmt.Println("# Review before running. Exposing these ports to the internet is intentional")
	fmt.Println("# for a honeypot; make sure nothing real listens behind them.")
	fmt.Println("#")
	fmt.Println("# ports opened:")
	for _, p := range ports {
		fmt.Printf("#   %d/%-3s  %s\n", p.port, p.proto, p.note)
	}
	fmt.Println()
	var adds []string
	for _, p := range ports {
		adds = append(adds, fmt.Sprintf("--add-port=%d/%s", p.port, p.proto))
	}
	fmt.Printf("sudo firewall-cmd --permanent%s %s\n", z, strings.Join(adds, " "))
	fmt.Println("sudo firewall-cmd --reload")
	fmt.Printf("sudo firewall-cmd%s --list-ports\n", z)
}

func printNftables(ports []fwPort, iface string) {
	tcp, udp := splitProtoPorts(ports)
	ifc := ""
	if iface != "" {
		ifc = "iifname \"" + iface + "\" "
	}
	fmt.Println("# tarpit-honeypot firewall rules — nftables")
	fmt.Println("# Appends accept rules to the inet filter input chain (adjust table/chain to taste).")
	fmt.Println()
	if len(tcp) > 0 {
		fmt.Printf("sudo nft add rule inet filter input %stcp dport { %s } accept\n", ifc, joinInts(tcp))
	}
	if len(udp) > 0 {
		fmt.Printf("sudo nft add rule inet filter input %sudp dport { %s } accept\n", ifc, joinInts(udp))
	}
}

func printUFW(ports []fwPort) {
	fmt.Println("# tarpit-honeypot firewall rules — ufw (Debian/Ubuntu)")
	fmt.Println()
	for _, p := range ports {
		fmt.Printf("sudo ufw allow %d/%s comment 'tarpit %s'\n", p.port, p.proto, p.note)
	}
}

func printIptables(ports []fwPort, iface string) {
	ifc := ""
	if iface != "" {
		ifc = "-i " + iface + " "
	}
	fmt.Println("# tarpit-honeypot firewall rules — iptables/ip6tables")
	fmt.Println("# Not persistent across reboot on its own — save with your distro's method")
	fmt.Println("# (iptables-save / netfilter-persistent).")
	fmt.Println()
	for _, p := range ports {
		fmt.Printf("sudo iptables -A INPUT %s-p %s --dport %d -j ACCEPT  # %s\n", ifc, p.proto, p.port, p.note)
	}
}

func splitProtoPorts(ports []fwPort) (tcp, udp []int) {
	for _, p := range ports {
		if p.proto == "udp" {
			udp = append(udp, p.port)
		} else {
			tcp = append(tcp, p.port)
		}
	}
	return tcp, udp
}

func joinInts(xs []int) string {
	ss := make([]string, len(xs))
	for i, x := range xs {
		ss[i] = strconv.Itoa(x)
	}
	return strings.Join(ss, ", ")
}
