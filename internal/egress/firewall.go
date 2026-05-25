package egress

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// The OS-level egress firewall is the hard backstop under the in-process
// allowlist: an nftables OUTPUT chain that drops the sensor's outbound packets
// unless they go to an allowlisted destination — so even a compromised
// in-process handler that calls raw net.Dial (or a library that dials outside
// the guard) can't be used to pivot / relay / exfil. It is scoped to the
// sensor's own UID via `meta skuid`, so the rest of the host is untouched, and
// it permits established (so listeners can reply), loopback, and DNS to the
// system resolvers (so sink hostnames keep resolving).
//
// Requires Linux, the `nft` binary, and CAP_NET_ADMIN — install it before
// dropping privileges. Opt-in (egress.enforce); the in-process guard runs
// regardless.

const defaultTable = "tarpit_egress"

// FirewallConfig parameterises the generated ruleset.
type FirewallConfig struct {
	UID       int      // govern only outbound from this user (the sensor's run-as uid)
	Entries   []string // allowlist: host / host:port / CIDR / IP / IP:port
	Resolvers []string // DNS resolver IPs to permit :53 to
	Table     string   // nft table name (default tarpit_egress)
}

func (c FirewallConfig) table() string {
	if c.Table != "" {
		return c.Table
	}
	return defaultTable
}

// BuildRuleset renders the nft script for the policy. Hostname entries are
// resolved to IPs; entries that don't resolve are skipped (the in-process guard
// still covers them by name). Pure — no privilege needed — so it is unit-tested
// against `nft -c`.
func BuildRuleset(c FirewallConfig) string {
	t := c.table()
	var b strings.Builder
	// Idempotent replace: create-if-absent, delete, recreate — so a restart
	// cleanly supersedes a stale table.
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", t, t)
	fmt.Fprintf(&b, "table inet %s {\n\tchain output {\n", t)
	b.WriteString("\t\ttype filter hook output priority 0; policy accept;\n")
	// Only govern the sensor's own traffic; everything else is accepted.
	fmt.Fprintf(&b, "\t\tmeta skuid != %d accept\n", c.UID)
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	b.WriteString("\t\tip daddr 127.0.0.0/8 accept\n")
	b.WriteString("\t\tip6 daddr ::1 accept\n")
	for _, r := range c.Resolvers {
		if ip := net.ParseIP(r); ip != nil {
			fam := famOf(ip)
			fmt.Fprintf(&b, "\t\t%s daddr %s udp dport 53 accept\n", fam, ip)
			fmt.Fprintf(&b, "\t\t%s daddr %s tcp dport 53 accept\n", fam, ip)
		}
	}
	for _, e := range c.Entries {
		for _, rule := range entryRules(e) {
			b.WriteString("\t\t" + rule + "\n")
		}
	}
	fmt.Fprintf(&b, "\t\tmeta skuid %d drop\n", c.UID)
	b.WriteString("\t}\n}\n")
	return b.String()
}

// entryRules turns one allowlist entry into nft accept rule(s).
func entryRules(entry string) []string {
	// CIDR.
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		return []string{fmt.Sprintf("%s daddr %s accept", famOfNet(ipnet), ipnet.String())}
	}
	// host:port (port-specific).
	if host, port, err := net.SplitHostPort(entry); err == nil {
		var out []string
		for _, ip := range resolve(host) {
			out = append(out, fmt.Sprintf("%s daddr %s th dport %s accept", famOf(ip), ip, port))
		}
		return out
	}
	// bare host / IP (any port).
	var out []string
	for _, ip := range resolve(entry) {
		out = append(out, fmt.Sprintf("%s daddr %s accept", famOf(ip), ip))
	}
	return out
}

func resolve(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

func famOf(ip net.IP) string {
	if ip.To4() != nil {
		return "ip"
	}
	return "ip6"
}

func famOfNet(n *net.IPNet) string { return famOf(n.IP) }

// SystemResolvers parses the nameserver IPs from /etc/resolv.conf so the
// firewall permits DNS to them (sink hostnames must keep resolving).
func SystemResolvers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseResolvers(b)
}

func parseResolvers(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// InstallFirewall applies the ruleset via `nft -f -`. Linux + nft + CAP_NET_ADMIN
// required; returns a clear error otherwise (the caller keeps the in-process
// guard regardless).
func InstallFirewall(ctx context.Context, c FirewallConfig) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("egress firewall: only supported on linux")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("egress firewall: nft not found on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, nft, "-f", "-")
	cmd.Stdin = strings.NewReader(BuildRuleset(c))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("egress firewall: nft apply failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveFirewall deletes the nft table (best-effort; a no-op if it's absent or
// nft is unavailable). Under an active seccomp filter the exec may be refused,
// in which case the (uid-scoped, harmless-when-down) table is left for the next
// start to supersede.
func RemoveFirewall(ctx context.Context, table string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if table == "" {
		table = defaultTable
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, nft, "delete", "table", "inet", table).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("egress firewall: nft delete failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
