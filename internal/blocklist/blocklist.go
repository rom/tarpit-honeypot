// Package blocklist is the optional active-response backstop: when a source IP
// crosses a configured risk level, the sensor drops that source at the host
// firewall (nftables) for a bounded TTL, then lets it expire. This is the
// honeypot analogue of fail2ban, but driven by the sensor's own decaying
// risk score rather than log-line regexes.
//
// It is deliberately conservative and opt-in:
//
//   - Disabled by default. A honeypot's value is *observation*; blocking a
//     source ends the engagement, so the operator must explicitly turn it on.
//   - TTL-bounded. Every block is an nftables set element with a native
//     `timeout`, so the kernel expires it without us tracking state — a
//     restart or a crash can't leave a host permanently firewalled.
//   - Allowlist-aware and never blocks loopback / link-local / the configured
//     never-block CIDRs (so you can't lock yourself out via your own probe).
//   - Linux + nft + CAP_NET_ADMIN only; a no-op (logged) elsewhere.
//
// The set lives in its own table (default tarpit_blocklist) so it never
// collides with the egress firewall table, and the input chain has a low
// priority + accept policy so it only adds DROP rules for set members and
// leaves all other inbound traffic to the normal stack.
package blocklist

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Config controls the blocklist backstop.
type Config struct {
	Enabled bool
	// Level is the minimum risk level that triggers a block:
	// "elevated" | "high" | "critical" (default "critical").
	Level string
	// TTL is how long each block lasts before nftables expires it.
	TTL time.Duration
	// NeverBlock is a list of IPs / CIDRs that are exempt (in addition to the
	// always-exempt loopback + link-local ranges).
	NeverBlock []string
	// Table is the nft table name (default tarpit_blocklist).
	Table string
	// Runner executes an nft invocation; nil uses the real nft binary. Tests
	// inject a fake to capture commands without touching the host firewall.
	Runner Runner
}

// Runner abstracts running an nft command (args after the binary) with stdin.
type Runner interface {
	Run(ctx context.Context, stdin string, args ...string) error
}

func (c Config) table() string {
	if c.Table == "" {
		return "tarpit_blocklist"
	}
	return c.Table
}

func (c Config) ttl() time.Duration {
	if c.TTL <= 0 {
		return 15 * time.Minute
	}
	return c.TTL
}

// levelRank maps a level name to its numeric rank, matching internal/risk.
func levelRank(name string) int {
	switch name {
	case "elevated":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return 3 // unknown / empty defaults to the safest (critical-only)
	}
}

// BaseRuleset renders the nft script that creates the blocklist table, the
// timeout-bearing sets (one v4, one v6), and an input chain that drops any
// source IP present in a set. Idempotent: it deletes-then-recreates the table.
func BaseRuleset(c Config) string {
	t := c.table()
	ttlSecs := int(c.ttl().Seconds())
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", t, t)
	fmt.Fprintf(&b, "table inet %s {\n", t)
	fmt.Fprintf(&b, "\tset blocked4 { type ipv4_addr; flags timeout; timeout %ds; }\n", ttlSecs)
	fmt.Fprintf(&b, "\tset blocked6 { type ipv6_addr; flags timeout; timeout %ds; }\n", ttlSecs)
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority -10; policy accept;\n")
	fmt.Fprintf(&b, "\t\tip saddr @blocked4 drop\n")
	fmt.Fprintf(&b, "\t\tip6 saddr @blocked6 drop\n")
	b.WriteString("\t}\n}\n")
	return b.String()
}

// Blocker applies blocks. Construct with New; nil-safe methods make a disabled
// blocker a no-op so callers don't need to branch.
type Blocker struct {
	cfg     Config
	runner  Runner
	exempt  []*net.IPNet
	minRank int
}

// New builds a Blocker. It does NOT install the base ruleset; call Install
// (Linux-only, needs nft + CAP_NET_ADMIN) at startup.
func New(c Config) *Blocker {
	r := c.Runner
	if r == nil {
		r = nftRunner{}
	}
	b := &Blocker{cfg: c, runner: r, minRank: levelRank(c.Level)}
	// Always-exempt ranges plus operator NeverBlock entries.
	for _, cidr := range append([]string{
		"127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10",
	}, c.NeverBlock...) {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			b.exempt = append(b.exempt, n)
			continue
		}
		// Bare IP → /32 or /128.
		if ip := net.ParseIP(cidr); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			b.exempt = append(b.exempt, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return b
}

// Enabled reports whether blocking is active.
func (b *Blocker) Enabled() bool { return b != nil && b.cfg.Enabled }

// Install applies the base ruleset (table + sets + drop chain).
func (b *Blocker) Install(ctx context.Context) error {
	if !b.Enabled() {
		return nil
	}
	return b.runner.Run(ctx, BaseRuleset(b.cfg), "-f", "-")
}

// Remove tears down the blocklist table (best-effort).
func (b *Blocker) Remove(ctx context.Context) error {
	if b == nil {
		return nil
	}
	return b.runner.Run(ctx, "", "delete", "table", "inet", b.cfg.table())
}

// ShouldBlock reports whether a crossing into level should trigger a block:
// blocking is enabled, the level meets the threshold, and the IP is valid and
// not exempt.
func (b *Blocker) ShouldBlock(ip, level string) bool {
	if !b.Enabled() {
		return false
	}
	if levelRank(level) < b.minRank {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range b.exempt {
		if n.Contains(parsed) {
			return false
		}
	}
	return true
}

// Block adds the source IP to the appropriate set with the configured TTL. A
// no-op when blocking is disabled or the IP is exempt/invalid.
func (b *Blocker) Block(ctx context.Context, ip, level string) error {
	if !b.ShouldBlock(ip, level) {
		return nil
	}
	set := "blocked4"
	if net.ParseIP(ip).To4() == nil {
		set = "blocked6"
	}
	elem := fmt.Sprintf("add element inet %s %s { %s }", b.cfg.table(), set, ip)
	return b.runner.Run(ctx, "", strings.Fields(elem)...)
}
