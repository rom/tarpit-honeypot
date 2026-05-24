package testharness

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"
)

func init() {
	RegisterGen(CatScan, func(cfg *Config) []Case {
		if cfg.Mode != "network" {
			return nil // scans need the wire
		}
		return []Case{
			{ID: "scan/portscan-seq", Category: CatScan, Title: "sequential TCP port scan",
				Fn: func(ctx context.Context, r *Run) (Status, string, error) { return portScan(ctx, r, false) }},
			{ID: "scan/portscan-rand", Category: CatScan, Title: "randomized TCP port scan",
				Fn: func(ctx context.Context, r *Run) (Status, string, error) { return portScan(ctx, r, true) }},
			{ID: "scan/host-sweep", Category: CatScan, Title: "TCP host sweep across a CIDR",
				Fn: hostSweep},
			{ID: "scan/ping-sweep", Category: CatScan, Title: "ICMP ping sweep (uses system ping)",
				Fn: pingSweep},
			{ID: "scan/arp-sweep", Category: CatScan, Title: "ARP sweep (uses arping; needs CAP_NET_RAW)",
				Fn: arpSweep},
		}
	})
}

func scanPorts(cfg *Config) []int {
	if len(cfg.ScanPorts) > 0 {
		return cfg.ScanPorts
	}
	seen := map[int]bool{}
	var ports []int
	for _, e := range cfg.Endpoints {
		if e.Port > 0 && !seen[e.Port] {
			seen[e.Port] = true
			ports = append(ports, e.Port)
		}
	}
	for _, p := range []int{21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080} {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

func portScan(ctx context.Context, r *Run, shuffle bool) (Status, string, error) {
	ports := append([]int(nil), scanPorts(r.Cfg)...)
	if shuffle {
		rng := caseRand(r.Cfg.Seed, "scan/portscan-rand")
		rng.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	}
	open := 0
	for _, p := range ports {
		if ctx.Err() != nil {
			return StatusSkip, "interrupted", nil
		}
		if tcpConnect(ctx, r.Cfg.Host, p, r.Cfg.Timeout) {
			open++
		}
	}
	st, detail := verifyScan(ctx, r,
		MatchRulePrefix("correlate:port_scan"),
		MatchRulePrefix("sniffer:tcp_"),
		MatchRulePrefix("scananalysis:"),
		MatchRulePrefix("correlate:service_sweep"))
	return st, fmt.Sprintf("%d/%d ports open; %s", open, len(ports), detail), nil
}

func hostSweep(ctx context.Context, r *Run) (Status, string, error) {
	hosts := hostsInCIDR(r.Cfg.SweepCIDR, 256)
	if len(hosts) == 0 {
		return StatusSkip, "no sweep_cidr configured", nil
	}
	port := 80
	if ps := scanPorts(r.Cfg); len(ps) > 0 {
		port = ps[0]
	}
	up := 0
	for _, h := range hosts {
		if ctx.Err() != nil {
			return StatusSkip, "interrupted", nil
		}
		if tcpConnect(ctx, h, port, r.Cfg.Timeout) {
			up++
		}
	}
	st, detail := verifyScan(ctx, r, MatchRulePrefix("correlate:host_sweep"), MatchRulePrefix("correlate:icmp_sweep"), MatchRulePrefix("sniffer:"))
	return st, fmt.Sprintf("swept %d hosts on :%d, %d up; %s", len(hosts), port, up, detail), nil
}

func pingSweep(ctx context.Context, r *Run) (Status, string, error) {
	hosts := hostsInCIDR(r.Cfg.SweepCIDR, 64)
	if len(hosts) == 0 {
		return StatusSkip, "no sweep_cidr configured", nil
	}
	if _, err := exec.LookPath("ping"); err != nil {
		return StatusSkip, "system ping not found", nil
	}
	reached := 0
	for _, h := range hosts {
		if ctx.Err() != nil {
			return StatusSkip, "interrupted", nil
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := exec.CommandContext(cctx, "ping", "-c", "1", "-W", "1", h).Run()
		cancel()
		if err == nil {
			reached++
		}
	}
	st, detail := verifyScan(ctx, r, MatchRulePrefix("correlate:icmp_sweep"), MatchRulePrefix("sniffer:"))
	return st, fmt.Sprintf("pinged %d hosts, %d replied; %s", len(hosts), reached, detail), nil
}

func arpSweep(ctx context.Context, r *Run) (Status, string, error) {
	hosts := hostsInCIDR(r.Cfg.SweepCIDR, 64)
	if len(hosts) == 0 {
		return StatusSkip, "no sweep_cidr configured", nil
	}
	if _, err := exec.LookPath("arping"); err != nil {
		return StatusSkip, "arping not found (ARP sweep needs raw L2 / CAP_NET_RAW)", nil
	}
	replied := 0
	for _, h := range hosts {
		if ctx.Err() != nil {
			return StatusSkip, "interrupted", nil
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := exec.CommandContext(cctx, "arping", "-c", "1", "-w", "1", h).Run()
		cancel()
		if err == nil {
			replied++
		}
	}
	st, detail := verifyScan(ctx, r, MatchRulePrefix("sniffer:arp"), MatchRulePrefix("device:"))
	return st, fmt.Sprintf("ARP-swept %d hosts, %d replied; %s", len(hosts), replied, detail), nil
}

// verifyScan checks (via the API, when configured) that the honeypot flagged
// the scan; without an API the scan is reported as completed (informational).
func verifyScan(ctx context.Context, r *Run, matchers ...func(apiEvent) bool) (Status, string) {
	if r.API == nil {
		return StatusPass, "completed (set verify.url to confirm detection)"
	}
	for _, m := range matchers {
		det, checked := r.API.Detected(ctx, m)
		if !checked {
			return StatusSkip, "verify API unreachable"
		}
		if det {
			return StatusPass, "honeypot flagged the scan"
		}
	}
	return StatusFail, "honeypot did NOT flag the scan"
}

// hostsInCIDR returns up to max usable host addresses in cidr.
func hostsInCIDR(cidr string, max int) []string {
	if cidr == "" {
		return nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var out []string
	ip := ipnet.IP.Mask(ipnet.Mask)
	for x := cloneIP(ip); ipnet.Contains(x) && len(out) < max; incIP(x) {
		out = append(out, x.String())
	}
	// Drop network + broadcast for IPv4 /<31 ranges when present.
	if len(out) > 2 && ip.To4() != nil {
		out = out[1 : len(out)-1]
	}
	return out
}

func cloneIP(ip net.IP) net.IP { c := make(net.IP, len(ip)); copy(c, ip); return c }
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
