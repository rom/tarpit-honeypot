package shell

import (
	"strings"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/archetype"
)

func TestDaemonForHandler(t *testing.T) {
	cases := map[string]string{
		"http":     "nginx",
		"mysql":    "mysqld",
		"redis":    "redis-server",
		"postgres": "postgres",
		"ftp":      "vsftpd",
		"telnet":   "inetd",
	}
	for handler, want := range cases {
		if got := daemonForHandler(handler); !strings.Contains(got, want) {
			t.Errorf("daemonForHandler(%q) = %q; want it to contain %q", handler, got, want)
		}
	}
	if daemonForHandler("nope") != "" {
		t.Error("unknown handler should map to no daemon")
	}
}

func TestHostStateRealism(t *testing.T) {
	arch := archetype.Lookup("debian 12")
	hs := deriveHost(arch)

	out, _ := OneShot(arch, "uptime")
	if !strings.Contains(out, "up ") || !strings.Contains(out, "load average:") {
		t.Errorf("uptime = %q", out)
	}

	out, _ = OneShot(arch, "last")
	if !strings.Contains(out, "still logged in") || !strings.Contains(out, "reboot") {
		t.Errorf("last = %q", out)
	}

	out, _ = OneShot(arch, "ifconfig")
	if !strings.Contains(out, hs.ip) || !strings.Contains(out, hs.mac) || !strings.Contains(out, "ether") {
		t.Errorf("ifconfig = %q; want ip %s + mac %s", out, hs.ip, hs.mac)
	}

	out, _ = OneShot(arch, "ps aux")
	for _, want := range []string{"/sbin/init", "sshd", "-bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("ps missing %q in:\n%s", want, out)
		}
	}

	out, _ = OneShot(arch, "ip route")
	if !strings.Contains(out, "default via "+hs.gw) {
		t.Errorf("ip route = %q; want default via %s", out, hs.gw)
	}

	out, _ = OneShot(arch, "route")
	if !strings.Contains(out, "Kernel IP routing table") {
		t.Errorf("route = %q", out)
	}

	out, _ = OneShot(arch, "arp")
	if !strings.Contains(out, "HWaddress") {
		t.Errorf("arp = %q", out)
	}
}

func TestHostStateDistinctAndStable(t *testing.T) {
	a := deriveHost(archetype.Lookup("debian 12"))
	b := deriveHost(archetype.Lookup("ubuntu 24.04 lts"))
	if a.ip == b.ip && a.mac == b.mac {
		t.Errorf("two archetypes produced identical ip+mac (%s/%s) — fingerprinting tell", a.ip, a.mac)
	}
	// Same archetype is stable across calls (deterministic seed).
	a2 := deriveHost(archetype.Lookup("debian 12"))
	if a.ip != a2.ip || a.mac != a2.mac {
		t.Errorf("same archetype not stable: %s/%s vs %s/%s", a.ip, a.mac, a2.ip, a2.mac)
	}
}
