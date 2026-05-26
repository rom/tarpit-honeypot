package ui

import (
	"net"
	"testing"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestBuildInterfacesPopulatesAndOrders(t *testing.T) {
	// Any host has at least loopback; we don't assert exact contents (the
	// platform decides), only that enumeration succeeds and the ordering rule
	// holds: up before down, loopback last within its up/down group.
	cards := buildInterfaces(nil)
	if len(cards) == 0 {
		t.Skip("no interfaces enumerated on this host")
	}
	for i := 1; i < len(cards); i++ {
		prev, cur := cards[i-1], cards[i]
		if prev.Up && !cur.Up {
			continue // up→down boundary
		}
		if !prev.Up && cur.Up {
			t.Errorf("ordering broken: down %q precedes up %q", prev.Name, cur.Name)
		}
		if prev.Up == cur.Up && prev.Loopback && !cur.Loopback {
			t.Errorf("ordering broken: loopback %q precedes non-loopback %q",
				prev.Name, cur.Name)
		}
	}
}

func TestBuildInterfacesPinnedFlag(t *testing.T) {
	cards := buildInterfaces(nil)
	if len(cards) == 0 {
		t.Skip("no interfaces enumerated on this host")
	}
	name := cards[0].Name
	cfg := &config.Config{}
	cfg.Sensor.Interfaces = []string{name, "definitely-not-an-iface"}
	cards = buildInterfaces(cfg)
	pinned := 0
	for _, c := range cards {
		if c.Pinned {
			pinned++
			if c.Name != name {
				t.Errorf("wrong iface pinned: %q (want %q)", c.Name, name)
			}
		}
	}
	if pinned != 1 {
		t.Errorf("pinned count = %d; want 1", pinned)
	}
}

// TestBuildInterfacesListenerCrossReference checks that listener bind
// addresses are counted on the right interface:
//   - a wildcard "0.0.0.0:N" / "[::]:N" hits every up interface (loopback
//     included; the kernel does deliver to lo for wildcard binds).
//   - a specific bind hits only the interface that owns that IP.
//   - a TCP vs UDP bind is counted in the right column.
func TestBuildInterfacesListenerCrossReference(t *testing.T) {
	// Pull a loopback address as the canonical "this host owns it" IP.
	cards := buildInterfaces(nil)
	var loIPv4 string
	for _, c := range cards {
		if c.Loopback {
			for _, a := range c.IPv4 {
				ip, _, _ := net.ParseCIDR(a)
				loIPv4 = ip.String()
				break
			}
			break
		}
	}
	if loIPv4 == "" {
		t.Skip("no loopback IPv4 to anchor cross-reference test")
	}
	cfg := &config.Config{}
	cfg.Listeners = []config.Listener{
		{ID: "wild-tcp", Proto: "tcp", Bind: "0.0.0.0:2222", Handler: "ssh"},
		{ID: "wild-udp", Proto: "udp", Bind: "0.0.0.0:53", Handler: "dns"},
		{ID: "lo-tcp", Proto: "tcp", Bind: loIPv4 + ":8088", Handler: "http"},
	}
	cards = buildInterfaces(cfg)
	var lo *netIfaceCard
	for i := range cards {
		if cards[i].Loopback {
			lo = &cards[i]
			break
		}
	}
	if lo == nil {
		t.Fatal("loopback iface missing from cards")
	}
	// Counts: the two wildcards + the explicit lo bind.
	if lo.BoundTCP < 2 || lo.BoundUDP < 1 {
		t.Errorf("loopback iface should reflect wildcard + specific binds; got tcp=%d udp=%d",
			lo.BoundTCP, lo.BoundUDP)
	}
	// Concrete binds: loopback gets every wildcard plus its own-IP binds.
	var sawLoSpecific, sawWildTCP, sawWildUDP bool
	for _, b := range lo.Binds {
		switch {
		case b.Port == 8088 && b.Handler == "http" && !b.Wildcard:
			sawLoSpecific = true
		case b.Port == 2222 && b.Wildcard && b.Proto == "tcp":
			sawWildTCP = true
		case b.Port == 53 && b.Wildcard && b.Proto == "udp":
			sawWildUDP = true
		}
	}
	if !sawLoSpecific {
		t.Errorf("loopback iface missing its specific 127.x:8088 bind; got %+v", lo.Binds)
	}
	if !sawWildTCP || !sawWildUDP {
		t.Errorf("loopback iface should inherit wildcard binds (wildTCP=%v wildUDP=%v); got %+v",
			sawWildTCP, sawWildUDP, lo.Binds)
	}
	// Binds are sorted: tcp before udp, then by port.
	for i := 1; i < len(lo.Binds); i++ {
		prev, cur := lo.Binds[i-1], lo.Binds[i]
		if prev.Proto > cur.Proto {
			t.Errorf("binds not sorted by proto: %s before %s", prev.Proto, cur.Proto)
		} else if prev.Proto == cur.Proto && prev.Port > cur.Port {
			t.Errorf("binds not sorted by port within %s: %d before %d",
				prev.Proto, prev.Port, cur.Port)
		}
	}
	// At least one up non-loopback iface should also see the wildcards.
	for _, c := range cards {
		if c.Up && !c.Loopback {
			if c.BoundTCP < 1 || c.BoundUDP < 1 {
				t.Errorf("wildcard bind missing from up non-loopback %q: tcp=%d udp=%d",
					c.Name, c.BoundTCP, c.BoundUDP)
			}
			// And the same wildcards should appear concretely in Binds.
			wild := 0
			for _, b := range c.Binds {
				if b.Wildcard {
					wild++
				}
			}
			if wild < 2 {
				t.Errorf("%q: expected >=2 wildcard binds in Binds; got %d (%+v)",
					c.Name, wild, c.Binds)
			}
			break
		}
	}
}
