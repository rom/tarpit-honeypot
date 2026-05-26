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
		{ID: "wild-tcp", Proto: "tcp", Bind: "0.0.0.0:2222"},
		{ID: "wild-udp", Proto: "udp", Bind: "0.0.0.0:53"},
		{ID: "lo-tcp", Proto: "tcp", Bind: loIPv4 + ":8088"},
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
	// Loopback should see the two wildcard binds + the explicit lo bind.
	if lo.BoundTCP < 2 || lo.BoundUDP < 1 {
		t.Errorf("loopback iface should reflect wildcard + specific binds; got tcp=%d udp=%d",
			lo.BoundTCP, lo.BoundUDP)
	}
	// At least one non-loopback up iface should also see the wildcards (when
	// the host has any). Skip the assertion on host with no non-loopback
	// interfaces — common inside minimal containers.
	for _, c := range cards {
		if c.Up && !c.Loopback {
			if c.BoundTCP < 1 || c.BoundUDP < 1 {
				t.Errorf("wildcard bind missing from up non-loopback %q: tcp=%d udp=%d",
					c.Name, c.BoundTCP, c.BoundUDP)
			}
			break
		}
	}
}
