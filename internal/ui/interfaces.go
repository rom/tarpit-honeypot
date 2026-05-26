package ui

import (
	"net"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// netIfaceCard is one host network interface as it appears on the /config
// board: what the OS reports (name, MAC, MTU, link state, addresses) plus a
// cross-reference against the sensor — whether it's listed in
// `sensor.interfaces` (the sniffer / responder pin set) and how many listener
// ports land on it (a wildcard bind hits every up, non-loopback interface; a
// specific-IP bind hits only the interface that owns that IP). Lets an
// operator confirm at a glance that the sensor is reachable where they expect.
type netIfaceCard struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	IPv4      []string `json:"ipv4,omitempty"`
	IPv6      []string `json:"ipv6,omitempty"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Multicast bool     `json:"multicast"`
	Pinned    bool     `json:"pinned"`    // explicitly listed in sensor.interfaces
	BoundTCP  int      `json:"bound_tcp"` // tcp listener ports bound here
	BoundUDP  int      `json:"bound_udp"` // udp listener ports bound here
}

// buildInterfaces enumerates the host's network interfaces and tags each one
// with sensor cross-references. Returns nil on enumeration error so a flaky
// platform layer can't break the page.
func buildInterfaces(c *config.Config) []netIfaceCard {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	pinned := map[string]bool{}
	if c != nil {
		for _, n := range c.Sensor.Interfaces {
			pinned[n] = true
		}
	}

	// Pre-resolve listener binds into two buckets: wildcard counts (apply to
	// every up, non-loopback / loopback interface respectively) and
	// specific-IP counts keyed by the bound IP.
	var wildTCP, wildUDP int
	specific := map[string]struct{ tcp, udp int }{}
	if c != nil {
		for _, l := range c.Listeners {
			proto := strings.ToLower(strings.TrimSpace(l.Proto))
			host, _, err := net.SplitHostPort(l.Bind)
			if err != nil {
				continue
			}
			host = strings.Trim(strings.TrimSpace(host), "[]")
			if host == "" || host == "0.0.0.0" || host == "::" {
				if proto == "udp" {
					wildUDP++
				} else {
					wildTCP++
				}
				continue
			}
			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}
			s := specific[ip.String()]
			if proto == "udp" {
				s.udp++
			} else {
				s.tcp++
			}
			specific[ip.String()] = s
		}
	}

	out := make([]netIfaceCard, 0, len(ifaces))
	for _, iface := range ifaces {
		card := netIfaceCard{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			MTU:       iface.MTU,
			Up:        iface.Flags&net.FlagUp != 0,
			Loopback:  iface.Flags&net.FlagLoopback != 0,
			Multicast: iface.Flags&net.FlagMulticast != 0,
			Pinned:    pinned[iface.Name],
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			s := ipNet.String()
			if ipNet.IP.To4() != nil {
				card.IPv4 = append(card.IPv4, s)
			} else {
				card.IPv6 = append(card.IPv6, s)
			}
			if hit, ok := specific[ipNet.IP.String()]; ok {
				card.BoundTCP += hit.tcp
				card.BoundUDP += hit.udp
			}
		}
		if card.Up {
			card.BoundTCP += wildTCP
			card.BoundUDP += wildUDP
		}
		out = append(out, card)
	}

	// Stable, useful ordering: up before down, loopback last within its
	// group, then alphabetical by name. Loopback last because it's almost
	// never what an operator scans down to first.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Up != out[j].Up {
			return out[i].Up
		}
		if out[i].Loopback != out[j].Loopback {
			return !out[i].Loopback
		}
		return out[i].Name < out[j].Name
	})
	return out
}
