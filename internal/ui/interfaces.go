package ui

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// strconvAtoi parses a decimal int and returns 0 on error — used for the port
// field so a malformed bind doesn't break the canvas.
func strconvAtoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// netIfaceCard is one host network interface as it appears on the /config
// board: what the OS reports (name, MAC, MTU, link state, addresses) plus a
// cross-reference against the sensor — whether it's listed in
// `sensor.interfaces` (the sniffer / responder pin set) and the concrete set
// of listener bind tuples (proto, port, handler) that land on it. A wildcard
// bind hits every up interface; a specific-IP bind hits only the interface
// that owns that IP. Lets an operator confirm at a glance that the sensor is
// reachable where they expect — and exactly which addresses are active.
type netIfaceCard struct {
	Name      string      `json:"name"`
	MAC       string      `json:"mac,omitempty"`
	MTU       int         `json:"mtu,omitempty"`
	IPv4      []string    `json:"ipv4,omitempty"`
	IPv6      []string    `json:"ipv6,omitempty"`
	Up        bool        `json:"up"`
	Loopback  bool        `json:"loopback"`
	Multicast bool        `json:"multicast"`
	Pinned    bool        `json:"pinned"`          // explicitly listed in sensor.interfaces
	BoundTCP  int         `json:"bound_tcp"`       // tcp listener ports bound here
	BoundUDP  int         `json:"bound_udp"`       // udp listener ports bound here
	Binds     []ifaceBind `json:"binds,omitempty"` // concrete proto/port/handler tuples
}

// ifaceBind is one listener bind that lands on the parent netIfaceCard. The
// Wildcard flag distinguishes binds inherited from a `0.0.0.0:*` / `[::]:*`
// listener (which appear on every up interface) from a specific-IP bind that
// targets only one interface.
type ifaceBind struct {
	Proto    string `json:"proto"`
	Port     int    `json:"port"`
	Handler  string `json:"handler,omitempty"`
	Wildcard bool   `json:"wildcard,omitempty"`
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

	// Pre-resolve listener binds into two buckets: wildcards (inherited by
	// every up interface) and specific-IP binds keyed by the bound IP.
	var wildBinds []ifaceBind
	specific := map[string][]ifaceBind{}
	if c != nil {
		for _, l := range c.Listeners {
			proto := strings.ToLower(strings.TrimSpace(l.Proto))
			if proto != "udp" {
				proto = "tcp" // anything unset/unknown is treated as TCP for display
			}
			host, portStr, err := net.SplitHostPort(l.Bind)
			if err != nil {
				continue
			}
			host = strings.Trim(strings.TrimSpace(host), "[]")
			port, _ := strconvAtoi(portStr)
			b := ifaceBind{Proto: proto, Port: port, Handler: l.Handler}
			if host == "" || host == "0.0.0.0" || host == "::" {
				b.Wildcard = true
				wildBinds = append(wildBinds, b)
				continue
			}
			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}
			specific[ip.String()] = append(specific[ip.String()], b)
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
			for _, b := range specific[ipNet.IP.String()] {
				card.Binds = append(card.Binds, b)
			}
		}
		if card.Up {
			card.Binds = append(card.Binds, wildBinds...)
		}
		for _, b := range card.Binds {
			if b.Proto == "udp" {
				card.BoundUDP++
			} else {
				card.BoundTCP++
			}
		}
		// Sort binds: tcp before udp, then by port — predictable across reloads.
		sort.SliceStable(card.Binds, func(i, j int) bool {
			if card.Binds[i].Proto != card.Binds[j].Proto {
				return card.Binds[i].Proto < card.Binds[j].Proto
			}
			return card.Binds[i].Port < card.Binds[j].Port
		})
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
