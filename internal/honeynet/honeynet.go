// Package honeynet models artificial networks of artificial hosts. The
// sensor binds real sockets (or relies on the OS to route additional IPs
// to it) and, when an incoming connection's destination IP matches one
// of the configured honeynet hosts, dispatches to a host-specific handler
// instance whose identity (banner version, serial number, hostname) is
// deterministically derived from sensor.deployment_id + the host id.
//
// One sensor can therefore present as N distinct machines without
// running N separate processes.
package honeynet

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/jitter"
	"github.com/rom/tarpit-honeypot/internal/listener/handler"
)

// Topology is the indexed honeynet model. It owns one handler instance per
// (host, port) so each artificial host gets a stable, deployment-unique
// banner / serial / version string.
type Topology struct {
	nets        []Network
	hostByIP    map[string]*Host    // any host IP -> Host
	serviceByEP map[endpoint]*boundService
}

type Network struct {
	ID      string
	CIDR    string
	Prefix  netip.Prefix
	Gateway string
	DNS     string
	Domain  string
	Hosts   []*Host
}

type Host struct {
	NetID    string
	IP       string
	Hostname string
	OS       string        // free-form ("linux", "windows", "cisco-ios", ...)
	Services []*Service
	Identity *identity.Identity // derived per-host
}

type Service struct {
	Port    int
	Handler string
	Banner  string
}

type boundService struct {
	host    *Host
	service *Service
	h       handler.Handler // nil for UDP services (UDP lookup goes through a different path)
	udp     handler.UDPHandler
}

type endpoint struct {
	ip   string
	port int
}

// Build constructs a Topology from the YAML config and the sensor's root
// identity + jitter. Returns an empty Topology if no honeynets are
// configured.
func Build(cfg []config.Honeynet, id *identity.Identity, jit *jitter.Jitterer, dataDir string, urlCanaries []config.URLCanary, tlsRotate int) (*Topology, error) {
	t := &Topology{
		hostByIP:    map[string]*Host{},
		serviceByEP: map[endpoint]*boundService{},
	}
	for _, ncfg := range cfg {
		n := Network{
			ID:      ncfg.ID,
			CIDR:    ncfg.CIDR,
			Gateway: ncfg.Gateway,
			DNS:     ncfg.DNS,
			Domain:  ncfg.Domain,
		}
		if ncfg.CIDR != "" {
			p, err := netip.ParsePrefix(ncfg.CIDR)
			if err != nil {
				return nil, fmt.Errorf("honeynet %s: cidr %q: %w", ncfg.ID, ncfg.CIDR, err)
			}
			n.Prefix = p
		}
		for _, hcfg := range ncfg.Hosts {
			if _, err := netip.ParseAddr(hcfg.IP); err != nil {
				return nil, fmt.Errorf("honeynet %s: host %s: bad ip %q: %w", ncfg.ID, hcfg.Hostname, hcfg.IP, err)
			}
			h := &Host{
				NetID:    ncfg.ID,
				IP:       hcfg.IP,
				Hostname: hcfg.Hostname,
				OS:       hcfg.OS,
				Identity: id.Derive("honeynet/" + ncfg.ID + "/" + hcfg.IP),
			}
			for _, sc := range hcfg.Services {
				if sc.Port <= 0 || sc.Port > 65535 {
					return nil, fmt.Errorf("honeynet %s host %s: bad port %d", ncfg.ID, hcfg.IP, sc.Port)
				}
				s := &Service{Port: sc.Port, Handler: sc.Handler, Banner: sc.Banner}
				h.Services = append(h.Services, s)
				bound, err := buildBoundService(h, s, jit, dataDir, urlCanaries, tlsRotate)
				if err != nil {
					return nil, fmt.Errorf("honeynet %s host %s port %d: %w", ncfg.ID, hcfg.IP, sc.Port, err)
				}
				t.serviceByEP[endpoint{ip: hcfg.IP, port: sc.Port}] = bound
			}
			n.Hosts = append(n.Hosts, h)
			t.hostByIP[hcfg.IP] = h
		}
		t.nets = append(t.nets, n)
	}
	return t, nil
}

// buildBoundService constructs a handler instance keyed by the host's
// derived Identity. We try the TCP handler factory first; if that fails,
// fall back to the UDP factory. This means a single Service entry can
// host either a TCP or UDP protocol, with the listener dispatch picking
// the right path based on incoming proto.
func buildBoundService(h *Host, s *Service, jit *jitter.Jitterer, dataDir string, urlCanaries []config.URLCanary, tlsRotate int) (*boundService, error) {
	deps := handler.Deps{
		Identity:    h.Identity,
		Jitter:      jit,
		DataDir:     dataDir,
		URLCanaries: urlCanaries,
		TLSRotate:   tlsRotate,
	}
	bs := &boundService{host: h, service: s}
	if hd, err := handler.Get(s.Handler, deps); err == nil {
		bs.h = hd
		return bs, nil
	}
	if uh, err := handler.GetUDP(s.Handler); err == nil {
		bs.udp = uh
		return bs, nil
	}
	return nil, fmt.Errorf("no TCP or UDP handler for %q", s.Handler)
}

// Lookup returns the (Host, Handler, Service) tuple for an incoming TCP
// connection's destination IP+port, or nil/nil/nil if the destination is
// not part of any configured honeynet.
func (t *Topology) Lookup(dstIP string, port int) (*Host, handler.Handler, *Service) {
	if t == nil {
		return nil, nil, nil
	}
	bs, ok := t.serviceByEP[endpoint{ip: dstIP, port: port}]
	if !ok {
		return nil, nil, nil
	}
	return bs.host, bs.h, bs.service
}

// LookupUDP is the UDP-side equivalent.
func (t *Topology) LookupUDP(dstIP string, port int) (*Host, handler.UDPHandler, *Service) {
	if t == nil {
		return nil, nil, nil
	}
	bs, ok := t.serviceByEP[endpoint{ip: dstIP, port: port}]
	if !ok {
		return nil, nil, nil
	}
	return bs.host, bs.udp, bs.service
}

// HostByName performs forward DNS-style lookup: hostname (with or without
// the network's domain suffix) -> host. Used by the dnscanary listener
// to answer A queries for honeynet hostnames.
func (t *Topology) HostByName(qname string) *Host {
	if t == nil {
		return nil
	}
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, n := range t.nets {
		domain := strings.ToLower(strings.TrimSuffix(n.Domain, "."))
		for _, h := range n.Hosts {
			short := strings.ToLower(h.Hostname)
			if q == short {
				return h
			}
			if domain != "" && q == short+"."+domain {
				return h
			}
		}
	}
	return nil
}

// Networks returns the list of configured networks. Useful for the
// list-honeynets subcommand.
func (t *Topology) Networks() []Network {
	if t == nil {
		return nil
	}
	out := append([]Network(nil), t.nets...)
	return out
}

// HostsInNetwork returns the hosts for a given network id (or all if id is
// empty), sorted by IP.
func (t *Topology) HostsInNetwork(id string) []*Host {
	if t == nil {
		return nil
	}
	var out []*Host
	for _, n := range t.nets {
		if id != "" && n.ID != id {
			continue
		}
		out = append(out, n.Hosts...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Empty reports whether the topology has zero networks. Cheap and safe
// for the sensor's "should we enable honeynet dispatch?" check.
func (t *Topology) Empty() bool {
	return t == nil || len(t.nets) == 0
}
