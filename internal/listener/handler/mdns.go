package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// mdns is a minimal multicast-DNS responder (RFC 6762, UDP 5353). mDNS
// resolves *.local names and drives DNS-SD service discovery. On a honeypot
// an mDNS query is a host enumerating the local segment: a PTR query for
// "_services._dns-sd._udp.local" is a service-discovery sweep, and like
// LLMNR/NBNS mDNS is a name-resolution poisoning surface. We observe the
// query, flag it, and answer .local A queries pointing at ourselves so a
// follow-up connection lands on us (where another listener captures it).
type mdns struct{}

func (m *mdns) Name() string { return "mdns" }

func (m *mdns) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	// mDNS is the DNS wire format, so the LLMNR/DNS parser applies.
	name, qtype, ok := parseLLMNRQuery(payload)
	if !ok {
		return res, nil
	}
	res.Meta["qname"] = name
	res.Meta["qtype"] = qtype

	// DNS-SD service enumeration: the meta-query every discovery tool sends
	// to list the segment's advertised services.
	if strings.HasPrefix(name, "_services._dns-sd._udp") || strings.Contains(name, "._dns-sd.") {
		flagAnomaly(&res, "mdns-service-enumeration")
	}
	// Surface the specific service type the probe hunts for (e.g. _ssh._tcp,
	// _smb._tcp, _ipp._tcp) — high-value-target recon over mDNS.
	if svc := mdnsServiceType(name); svc != "" {
		res.Meta["mdns_service"] = svc
		switch svc {
		case "_ssh._tcp", "_sftp-ssh._tcp", "_smb._tcp", "_rdp._tcp", "_vnc._tcp":
			flagAnomaly(&res, "mdns-remote-access-recon")
		}
	}

	ourIP := pc.LocalAddr().String()
	if i := strings.LastIndex(ourIP, ":"); i >= 0 {
		ourIP = ourIP[:i]
	}
	if strings.HasPrefix(ourIP, "[") { // IPv6 literal — fall back to a v4 answer
		ourIP = "127.0.0.1"
	}
	if reply := buildLLMNRAnswer(payload, name, qtype, ourIP); reply != nil {
		if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		}
		res.BannerSent = "mdns A-record reply"
	}
	_ = cfg
	return res, nil
}

// mdnsServiceType extracts the "_service._proto" label pair from a DNS-SD
// query name (e.g. "_ssh._tcp.local" -> "_ssh._tcp"); "" if not a service name.
func mdnsServiceType(name string) string {
	i := strings.Index(name, "._tcp")
	if i < 0 {
		i = strings.Index(name, "._udp")
	}
	if i <= 0 || name[0] != '_' {
		return ""
	}
	return name[:i+5]
}
