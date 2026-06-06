package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// adsDiscovery emulates the Beckhoff TwinCAT AMS/UDP discovery + route service
// on UDP 48899 — the broadcast TcAmsRemoteMgr / "Add Route" dialog uses to find
// TwinCAT systems and to add a remote route (with credentials) to them. A
// discovery request enumerates control systems; an AddRoute request is an
// attacker establishing a trusted engineering route — a foothold into the
// controller. We parse the AMS/UDP header, capture the sender AmsNetId and
// (for AddRoute) the embedded route/host/user strings, flag the operation, and
// answer a discovery request with a believable TwinCAT identity (bounded +
// globally rate-limited so it can't be used as a reflector). AddRoute is
// captured, never honored.
type adsDiscovery struct {
	id  *identity.Identity
	lim *udpReflectLimiter
}

func (a *adsDiscovery) Name() string { return "ads_discovery" }

// amsUDPMagic is the TwinCAT AMS/UDP header cookie (little-endian 0x71146603).
const amsUDPMagic = 0x71146603

func (a *adsDiscovery) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	flagAnomaly(&res, "ics-ads-discovery")
	if len(payload) < 16 || binary.LittleEndian.Uint32(payload[0:4]) != amsUDPMagic {
		res.Meta["non_ams_udp"] = true
		return res, nil
	}
	service := binary.LittleEndian.Uint32(payload[4:8]) &^ 0x80000000
	res.Meta["ams_udp_service"] = adsUDPServiceName(service)
	res.Meta["ams_source"] = amsNetID(payload[8:14])
	setIfEmpty(res.Meta, "intent", "TwinCAT AMS/UDP discovery — enumerating Beckhoff control systems")

	switch service {
	case 1: // identify / discovery — answer with our identity (bounded)
		if a.lim.allow() {
			reply := a.discoveryReply(service)
			if len(reply) <= len(payload) {
				if _, err := pc.WriteTo(reply, src); err == nil {
					res.BannerSent = "twincat ams discovery reply"
				}
			}
		}
	case 6: // AddRoute (carries route name / host / user / password) = foothold
		flagAnomaly(&res, "ics-ads-route-add")
		res.Meta["intent"] = "TwinCAT AMS AddRoute — adding a remote engineering route (control-system foothold)"
		if strs := amsPrintableStrings(payload[14:]); len(strs) > 0 {
			res.Meta["ams_route_fields"] = strs
		}
	}
	return res, nil
}

// discoveryReply builds a minimal, bounded AMS/UDP discovery response: the
// magic, the service with the response bit set, our (per-deployment) AmsNetId +
// the system-service port, and a zero tag count.
func (a *adsDiscovery) discoveryReply(service uint32) []byte {
	netID := []byte{5, 0, 0, 1, 1, 1}
	if a.id != nil {
		v := a.id.Uint32("twincat-amsnetid")
		netID = []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v), 1, 1}
	}
	out := make([]byte, 0, 20)
	out = binary.LittleEndian.AppendUint32(out, amsUDPMagic)
	out = binary.LittleEndian.AppendUint32(out, service|0x80000000)
	out = append(out, netID...)
	out = binary.LittleEndian.AppendUint16(out, 10000) // AMS system-service port
	out = binary.LittleEndian.AppendUint32(out, 0)     // tag count
	return out
}

// adsUDPServiceName names the AMS/UDP service ids relevant to enumeration.
func adsUDPServiceName(s uint32) string {
	switch s {
	case 1:
		return "Identify/Discovery"
	case 6:
		return "AddRoute"
	}
	return "service-" + itoa(int(s))
}

// amsPrintableStrings extracts the printable-ASCII runs (>=3 chars, capped) an
// AddRoute carries — the route name, target host, and username — without
// depending on the exact tag layout.
func amsPrintableStrings(b []byte) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= 3 {
			out = append(out, safe.SanitizeForLog(string(cur)))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
		} else {
			flush()
		}
		if len(out) >= 8 {
			break
		}
	}
	flush()
	return out
}
