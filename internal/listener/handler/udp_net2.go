package handler

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/safe"
)

// Additional networking / mobile-core / overlay / utility-metering / lighting
// UDP protocol responders. All capture-only (no reply → no amplification);
// each decodes the protocol header and flags the probe.
//
//   gtp_c (2123), gtp_u (2152), vxlan (4789), geneve (6081), wccp (2048),
//   radius_acct (1813), dhcpv6 (547), ripng (521), babel (6696), bfd (3784),
//   ldp (646), teredo (3544), ike_natt (4500), mndp (5678), aruba_papi (8211),
//   artnet (6454), sacn (5568), collectd (25826), plex_gdm (32414), c1222 (1153)

// gtpC — GTP control plane (UDP 2123), the mobile (LTE/5G) core signalling.
type gtpC struct{}

func (g *gtpC) Name() string { return "gtp_c" }
func (g *gtpC) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "mobile-core-gtp-c-probe")
	if len(payload) >= 2 {
		res.Meta["gtp_version"] = payload[0] >> 5
		res.Meta["gtp_message_type"] = payload[1]
	}
	return res, nil
}

// gtpU — GTP user plane (UDP 2152): carries subscriber data tunnels (TEIDs).
type gtpU struct{}

func (g *gtpU) Name() string { return "gtp_u" }
func (g *gtpU) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "mobile-core-gtp-u-probe")
	if len(payload) >= 8 {
		res.Meta["gtp_message_type"] = payload[1]
		res.Meta["gtp_teid"] = binary.BigEndian.Uint32(payload[4:8])
	}
	return res, nil
}

// vxlan — VXLAN overlay (UDP 4789). A probe is a tenant-overlay injection attempt.
type vxlan struct{}

func (v *vxlan) Name() string { return "vxlan" }
func (v *vxlan) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "overlay-vxlan-probe")
	if len(payload) >= 8 && payload[0]&0x08 != 0 {
		res.Meta["vxlan_vni"] = uint32(payload[4])<<16 | uint32(payload[5])<<8 | uint32(payload[6])
		flagAnomaly(&res, "overlay-injection")
	}
	return res, nil
}

// geneve — Geneve overlay (UDP 6081).
type geneve struct{}

func (g *geneve) Name() string { return "geneve" }
func (g *geneve) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "overlay-geneve-probe")
	if len(payload) >= 8 {
		res.Meta["geneve_version"] = payload[0] >> 6
		res.Meta["geneve_vni"] = uint32(payload[4])<<16 | uint32(payload[5])<<8 | uint32(payload[6])
		flagAnomaly(&res, "overlay-injection")
	}
	return res, nil
}

// wccp — Cisco Web Cache Communication Protocol (UDP 2048).
type wccp struct{}

func (w *wccp) Name() string { return "wccp" }
func (w *wccp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "wccp-probe")
	if len(payload) >= 4 {
		res.Meta["wccp_message_type"] = binary.BigEndian.Uint32(payload[0:4])
		flagAnomaly(&res, "network-infra-probe")
	}
	return res, nil
}

// radiusAcct — RADIUS Accounting (UDP 1813). Captures the accounting username.
type radiusAcct struct{}

func (r *radiusAcct) Name() string { return "radius_acct" }
func (r *radiusAcct) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "radius-accounting-probe")
	if len(payload) >= 20 {
		res.Meta["radius_code"] = payload[0]
		// walk a couple attributes for User-Name (type 1).
		for p := 20; p+2 <= len(payload); {
			t, l := payload[p], int(payload[p+1])
			if l < 2 || p+l > len(payload) {
				break
			}
			if t == 1 {
				res.Meta["user_name"] = safe.SanitizeForLog(string(payload[p+2 : p+l]))
			}
			p += l
		}
	}
	return res, nil
}

// dhcpv6 — DHCPv6 (UDP 547). Decodes the message type.
type dhcpv6 struct{}

func (d *dhcpv6) Name() string { return "dhcpv6" }
func (d *dhcpv6) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "dhcpv6-probe")
	if len(payload) >= 1 {
		res.Meta["dhcpv6_msg_type"] = payload[0]
	}
	return res, nil
}

// ripng — RIPng (UDP 521). A response is a route-injection attempt.
type ripng struct{}

func (r *ripng) Name() string { return "ripng" }
func (r *ripng) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ripng-probe")
	if len(payload) >= 2 {
		res.Meta["ripng_command"] = payload[0]
		if payload[0] == 2 {
			flagAnomaly(&res, "rip-route-injection")
		} else if payload[0] == 1 {
			flagAnomaly(&res, "routing-recon")
		}
	}
	return res, nil
}

// babel — Babel routing protocol (UDP 6696).
type babel struct{}

func (b *babel) Name() string { return "babel" }
func (b *babel) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "babel-routing-probe")
	if len(payload) >= 4 && payload[0] == 42 { // Babel magic
		res.Meta["babel_version"] = payload[1]
		flagAnomaly(&res, "routing-recon")
	}
	return res, nil
}

// bfd — Bidirectional Forwarding Detection (UDP 3784).
type bfd struct{}

func (b *bfd) Name() string { return "bfd" }
func (b *bfd) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "bfd-probe")
	if len(payload) >= 1 {
		res.Meta["bfd_version"] = payload[0] >> 5
		flagAnomaly(&res, "network-infra-probe")
	}
	return res, nil
}

// ldp — MPLS Label Distribution Protocol hello (UDP 646).
type ldp struct{}

func (l *ldp) Name() string { return "ldp" }
func (l *ldp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "mpls-ldp-probe")
	if len(payload) >= 2 {
		res.Meta["ldp_version"] = binary.BigEndian.Uint16(payload[0:2])
		flagAnomaly(&res, "network-infra-probe")
	}
	return res, nil
}

// teredo — Teredo IPv6-over-UDP tunneling (UDP 3544).
type teredo struct{}

func (t *teredo) Name() string { return "teredo" }
func (t *teredo) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "teredo-tunnel-probe")
	flagAnomaly(&res, "tunnel-probe")
	return res, nil
}

// ikeNATT — IKE/IPsec over NAT-T (UDP 4500). Non-ESP marker then ISAKMP.
type ikeNATT struct{}

func (i *ikeNATT) Name() string { return "ike_natt" }
func (i *ikeNATT) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ike-natt-probe")
	// 4 zero bytes = non-ESP marker, then the ISAKMP header (exchange at +18).
	if len(payload) >= 24 && binary.BigEndian.Uint32(payload[0:4]) == 0 {
		res.Meta["ike_exchange"] = payload[4+18]
		if payload[4+17]>>4 == 1 && payload[4+18] == 4 {
			flagAnomaly(&res, "ike-aggressive-mode")
		}
	}
	return res, nil
}

// mndp — MikroTik Neighbor Discovery Protocol (UDP 5678).
type mndp struct{}

func (m *mndp) Name() string { return "mndp" }
func (m *mndp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "mikrotik-mndp-probe")
	flagAnomaly(&res, "device-discovery-probe")
	if r := asciiRun(payload); len(r) >= 3 {
		res.Meta["mndp_text"] = safe.SanitizeForLog(clipStr(r, 96))
	}
	return res, nil
}

// arubaPAPI — Aruba PAPI controller protocol (UDP 8211).
type arubaPAPI struct{}

func (a *arubaPAPI) Name() string { return "aruba_papi" }
func (a *arubaPAPI) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "aruba-papi-probe")
	flagAnomaly(&res, "network-infra-probe")
	return res, nil
}

// artnet — Art-Net DMX-over-UDP stage/architectural lighting (UDP 6454).
type artnet struct{}

func (a *artnet) Name() string { return "artnet" }
func (a *artnet) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-artnet-probe")
	if len(payload) >= 10 && string(payload[0:7]) == "Art-Net" {
		op := binary.LittleEndian.Uint16(payload[8:10])
		res.Meta["artnet_opcode"] = "0x" + strconv.FormatInt(int64(op), 16)
		if op == 0x5000 { // ArtDmx — a lighting actuation
			flagAnomaly(&res, "ba-lighting-control")
		}
	}
	return res, nil
}

// sacn — Streaming ACN (E1.31) lighting control (UDP 5568).
type sacn struct{}

func (s *sacn) Name() string { return "sacn" }
func (s *sacn) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ba-sacn-probe")
	// E1.31 root layer ACN PID "ASC-E1.17".
	if indexFold(string(payload), "asc-e1.17") >= 0 {
		flagAnomaly(&res, "ba-lighting-control")
	}
	return res, nil
}

// collectd — collectd network plugin metrics (UDP 25826).
type collectd struct{}

func (c *collectd) Name() string { return "collectd" }
func (c *collectd) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "collectd-probe")
	if len(payload) >= 4 {
		res.Meta["collectd_part_type"] = binary.BigEndian.Uint16(payload[0:2])
	}
	return res, nil
}

// plexGDM — Plex GDM media-server discovery (UDP 32414).
type plexGDM struct{}

func (p *plexGDM) Name() string { return "plex_gdm" }
func (p *plexGDM) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "plex-gdm-probe")
	if hasPrefixFold(string(payload), "M-SEARCH") {
		res.Meta["plex_query"] = "discover"
	}
	return res, nil
}

// c1222 — ANSI C12.22 smart-meter / AMI networking (UDP 1153).
type c1222 struct{}

func (c *c1222) Name() string { return "c1222" }
func (c *c1222) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := captureUDP(payload, "ics-c1222-metering-probe")
	if len(payload) >= 1 && payload[0] == 0x60 { // ACSE AARQ tag
		res.Meta["c1222_acse"] = true
		flagAnomaly(&res, "ics-metering-access")
	}
	return res, nil
}
