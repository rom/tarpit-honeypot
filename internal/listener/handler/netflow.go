package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// netflow is a UDP NetFlow / IPFIX collector decoy (default port 2055/4739/9995).
// Routers, firewalls and switches export flow records to a configured
// collector; an exposed collector (or one an attacker points a compromised
// router at) receives a map of who-talks-to-whom on the network — valuable
// reconnaissance. We parse the export header (NetFlow v5 / v9 / IPFIX v10),
// record the version, source-router info, and flow/record counts, and — for v5,
// whose record layout is fixed — decode the first few flows (src/dst IP, ports,
// protocol, bytes). We never reply (flow export is one-way UDP; a reply would
// be a reflection surface).
type netflow struct{}

func (n *netflow) Name() string { return "netflow" }

func (n *netflow) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{"proto": "netflow"}}
	res.Payload = payload
	if len(payload) < 4 {
		res.Meta["netflow"] = "short"
		return res, nil
	}
	version := binary.BigEndian.Uint16(payload[0:2])
	count := binary.BigEndian.Uint16(payload[2:4])
	res.Meta["netflow_version"] = int(version)

	switch version {
	case 5:
		res.Meta["flow_count"] = int(count)
		n.decodeV5(payload, int(count), &res)
	case 9:
		res.Meta["record_count"] = int(count)
		if len(payload) >= 20 {
			res.Meta["source_id"] = binary.BigEndian.Uint32(payload[16:20])
		}
	case 10: // IPFIX
		// IPFIX header: version(2) length(2) exportTime(4) seq(4) obsDomain(4).
		res.Meta["ipfix"] = true
		res.Meta["message_length"] = int(count) // for v10 the 2nd field is length, not count
		if len(payload) >= 16 {
			res.Meta["observation_domain"] = binary.BigEndian.Uint32(payload[12:16])
		}
	default:
		res.Meta["netflow"] = "unknown-version"
	}
	flagAnomaly(&res, "netflow-export-received")
	return res, nil
}

// decodeV5 decodes up to the first few fixed-layout NetFlow v5 records, which
// reveal the exporting network's actual traffic (src/dst/proto/bytes).
func (n *netflow) decodeV5(p []byte, count int, res *Result) {
	const hdr = 24
	const rec = 48
	if count > 30 {
		count = 30
	}
	var flows []map[string]any
	for i := 0; i < count && i < 5; i++ {
		off := hdr + i*rec
		if off+rec > len(p) {
			break
		}
		r := p[off:]
		flows = append(flows, map[string]any{
			"src":      net.IP(r[0:4]).String(),
			"dst":      net.IP(r[4:8]).String(),
			"src_port": int(binary.BigEndian.Uint16(r[32:34])),
			"dst_port": int(binary.BigEndian.Uint16(r[34:36])),
			"protocol": int(r[38]),
			"packets":  binary.BigEndian.Uint32(r[16:20]),
			"bytes":    binary.BigEndian.Uint32(r[20:24]),
		})
	}
	if len(flows) > 0 {
		res.Meta["flows"] = flows
	}
}
