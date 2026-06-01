package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// sflow is a UDP sFlow collector decoy (default port 6343). sFlow is the
// switch-centric flow-export counterpart to NetFlow: switches sample packets
// and counters and ship them to a collector. An exposed sFlow collector
// receives the sampling agent's identity and sample metadata — useful network
// reconnaissance and a sign a switch was pointed (or misconfigured) at us. We
// parse the sFlow v5 datagram header (version, agent address, sub-agent id,
// sequence, sample count) and record it. One-way UDP — we never reply.
type sflow struct{}

func (s *sflow) Name() string { return "sflow" }

func (s *sflow) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{"proto": "sflow"}}
	res.Payload = payload
	if len(payload) < 8 {
		res.Meta["sflow"] = "short"
		return res, nil
	}
	version := binary.BigEndian.Uint32(payload[0:4])
	res.Meta["sflow_version"] = int(version)
	if version != 5 {
		res.Meta["sflow"] = "unsupported-version"
		flagAnomaly(&res, "sflow-export-received")
		return res, nil
	}
	// v5 datagram: version(4) agentAddrType(4) agentAddr(4|16) subAgentID(4)
	// seqNumber(4) sysUptime(4) numSamples(4).
	addrType := binary.BigEndian.Uint32(payload[4:8])
	off := 8
	switch addrType {
	case 1: // IPv4
		if off+4 <= len(payload) {
			res.Meta["agent_address"] = net.IP(payload[off : off+4]).String()
			off += 4
		}
	case 2: // IPv6
		if off+16 <= len(payload) {
			res.Meta["agent_address"] = net.IP(payload[off : off+16]).String()
			off += 16
		}
	}
	if off+16 <= len(payload) {
		res.Meta["sub_agent_id"] = binary.BigEndian.Uint32(payload[off : off+4])
		res.Meta["sequence"] = binary.BigEndian.Uint32(payload[off+4 : off+8])
		res.Meta["uptime_ms"] = binary.BigEndian.Uint32(payload[off+8 : off+12])
		res.Meta["sample_count"] = binary.BigEndian.Uint32(payload[off+12 : off+16])
	}
	flagAnomaly(&res, "sflow-export-received")
	return res, nil
}
