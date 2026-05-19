package handler

import (
	"context"
	"fmt"
	"net"

	g "github.com/gosnmp/gosnmp"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// snmp parses incoming SNMPv1/v2c GetRequest packets, extracts the
// community string (a frequent credential-spraying target), and replies
// with a GetResponse echoing the request varbinds as nulls. v3 is not
// supported (auth would be complex and irrelevant for a honeypot).
type snmp struct{}

func (s *snmp) Name() string { return "snmp" }

func (s *snmp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}

	// gosnmp's SnmpPacket.UnmarshalMsg works on raw bytes via the GoSNMP
	// helper but constructing one for unmarshalling is awkward. We use the
	// low-level Unmarshal from gosnmp's package via the helper below.
	client := &g.GoSNMP{}
	pkt, err := client.SnmpDecodePacket(payload)
	if err != nil {
		res.Meta = map[string]any{"decode_err": err.Error()}
		// Still record what we saw, just don't reply (don't echo crap).
		return res, nil
	}
	meta := map[string]any{
		"version":   versionName(pkt.Version),
		"community": pkt.Community,
		"pdu_type":  pduTypeName(pkt.PDUType),
	}
	if len(pkt.Variables) > 0 {
		oids := make([]string, 0, len(pkt.Variables))
		for _, v := range pkt.Variables {
			oids = append(oids, v.Name)
		}
		meta["oids"] = oids
	}
	res.Meta = meta

	// Only reply to GetRequest / GetNextRequest. Traps/responses we just log.
	if pkt.PDUType != g.GetRequest && pkt.PDUType != g.GetNextRequest {
		return res, nil
	}

	// Build a GetResponse with Null values for each varbind.
	respPDUs := make([]g.SnmpPDU, 0, len(pkt.Variables))
	for _, v := range pkt.Variables {
		respPDUs = append(respPDUs, g.SnmpPDU{Name: v.Name, Type: g.Null})
	}
	respPkt := &g.SnmpPacket{
		Version:    pkt.Version,
		Community:  pkt.Community,
		PDUType:    g.GetResponse,
		RequestID:  pkt.RequestID,
		Error:      0,
		ErrorIndex: 0,
		Variables:  respPDUs,
	}
	out, err := respPkt.MarshalMsg()
	if err != nil {
		res.Meta["marshal_err"] = err.Error()
		return res, nil
	}
	if _, err := pc.WriteTo(out, src); err != nil {
		res.Meta["write_err"] = err.Error()
	} else {
		res.BannerSent = fmt.Sprintf("snmp %s GetResponse (community=%s)", versionName(pkt.Version), pkt.Community)
	}
	_ = cfg
	return res, nil
}

func versionName(v g.SnmpVersion) string {
	switch v {
	case g.Version1:
		return "v1"
	case g.Version2c:
		return "v2c"
	case g.Version3:
		return "v3"
	}
	return "unknown"
}

func pduTypeName(t g.PDUType) string {
	switch t {
	case g.GetRequest:
		return "GetRequest"
	case g.GetNextRequest:
		return "GetNextRequest"
	case g.GetResponse:
		return "GetResponse"
	case g.SetRequest:
		return "SetRequest"
	case g.Trap:
		return "Trap"
	case g.GetBulkRequest:
		return "GetBulkRequest"
	case g.InformRequest:
		return "InformRequest"
	case g.SNMPv2Trap:
		return "SNMPv2Trap"
	}
	return fmt.Sprintf("0x%02x", byte(t))
}
