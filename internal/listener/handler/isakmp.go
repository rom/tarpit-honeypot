package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// isakmp emulates an IKE/ISAKMP endpoint (UDP 500), the IPsec VPN key
// exchange. The ISAKMP header is: initiator cookie(8) responder cookie(8)
// next-payload(1) version(1) exchange-type(1) flags(1) message-id(4)
// length(4). We capture the probe and flag it, but DO NOT reply — IKE is a
// known reflection/amplification vector and bringing up a real exchange
// needs crypto we don't emulate. Recording the probe is the value.
type isakmp struct{}

func (isakmp) Name() string { return "isakmp" }

func (isakmp) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 28 {
		res.Meta["non_isakmp"] = true
		return res, nil
	}
	res.Meta["ike_version"] = isakmpVersion(payload[17])
	res.Meta["ike_exchange"] = isakmpExchange(payload[18])
	res.Meta["ike_length"] = int(binary.BigEndian.Uint32(payload[24:28]))
	flagAnomaly(&res, "ike-probe")
	return res, nil
}

func isakmpVersion(v byte) string {
	switch v >> 4 {
	case 1:
		return "1.0 (IKEv1)"
	case 2:
		return "2.0 (IKEv2)"
	}
	return "unknown"
}

func isakmpExchange(e byte) string {
	switch e {
	case 2:
		return "identity-protection (main mode)"
	case 4:
		return "aggressive"
	case 34:
		return "IKE_SA_INIT"
	case 35:
		return "IKE_AUTH"
	}
	return "other"
}
