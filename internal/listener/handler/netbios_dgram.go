package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// netbiosDgram emulates the NetBIOS Datagram Service (UDP 138). Datagrams
// carry browser-protocol announcements and SMB mailslot traffic; a source
// sending them to the honeypot is doing legacy-Windows network discovery
// (or BadTunnel-style spoofing). We capture + flag, no reply.
type netbiosDgram struct{}

func (netbiosDgram) Name() string { return "netbios_dgram" }

func (netbiosDgram) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	if len(payload) < 1 {
		return res, nil
	}
	res.Meta["nbds_msg_type"] = nbdsType(payload[0])
	flagAnomaly(&res, "netbios-datagram")
	return res, nil
}

func nbdsType(t byte) string {
	switch t {
	case 0x10:
		return "DIRECT_UNIQUE"
	case 0x11:
		return "DIRECT_GROUP"
	case 0x12:
		return "BROADCAST"
	case 0x13:
		return "ERROR"
	case 0x14:
		return "QUERY_REQUEST"
	case 0x15:
		return "POSITIVE_QUERY_RESPONSE"
	case 0x16:
		return "NEGATIVE_QUERY_RESPONSE"
	}
	return "unknown"
}
