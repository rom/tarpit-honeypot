package handler

import (
	"context"
	"fmt"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// UDPHandler is the contract for UDP banner-mode handlers. The handler
// inspects one incoming datagram and may write a reply via pc.WriteTo.
//
// Unlike TCP handlers, the same listener will spawn many UDP handles in
// parallel (one per packet from a unique source), so handler state must
// be either immutable or guarded by the handler itself.
type UDPHandler interface {
	Name() string
	Handle(ctx context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error)
}

// GetUDP returns the UDP handler for a configured listener.handler name.
// Any handler that wants honeynet topology can implement the optional
// HoneynetAware interface and the caller can call .SetHoneynetView()
// after construction.
//
// deps may be the zero value — handlers that consume archetype info
// (snmp) treat a nil arch as "no archetype", which keeps behavior
// identical to the v1.0 path.
func GetUDP(name string, deps Deps) (UDPHandler, error) {
	switch name {
	case "raw":
		return &rawUDP{}, nil
	case "snmp":
		return &snmp{arch: deps.Archetype}, nil
	case "ntp":
		return &ntp{}, nil
	case "bacnet":
		return &bacnet{}, nil
	case "tftp":
		return &tftp{}, nil
	case "ipmi":
		return &ipmi{}, nil
	case "syslog_udp":
		return &syslogUDP{}, nil
	case "radius":
		return &radius{}, nil
	case "sip":
		return &sipUDP{}, nil
	case "ssdp":
		return &ssdp{}, nil
	case "cldap":
		return &cldap{}, nil
	case "llmnr":
		return &llmnr{}, nil
	case "nbns":
		return &nbns{}, nil
	case "fins":
		return &fins{}, nil
	case "coap":
		return &coap{}, nil
	case "knx":
		return &knx{}, nil
	}
	return nil, fmt.Errorf("unknown udp handler %q", name)
}

// HoneynetAware is implemented by handlers that want the topology
// snapshot. SetHoneynetView is called immediately after construction
// (Get / GetUDP) when honeynets are configured.
type HoneynetAware interface {
	SetHoneynetView(HoneynetSnapshot)
}

// rawUDP records the packet bytes and optionally writes a static banner back.
type rawUDP struct{}

func (r *rawUDP) Name() string { return "raw" }

func (r *rawUDP) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}
	if cfg.Banner != "" {
		_, err := pc.WriteTo([]byte(cfg.Banner), src)
		if err != nil {
			res.Meta = map[string]any{"write_err": err.Error()}
		} else {
			res.BannerSent = cfg.Banner
		}
	}
	return res, nil
}
