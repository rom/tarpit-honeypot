package handler

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

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

// udpReflectLimiter is a global token-bucket rate limiter that caps how
// many believable replies a discovery/reflector handler (coap/knx/ssdp/
// fins) emits per second. Those protocols are inherently amplifying
// (small request → larger response), and UDP source addresses are
// spoofable, so a per-source limit is defeated by spoofing — only a
// *global* cap bounds the total reflected bandwidth and makes the sensor
// useless as a DDoS reflector. It holds no per-source state, so it can't
// be a memory-exhaustion vector itself. nil = unlimited (unit tests that
// construct a handler directly).
type udpReflectLimiter struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	rate   float64 // tokens (replies) per second
	last   time.Time
}

func newUDPReflectLimiter() *udpReflectLimiter {
	return &udpReflectLimiter{tokens: 40, burst: 40, rate: 20, last: time.Now()}
}

// allow reports whether one reply may be sent now, consuming a token.
func (l *udpReflectLimiter) allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
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
		return &ssdp{lim: newUDPReflectLimiter()}, nil
	case "cldap":
		return &cldap{}, nil
	case "llmnr":
		return &llmnr{}, nil
	case "nbns":
		return &nbns{}, nil
	case "mdns":
		return &mdns{}, nil
	case "fins":
		return &fins{lim: newUDPReflectLimiter()}, nil
	case "coap":
		return &coap{lim: newUDPReflectLimiter()}, nil
	case "knx":
		return &knx{lim: newUDPReflectLimiter()}, nil
	case "isakmp":
		return isakmp{}, nil
	case "netbios_dgram":
		return netbiosDgram{}, nil
	case "stun":
		return &stun{lim: newUDPReflectLimiter()}, nil
	case "mssql_browser":
		return &mssqlBrowser{lim: newUDPReflectLimiter()}, nil
	case "profinet":
		return &profinet{}, nil
	case "wdbrpc":
		return &wdbrpc{lim: newUDPReflectLimiter()}, nil
	case "iax2":
		return &iax2{}, nil
	case "dhcp":
		return &dhcp{}, nil
	case "dns":
		return &dnsHandler{id: deps.Identity, topo: deps.HoneynetView}, nil
	case "statsd":
		return &statsd{}, nil
	case "tristation":
		return &tristation{lim: newUDPReflectLimiter()}, nil
	case "ge_egd":
		return &geEGD{}, nil
	case "bsap":
		return &bsap{lim: newUDPReflectLimiter()}, nil
	case "lontalk":
		return &lonTalk{}, nil
	case "dtls":
		return &dtls{}, nil
	case "quic":
		return &quicH{}, nil
	case "netflow":
		return &netflow{}, nil
	case "sflow":
		return &sflow{}, nil
	case "auto":
		return &autoUDP{}, nil
	case "echo":
		return &echoUDP{}, nil
	case "discard":
		return &discardUDP{}, nil
	case "daytime":
		return &daytimeUDP{}, nil
	case "qotd":
		return &qotdUDP{}, nil
	case "chargen":
		return &chargenUDP{}, nil
	case "time":
		return &timeUDP{}, nil
	}
	return nil, fmt.Errorf("unknown udp handler %q", name)
}

// HoneynetAware is implemented by handlers that want the topology
// snapshot. SetHoneynetView is called immediately after construction
// (Get / GetUDP) when honeynets are configured.
type HoneynetAware interface {
	SetHoneynetView(HoneynetSnapshot)
}

// autoUDP is the generic UDP catch-all: it records the datagram and guesses
// the protocol from its leading bytes, flagging unmodelled traffic. It never
// writes a response — a UDP reply to a (spoofable) source is a reflection /
// amplification primitive, which the honeypot must never become.
type autoUDP struct{}

func (a *autoUDP) Name() string { return "auto" }

func (a *autoUDP) Handle(_ context.Context, payload []byte, _ net.Addr, _ net.PacketConn, _ config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	if len(payload) == 0 {
		res.Meta["no_data"] = true
		return res, nil
	}
	res.Payload = append([]byte(nil), payload...)
	res.Meta["protocol_guess"] = guessProtocol(payload)
	res.Meta["bytes"] = len(payload)
	flagAnomaly(&res, "unknown-protocol")
	return res, nil
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
