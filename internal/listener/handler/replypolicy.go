package handler

import (
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// dbReplyDelay is the deployment-wide artificial delay database handlers add
// before answering, so a decoy DB feels like a real, loaded server (seconds,
// not microseconds). 0 = no delay. Set once at startup.
var dbReplyDelay atomic.Int64

// SetDBReplyDelay installs the database reply delay (config sensor.db_reply_delay).
func SetDBReplyDelay(d time.Duration) {
	if d < 0 {
		d = 0
	}
	dbReplyDelay.Store(int64(d))
}

// dbReplyDelaySleep blocks for the configured DB reply delay (a no-op when 0).
func dbReplyDelaySleep() {
	if d := dbReplyDelay.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
}

// replyPolicy is the deployment-wide outbound-reply policy. It is the single
// lever that decides whether — and how far — a handler may talk back to a
// client, so an operator can run the sensor anywhere from a pure passive sink
// to a fully interactive trap. Set once at startup (SetReplyPolicy) and read
// concurrently by every listener, so the fields are immutable after start.
//
// Modes (config sensor.reply_policy):
//   - "full" (default)        any protocol may reply; full bidirectional /
//     interactive sessions + (opt-in) call-outs.
//   - "non-ot"               like full, but OT-class handlers are muted.
//   - "fingerprint"          may reply enough to fingerprint the client /
//     capture credentials, but no deep interactive
//     session and no outbound call-outs.
//   - "fingerprint-non-ot"   fingerprint level, and OT-class handlers muted.
//   - "mute"                 receive only — every outgoing byte is dropped and
//     no call-out is made.
type replyPolicy struct {
	mute            bool // drop all outbound bytes
	allowOT         bool // OT-class handlers may reply
	fullInteraction bool // deep sessions + outbound call-outs allowed
	noAmplifier     bool // never reply to amplifier modes (NTP mode6/7, reflectors)
}

var (
	globalReplyPolicy = replyPolicy{allowOT: true, fullInteraction: true} // default = full
	suppressLog       atomic.Int64                                        // throttle "reply suppressed" warnings
)

// SetReplyPolicy installs the deployment reply policy from the config strings.
// Called once before listeners start. An unknown mode falls back to "full"
// (current behavior) with a warning.
func SetReplyPolicy(mode string, noAmplifierReplies bool) {
	p := replyPolicy{noAmplifier: noAmplifierReplies}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "full":
		p.allowOT, p.fullInteraction = true, true
	case "non-ot", "non_ot":
		p.allowOT, p.fullInteraction = false, true
	case "fingerprint", "capture":
		p.allowOT, p.fullInteraction = true, false
	case "fingerprint-non-ot", "fingerprint_non_ot":
		p.allowOT, p.fullInteraction = false, false
	case "mute", "receive-only", "receive_only":
		p.mute, p.allowOT, p.fullInteraction = true, false, false
	default:
		slog.Warn("reply_policy: unknown mode, defaulting to full", "mode", mode)
		p.allowOT, p.fullInteraction = true, true
	}
	globalReplyPolicy = p
	if p.mute {
		slog.Warn("reply policy: MUTE — all outbound replies and call-outs are suppressed (receive-only)")
	} else if !p.allowOT {
		slog.Info("reply policy: OT-class handlers are muted", "full_interaction", p.fullInteraction)
	}
	if p.noAmplifier {
		slog.Info("reply policy: amplifier-mode replies (NTP mode 6/7, UDP reflectors) are suppressed")
	}
}

// otHandlers is the set of handler names classified as operational-technology /
// ICS so the reply policy can mute them as a class.
var otHandlers = map[string]bool{
	"modbus": true, "modbus_security": true, "modbuss": true, "modbus_udp": true,
	"s7": true, "s7comm_plus": true, "dnp3": true, "iec104": true,
	"ethernetip": true, "opcua": true, "mms": true, "iccp_secure": true,
	"bacnet": true, "ge_srtp": true, "codesys": true, "hartip": true,
	"pcworx": true, "proconos": true, "c37118": true, "osdp": true,
	"focas": true, "osisoft_pi": true, "fox": true, "atg": true,
	"proficy_historian": true, "canary_historian": true, "aspen_ip21": true,
	"melsec": true, "ads": true, "ads_discovery": true, "fins": true,
	"fins_tcp": true, "fins_udp": true, "roc_plus": true, "pcom": true,
	"secs_gem": true, "crimson": true, "knx": true, "profinet": true,
	"tristation": true, "bsap": true, "ge_egd": true, "lontalk": true,
	"wdbrpc": true, "siprotec": true,
}

// IsOTHandler reports whether a handler name is in the OT/ICS class.
func IsOTHandler(name string) bool { return otHandlers[name] }

// handlerMuted reports whether the named handler must produce NO outbound
// bytes under the current policy (global mute, or an OT handler with OT muted).
func handlerMuted(name string) bool {
	return globalReplyPolicy.mute || (!globalReplyPolicy.allowOT && IsOTHandler(name))
}

// FullInteractionAllowed reports whether deep/interactive engagement (shell
// sessions, accept-creds post-auth sessions, outbound sample retrieval) is
// permitted. False under fingerprint / mute modes.
func FullInteractionAllowed() bool { return globalReplyPolicy.fullInteraction }

// AmplifierReplyAllowed reports whether a handler may answer an amplifier-mode
// request (NTP mode 6/7, UDP reflectors). When the policy suppresses them it
// also logs a throttled special warning so the operator sees the staged DRDoS
// probe being declined.
func AmplifierReplyAllowed(handlerName, kind string, src net.Addr) bool {
	if !globalReplyPolicy.noAmplifier {
		return true
	}
	if n := suppressLog.Add(1); n <= 20 || n%1000 == 0 {
		slog.Warn("amplifier reply suppressed by reply policy",
			"handler", handlerName, "kind", kind, "src", addrString(src))
	}
	return false
}

// GateConn returns conn unchanged when the named handler may reply, or a
// write-discarding wrapper when the policy mutes it — so the handler still
// reads + captures the request but emits nothing on the wire.
func GateConn(conn net.Conn, handlerName string) net.Conn {
	if handlerMuted(handlerName) {
		return &discardConn{Conn: conn}
	}
	return conn
}

// GatePacketConn does the same for a UDP handler's reply socket.
func GatePacketConn(pc net.PacketConn, handlerName string) net.PacketConn {
	if handlerMuted(handlerName) {
		return &discardPacketConn{PacketConn: pc}
	}
	return pc
}

// discardConn wraps a net.Conn and silently drops all writes (reads pass
// through, so request capture still works).
type discardConn struct{ net.Conn }

func (d *discardConn) Write(b []byte) (int, error) { return len(b), nil }

// discardPacketConn drops all WriteTo calls (no UDP reply / reflection).
type discardPacketConn struct{ net.PacketConn }

func (d *discardPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
