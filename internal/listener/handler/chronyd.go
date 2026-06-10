package handler

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// chronyd implements the chrony command/monitoring protocol (cmdmon) on UDP
// 323 — the control channel `chronyc` uses to talk to a chrony time daemon, the
// default NTP implementation on modern RHEL/CentOS-Stream/Rocky/Alma/Oracle/
// Fedora/Amazon-Linux/SUSE-15/Ubuntu-20.04+ servers. It complements the NTP
// time service on UDP 123.
//
// cmdmon is bound to localhost by default; reaching it from off-box means the
// operator opened it with `bindcmdaddress`/`cmdallow`, and an external party
// speaking it is high-signal reconnaissance or control of the host clock. The
// protocol is also a historical DRDoS amplifier (the older `subnets_accessed` /
// `client_accesses` replies are large) and the target of CVE-2012-4502 (cmdmon
// buffer overflow) / CVE-2012-4503 (NULL deref), so — exactly like the NTP
// mode-6/7 path — we engage it WITHOUT becoming a useful reflector: every reply
// goes through the global `udpReflectLimiter` + the reply policy and is a tiny
// "no command access" status (what a default-deny chronyd returns to a remote
// client), never a data-bearing body.
type chronyd struct {
	lim *udpReflectLimiter
	id  *identity.Identity
}

func (c *chronyd) Name() string { return "chronyd" }

// chrony cmdmon constants (candm.h). The request header is:
//
//	u8 version | u8 pkt_type | u8 res1 | u8 res2 | u16 command | u16 attempt |
//	u32 sequence | u32 pad1 | u32 pad2 | <body>
const (
	chronyProtoVersion   = 6
	chronyPktCmdRequest  = 1
	chronyPktCmdReply    = 2
	chronyReplyNull      = 1  // RPY_NULL
	chronyStatusNoAccess = 10 // STT_NOHOSTACCESS — default-deny remote
)

func (c *chronyd) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{"proto": "chrony-cmdmon"}}

	// Reaching cmdmon at all (off the loopback chronyd binds by default) is a
	// recon/control signal regardless of how well-formed the request is.
	flagAnomaly(&res, "chrony-cmdmon-probe")

	if len(payload) < 20 {
		res.Meta["short_packet"] = true
		res.Meta["len"] = len(payload)
		flagAnomaly(&res, "chrony-cmdmon-malformed")
		// CVE-2012-4503: a truncated cmdmon request crashed older chronyd
		// (NULL deref). The under-length datagram is the observable trigger.
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2012-4503")
		flagAnomaly(&res, "cve:CVE-2012-4503")
		res.Meta["intent"] = "chrony cmdmon malformed request — parser DoS probe (CVE-2012-4503)"
		return res, nil
	}

	version := payload[0]
	pktType := payload[1]
	command := binary.BigEndian.Uint16(payload[4:6])
	seq := binary.BigEndian.Uint32(payload[8:12])
	res.Meta["chrony_version"] = int(version)
	res.Meta["chrony_command"] = int(command)
	res.Meta["chrony_pkt_type"] = int(pktType)

	if pktType != chronyPktCmdRequest {
		res.Meta["non_request_pkt"] = true
		flagAnomaly(&res, "chrony-cmdmon-malformed")
		return res, nil
	}

	class, name, intent := classifyChronyCommand(command)
	res.Meta["chrony_command_name"] = name
	res.Meta["chrony_command_class"] = class
	res.Meta["intent"] = intent
	switch class {
	case "clock-manipulation":
		flagAnomaly(&res, "chrony-clock-manipulation")
	case "source-manipulation":
		flagAnomaly(&res, "chrony-source-manipulation")
	case "access-control":
		flagAnomaly(&res, "chrony-access-control-change")
	case "service-control":
		flagAnomaly(&res, "chrony-service-control")
	case "recon":
		flagAnomaly(&res, "chrony-cmdmon-recon")
	}

	// CVE-2012-4502: the SUBNETS_ACCESSED / CLIENT_ACCESSES cmdmon replies
	// overflowed a fixed buffer in chronyd < 1.27 when the request asked for an
	// abnormal number of entries. Flag those request codes carrying a
	// suspiciously large body.
	if (command == chronyReqSubnetsAccessed || command == chronyReqClientAccesses) && len(payload) > 256 {
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2012-4502")
		flagAnomaly(&res, "cve:CVE-2012-4502")
		res.Meta["intent"] = "chrony cmdmon subnets/client-accesses overflow probe (CVE-2012-4502)"
	}

	// Reply like a real, reachable chronyd that denies remote command access by
	// default: a CMD_REPLY with status NOHOSTACCESS. It is smaller than the
	// request (never an amplifier) and carries no data, but it confirms a live
	// chrony to a scanner. Gated by the reply policy + the global reflect
	// limiter so the sensor can't be used as a reflector.
	if !AmplifierReplyAllowed("chronyd", "cmdmon", src) {
		res.Meta["amplifier_suppressed"] = true
	} else if !c.lim.allow() {
		res.Meta["rate_limited"] = true
	} else {
		reply := buildChronyReply(version, command, seq, chronyReplyNull, chronyStatusNoAccess)
		if _, err := pc.WriteTo(reply, src); err != nil {
			res.Meta["write_err"] = err.Error()
		} else {
			res.BannerSent = "chrony cmdmon NoHostAccess"
		}
	}
	return res, nil
}

// chrony cmdmon request codes (candm.h REQ_*). Numbers follow upstream chrony;
// a few have shifted across major versions, so unknown codes degrade to a
// generic recon label rather than being misclassified.
const (
	chronyReqOnline          = 1
	chronyReqOffline         = 2
	chronyReqBurst           = 3
	chronyReqSettime         = 11
	chronyReqLocal           = 12
	chronyReqNSources        = 14
	chronyReqSourceData      = 15
	chronyReqAllow           = 17
	chronyReqAllowAll        = 18
	chronyReqDeny            = 19
	chronyReqDenyAll         = 20
	chronyReqCmdAllow        = 21
	chronyReqCmdAllowAll     = 22
	chronyReqCmdDeny         = 23
	chronyReqCmdDenyAll      = 24
	chronyReqAddServer       = 27
	chronyReqAddPeer         = 28
	chronyReqDelSource       = 29
	chronyReqWriteRTC        = 30
	chronyReqDfreq           = 31
	chronyReqDoffset         = 32
	chronyReqTracking        = 33
	chronyReqSourcestats     = 34
	chronyReqSubnetsAccessed = 38
	chronyReqClientAccesses  = 39
	chronyReqMakestep        = 43
	chronyReqActivity        = 44
	chronyReqShutdown        = 67 // REQ_SHUTDOWN (chrony 4.x)
)

// classifyChronyCommand maps a cmdmon request code to (class, name, intent).
func classifyChronyCommand(cmd uint16) (class, name, intent string) {
	switch cmd {
	case chronyReqSettime, chronyReqDoffset, chronyReqDfreq, chronyReqMakestep:
		return "clock-manipulation", chronyCmdName(cmd),
			"chrony cmdmon clock manipulation (settime/offset/makestep) — host time-shift attempt"
	case chronyReqAddServer, chronyReqAddPeer, chronyReqDelSource, chronyReqOnline, chronyReqOffline, chronyReqBurst, chronyReqLocal:
		return "source-manipulation", chronyCmdName(cmd),
			"chrony cmdmon source manipulation (add/del server/peer) — NTP source tampering"
	case chronyReqAllow, chronyReqAllowAll, chronyReqDeny, chronyReqDenyAll,
		chronyReqCmdAllow, chronyReqCmdAllowAll, chronyReqCmdDeny, chronyReqCmdDenyAll:
		return "access-control", chronyCmdName(cmd),
			"chrony cmdmon access-control change (allow/deny) — loosening NTP/cmd access"
	case chronyReqShutdown, chronyReqWriteRTC:
		return "service-control", chronyCmdName(cmd),
			"chrony cmdmon service control (shutdown/writertc) — disrupting the time service"
	case chronyReqTracking, chronyReqNSources, chronyReqSourceData, chronyReqSourcestats,
		chronyReqActivity, chronyReqSubnetsAccessed, chronyReqClientAccesses:
		return "recon", chronyCmdName(cmd),
			"chrony cmdmon status read (tracking/sources/activity) — time-service reconnaissance"
	}
	return "recon", chronyCmdName(cmd), "chrony cmdmon request — time-service reconnaissance"
}

func chronyCmdName(cmd uint16) string {
	switch cmd {
	case chronyReqOnline:
		return "ONLINE"
	case chronyReqOffline:
		return "OFFLINE"
	case chronyReqBurst:
		return "BURST"
	case chronyReqSettime:
		return "SETTIME"
	case chronyReqLocal:
		return "LOCAL"
	case chronyReqNSources:
		return "N_SOURCES"
	case chronyReqSourceData:
		return "SOURCE_DATA"
	case chronyReqAllow:
		return "ALLOW"
	case chronyReqAllowAll:
		return "ALLOWALL"
	case chronyReqDeny:
		return "DENY"
	case chronyReqDenyAll:
		return "DENYALL"
	case chronyReqCmdAllow:
		return "CMDALLOW"
	case chronyReqCmdAllowAll:
		return "CMDALLOWALL"
	case chronyReqCmdDeny:
		return "CMDDENY"
	case chronyReqCmdDenyAll:
		return "CMDDENYALL"
	case chronyReqAddServer:
		return "ADD_SERVER"
	case chronyReqAddPeer:
		return "ADD_PEER"
	case chronyReqDelSource:
		return "DEL_SOURCE"
	case chronyReqWriteRTC:
		return "WRITERTC"
	case chronyReqDfreq:
		return "DFREQ"
	case chronyReqDoffset:
		return "DOFFSET"
	case chronyReqTracking:
		return "TRACKING"
	case chronyReqSourcestats:
		return "SOURCESTATS"
	case chronyReqSubnetsAccessed:
		return "SUBNETS_ACCESSED"
	case chronyReqClientAccesses:
		return "CLIENT_ACCESSES"
	case chronyReqMakestep:
		return "MAKESTEP"
	case chronyReqActivity:
		return "ACTIVITY"
	case chronyReqShutdown:
		return "SHUTDOWN"
	}
	return "UNKNOWN"
}

// buildChronyReply assembles a minimal CMD_REPLY header (no body): the version,
// echoed command + sequence, a reply type, and a status code. Layout mirrors
// chrony's CMD_Reply fixed header.
func buildChronyReply(version byte, command uint16, seq uint32, reply, status uint16) []byte {
	b := make([]byte, 28)
	b[0] = version
	b[1] = chronyPktCmdReply
	// b[2], b[3] reserved
	binary.BigEndian.PutUint16(b[4:6], command)
	binary.BigEndian.PutUint16(b[6:8], reply)
	binary.BigEndian.PutUint16(b[8:10], status)
	// b[10:16] pad (pad1/pad2/pad3)
	binary.BigEndian.PutUint32(b[16:20], seq)
	// b[20:28] pad
	return b
}
