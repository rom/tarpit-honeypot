package handler

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// ntp implements NTPv4 (RFC 5905) plus the mode-6 control (ntpq) and mode-7
// private (ntpdc) query surface a scanner probes. Incoming packet is 48 bytes
// minimum; we read mode + version and answer.
//
// Mode 6/7 are the classic NTP DRDoS amplifiers, so we engage them WITHOUT
// becoming a useful reflector: every mode-6/7 reply goes through the global
// `udpReflectLimiter` AND the bodies are kept minimal — a single READVAR
// system-variable line, a short peer list, a one-entry monlist (real monlist
// returns ~600 entries / ~556x; we return 1). That lets `ntpq -c rv`,
// `ntpq -c peers` and `ntpdc -c monlist` see a live, believable server (and be
// fingerprinted) while the aggregate reflected bandwidth stays capped.
type ntp struct {
	lim *udpReflectLimiter
	id  *identity.Identity
}

func (n *ntp) Name() string { return "ntp" }

// NTP time epoch starts 1900-01-01 UTC; Unix epoch is 1970-01-01.
const ntpEpochOffset = 2208988800

func (n *ntp) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...)}
	if len(payload) < 48 {
		res.Meta = map[string]any{"short_packet": true, "len": len(payload)}
		return res, nil
	}

	li := (payload[0] >> 6) & 0x03
	ver := (payload[0] >> 3) & 0x07
	mode := payload[0] & 0x07
	res.Meta = map[string]any{
		"li":   li,
		"ver":  ver,
		"mode": modeName(mode),
	}

	if mode != 3 {
		// Non-client modes. Mode 6 (ntpq control) and mode 7 (ntpdc private) are
		// the classic amplifiers — we answer them, but minimally and behind the
		// global reflection limiter (see the type doc), so the scanner is engaged
		// and fingerprinted without the box being a useful reflector.
		switch mode {
		case 7:
			// mode 7 (ntpdc private). Decode the implementation + request code:
			// REQ_MON_GETLIST (42) / REQ_MON_GETLIST_1 (20) is the monlist
			// amplifier; the others are reconnaissance.
			res.Meta["ntp_impl"] = payload[2]
			rc := payload[3]
			res.Meta["ntp_request_code"] = rc
			switch rc {
			case 20, 42:
				// The classic NTP monlist DRDoS reflector (huge amplification).
				res.Meta["ntp_request"] = "REQ_MON_GETLIST"
				flagAnomaly(&res, "ntp-monlist-amplification")
				flagAnomaly(&res, "cve:CVE-2013-5211")
				res.Meta["intent"] = "NTP monlist (mode 7) amplification — staging a DRDoS reflector (CVE-2013-5211, up to ~556x)"
				n.sendMode7(&res, payload, src, pc, ver, rc, n.monlistEntry(src))
			case 0:
				res.Meta["ntp_request"] = "REQ_PEER_LIST"
				flagAnomaly(&res, "ntp-mode7-private")
				res.Meta["intent"] = "NTP peer-list recon (mode 7 ntpdc private)"
				n.sendMode7(&res, payload, src, pc, ver, rc, nil)
			case 16:
				res.Meta["ntp_request"] = "REQ_GET_RESTRICT"
				flagAnomaly(&res, "ntp-mode7-private")
				res.Meta["intent"] = "NTP restrict-list recon (mode 7 ntpdc private)"
				n.sendMode7(&res, payload, src, pc, ver, rc, nil)
			default:
				flagAnomaly(&res, "ntp-mode7-private")
				res.Meta["intent"] = "NTP mode-7 (ntpdc private) query — amplification / recon surface"
				n.sendMode7(&res, payload, src, pc, ver, rc, nil)
			}
		case 6:
			// mode 6 (control). Decode the opcode; READVAR (2) is the ntpq
			// version/config recon vector, READSTAT (1) the `ntpq -c peers` list.
			flagAnomaly(&res, "ntp-control-query")
			op := payload[1] & 0x1f
			res.Meta["ntp_control_opcode"] = op
			switch op {
			case 2: // READVAR — `ntpq -c rv target`
				res.Meta["ntp_control"] = "READVAR"
				res.Meta["intent"] = "NTP mode-6 READVAR control query — ntpq version/config recon (ntpq -c rv)"
				n.sendControl(&res, payload, src, pc, ver, op, []byte(n.sysVars()))
			case 1: // READSTAT — `ntpq -c peers target` (peer association list)
				res.Meta["ntp_control"] = "READSTAT"
				res.Meta["intent"] = "NTP mode-6 READSTAT control query — ntpq peer enumeration (ntpq -c peers)"
				n.sendControl(&res, payload, src, pc, ver, op, ntpPeerStatus())
			default:
				res.Meta["intent"] = "NTP mode-6 control query (ntpq) — recon / amplification"
				n.sendControl(&res, payload, src, pc, ver, op, nil)
			}
		default:
			// Other non-client modes (symmetric/broadcast/reserved): not normal
			// for an inbound probe to a public time server.
			flagAnomaly(&res, "ntp-nonclient-mode")
			res.Meta["intent"] = "NTP non-client mode " + modeName(mode) + " probe"
		}
		// Structural tool fingerprint (ntpdc / ntpq / monlist scanner / legacy).
		var impl, rc byte
		if mode == 7 && len(payload) >= 4 {
			impl, rc = payload[2], payload[3]
		}
		if tools := toolfp.IdentifyNTP(mode, ver, impl, rc); len(tools) > 0 {
			res.Meta["tools"] = tools
			for _, t := range tools {
				flagAnomaly(&res, "tool:"+t)
			}
		}
		return res, nil
	}

	now := time.Now().UTC()
	sec, frac := ntpTime(now)

	resp := make([]byte, 48)
	resp[0] = byte((0)<<6 | (ver&0x07)<<3 | 4) // LI=0, version echoed, mode=4 (server)
	resp[1] = 2                                // stratum 2
	resp[2] = 4                                // poll interval (16s)
	resp[3] = 0xeb                             // precision ~ -21 (~0.5us)
	// root delay + dispersion: small positive constants
	binary.BigEndian.PutUint32(resp[4:8], 0x00000010)
	binary.BigEndian.PutUint32(resp[8:12], 0x00000010)
	// reference id "LOCL"
	copy(resp[12:16], []byte("LOCL"))
	// reference timestamp = now - poll
	rsec, rfrac := ntpTime(now.Add(-16 * time.Second))
	binary.BigEndian.PutUint32(resp[16:20], rsec)
	binary.BigEndian.PutUint32(resp[20:24], rfrac)
	// origin timestamp = client transmit timestamp (bytes 40..48 of request)
	copy(resp[24:32], payload[40:48])
	// receive timestamp = now
	binary.BigEndian.PutUint32(resp[32:36], sec)
	binary.BigEndian.PutUint32(resp[36:40], frac)
	// transmit timestamp = now
	binary.BigEndian.PutUint32(resp[40:44], sec)
	binary.BigEndian.PutUint32(resp[44:48], frac)

	if _, err := pc.WriteTo(resp, src); err != nil {
		res.Meta["write_err"] = err.Error()
	} else {
		res.BannerSent = "ntp v4 server response"
	}
	_ = cfg
	return res, nil
}

func ntpTime(t time.Time) (sec, frac uint32) {
	secs := t.Unix() + ntpEpochOffset
	nanos := t.Nanosecond()
	return uint32(secs), uint32(uint64(nanos) * (1 << 32) / 1_000_000_000)
}

func modeName(m byte) string {
	switch m {
	case 0:
		return "reserved"
	case 1:
		return "symmetric_active"
	case 2:
		return "symmetric_passive"
	case 3:
		return "client"
	case 4:
		return "server"
	case 5:
		return "broadcast"
	case 6:
		return "ntp_control"
	case 7:
		return "private"
	}
	return "?"
}

// ntpVersion returns a believable ntpd version banner, deployment-stable.
func (n *ntp) ntpVersion() string {
	pool := []string{
		"ntpd 4.2.8p15@1.3728-o", "ntpd 4.2.6p5@1.2349-o",
		"ntpd 4.2.8p17@1.4004-o", "ntpd 4.2.8p10@1.3728-o",
	}
	if n.id == nil {
		return pool[0]
	}
	return pool[int(n.id.Uint32("ntp-version"))%len(pool)]
}

// sysVars renders the NTP mode-6 READVAR system-variable string — exactly what
// `ntpq -c rv target` prints. The version + processor + system fields are the
// recon target; the rest are believable steady-state clock values.
func (n *ntp) sysVars() string {
	proc, system := "x86_64", "Linux/5.4.0-200-generic"
	refid := "192.168.0.1"
	return fmt.Sprintf(
		"version=\"%s\", processor=\"%s\", system=\"%s\", leap=00, stratum=2, "+
			"precision=-23, rootdelay=1.250, rootdisp=12.340, refid=%s, "+
			"reftime=0x%08x.00000000, clock=0x%08x.00000000, peer=12345, tc=10, "+
			"mintc=3, offset=0.123, frequency=-7.456, sys_jitter=0.061, "+
			"clk_jitter=0.092, clk_wander=0.005",
		n.ntpVersion(), proc, system, refid,
		uint32(time.Now().Unix())+ntpEpochOffset-16, uint32(time.Now().Unix())+ntpEpochOffset)
}

// ntpPeerStatus builds a READSTAT response body: (association-id, peer-status)
// 16-bit pairs for a couple of believable upstream peers. `ntpq -c peers`
// issues READSTAT first, then a per-association READVAR.
func ntpPeerStatus() []byte {
	// peer status word 0x961a ≈ reachable, sys.peer, candidate.
	return []byte{
		0x80, 0x01, 0x96, 0x1a, // assoc 0x8001, status 0x961a (sys.peer)
		0x80, 0x02, 0x94, 0x14, // assoc 0x8002, status 0x9414 (candidate)
		0x80, 0x03, 0x90, 0x14, // assoc 0x8003, status 0x9014 (reachable)
	}
}

// sendControl emits a mode-6 control response echoing the request's version +
// opcode with the response bit set, carrying body (the system-variable string
// or the peer-status list). Rate-limited; minimal body (no amplification).
func (n *ntp) sendControl(res *Result, req []byte, src net.Addr, pc net.PacketConn, ver, op byte, body []byte) {
	if !AmplifierReplyAllowed("ntp", "mode6-control", src) {
		res.Meta["amplifier_suppressed"] = true
		return
	}
	if !n.lim.allow() {
		res.Meta["rate_limited"] = true
		return
	}
	seq := uint16(0)
	if len(req) >= 4 {
		seq = binary.BigEndian.Uint16(req[2:4])
	}
	if len(body) > 468 { // keep one UDP control packet; never amplify
		body = body[:468]
	}
	resp := make([]byte, 12+len(body))
	resp[0] = byte((ver&0x07)<<3 | 6) // LI=0, version echoed, mode=6
	resp[1] = 0x80 | (op & 0x1f)      // Response bit + opcode
	binary.BigEndian.PutUint16(resp[2:4], seq)
	binary.BigEndian.PutUint16(resp[4:6], 0x0000)  // status
	binary.BigEndian.PutUint16(resp[6:8], 0x0000)  // association id
	binary.BigEndian.PutUint16(resp[8:10], 0x0000) // offset
	binary.BigEndian.PutUint16(resp[10:12], uint16(len(body)))
	copy(resp[12:], body)
	if _, err := pc.WriteTo(resp, src); err != nil {
		res.Meta["write_err"] = err.Error()
		return
	}
	res.BannerSent = "ntp mode-6 control response"
}

// monlistEntry builds a single 72-byte mon_getlist_1 record for the requesting
// source — enough to satisfy `ntpdc -c monlist` with one entry. We never return
// the full ~600-entry list a real server would (that's the amplification).
func (n *ntp) monlistEntry(src net.Addr) []byte {
	e := make([]byte, 72)
	binary.BigEndian.PutUint32(e[0:4], 64)  // avg_int
	binary.BigEndian.PutUint32(e[4:8], 1)   // last_int
	binary.BigEndian.PutUint32(e[8:12], 0)  // restr
	binary.BigEndian.PutUint32(e[12:16], 3) // count
	// remote + local addresses (v4-mapped); a believable upstream peer.
	if ua, ok := src.(*net.UDPAddr); ok && ua.IP.To4() != nil {
		copy(e[16:20], ua.IP.To4())
	}
	e[24], e[25], e[26], e[27] = 192, 168, 0, 10 // local addr
	binary.BigEndian.PutUint16(e[28:30], 123)    // port
	e[30] = 3                                    // mode (client)
	e[31] = 4                                    // version
	return e
}

// sendMode7 emits a mode-7 (ntpdc private) response. When entry is non-nil it
// carries exactly one monlist record; otherwise an empty item list. Rate-limited.
func (n *ntp) sendMode7(res *Result, req []byte, src net.Addr, pc net.PacketConn, ver, rc byte, entry []byte) {
	if !AmplifierReplyAllowed("ntp", "mode7-private", src) {
		res.Meta["amplifier_suppressed"] = true
		return
	}
	if !n.lim.allow() {
		res.Meta["rate_limited"] = true
		return
	}
	nitems := 0
	itemsize := 0
	if entry != nil {
		nitems = 1
		itemsize = len(entry)
	}
	resp := make([]byte, 8+len(entry))
	resp[0] = 0x80 | (ver&0x07)<<3 | 7 // Response bit + version + mode 7
	resp[1] = 0                        // auth=0, seq=0
	resp[2] = 3                        // implementation = IMPL_XNTPD
	resp[3] = rc                       // echo request code
	binary.BigEndian.PutUint16(resp[4:6], uint16(nitems&0x0fff))
	binary.BigEndian.PutUint16(resp[6:8], uint16(itemsize&0x0fff))
	copy(resp[8:], entry)
	if _, err := pc.WriteTo(resp, src); err != nil {
		res.Meta["write_err"] = err.Error()
		return
	}
	res.BannerSent = "ntp mode-7 private response"
}
