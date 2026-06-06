package handler

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// ntp implements the bare minimum of NTPv4 (RFC 5905) needed to fingerprint
// a scanner. Incoming packet is 48 bytes minimum; we read mode + version,
// then write back a plausible server response with our clock.
//
// We do NOT support the NTP monlist or other amplification-prone commands
// (mode 7 / private mode). Those are an active attack vector — replying to
// them turns the honeypot into an amplifier. Anything that isn't mode 3
// (client) we record and drop.
type ntp struct{}

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
		// Don't reply to non-client requests. Especially: never reply to
		// mode 7 (private / monlist) or mode 6 (control) — those are the
		// classic NTP amplifiers. We DON'T answer (no reflection), but we do
		// flag the recon so an analyst sees the amplification probe.
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
			case 0:
				res.Meta["ntp_request"] = "REQ_PEER_LIST"
				flagAnomaly(&res, "ntp-mode7-private")
				res.Meta["intent"] = "NTP peer-list recon (mode 7 ntpdc private)"
			case 16:
				res.Meta["ntp_request"] = "REQ_GET_RESTRICT"
				flagAnomaly(&res, "ntp-mode7-private")
				res.Meta["intent"] = "NTP restrict-list recon (mode 7 ntpdc private)"
			default:
				flagAnomaly(&res, "ntp-mode7-private")
				res.Meta["intent"] = "NTP mode-7 (ntpdc private) query — amplification / recon surface"
			}
		case 6:
			// mode 6 (control). Decode the opcode; READVAR is the ntpq
			// amplification/recon vector (also abused by CVE-2016-9311-class crashes).
			flagAnomaly(&res, "ntp-control-query")
			op := payload[1] & 0x1f
			res.Meta["ntp_control_opcode"] = op
			if op == 2 {
				res.Meta["ntp_control"] = "READVAR"
				res.Meta["intent"] = "NTP mode-6 READVAR control query — ntpq config/version recon + amplification"
			} else {
				res.Meta["intent"] = "NTP mode-6 control query (ntpq) — recon / amplification"
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
