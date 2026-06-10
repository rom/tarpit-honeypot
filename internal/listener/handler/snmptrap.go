package handler

import (
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// snmptrap is a passive SNMP trap / inform receiver for udp/162. Real
// management stations (and compromised devices) send traps here; attackers
// also hit 162 with malformed / oversized / fuzzed SNMP to fingerprint the
// trap host or to drive the SNMP-subsystem parsing bugs behind the Cisco IOS /
// IOS XE RCE class. We parse v1 / v2c traps + informs (and note v3) tolerantly,
// capture the source / version / community / enterprise / trap numbers /
// varbinds, flag malformed / oversized / non-standard / randomized-OID
// structure, attribute the Cisco SNMP RCE CVEs on a clear overflow primitive,
// and — for an inform, when the reply policy allows — return the acknowledgement
// a real receiver would so the sender proceeds (and reveals more).
type snmptrap struct{ lim *udpReflectLimiter }

func (s *snmptrap) Name() string { return "snmptrap" }

func (s *snmptrap) Handle(ctx context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Meta: map[string]any{}}
	res.Meta["bytes_in"] = int64(len(payload))

	in := inspectSNMP(payload)
	res.Meta["snmp_version"] = snmpVersionLabel(in.Version)
	if in.Community != "" {
		res.Meta["community"] = in.Community
	}
	if in.V3User != "" {
		res.Meta["snmp_v3_user"] = in.V3User
	}
	pdu := "unknown"
	switch {
	case in.IsInform:
		pdu = "inform"
	case in.IsTrap:
		pdu = "trap"
	case in.PDUType != 0:
		pdu = pduLabel(in.PDUType)
	}
	res.Meta["snmp_pdu"] = pdu
	if in.EnterpriseOID != "" {
		res.Meta["enterprise_oid"] = in.EnterpriseOID
	}
	if in.GenericTrap >= 0 {
		res.Meta["generic_trap"] = in.GenericTrap
		res.Meta["specific_trap"] = in.SpecificTrap
		if name := v1GenericTrapName(in.GenericTrap); name != "" {
			res.Meta["trap_type"] = name
		}
	}
	if in.VarbindCount > 0 {
		res.Meta["varbinds"] = in.VarbindCount
	}
	if len(in.VarbindOIDs) > 0 {
		res.Meta["varbind_oids"] = in.VarbindOIDs
	}
	// "intent" labels what the sender is doing, surfaced on the DNS/SNMP-style
	// analytics ("what the attacker is actually doing").
	res.Meta["intent"] = trapIntent(in)

	// A trap arriving on 162 with a default/guessed community is recon that the
	// receiver is open + which communities it accepts.
	if snmpIsDefaultCommunity(in.Community) {
		flagAnomaly(&res, "snmptrap-default-community")
		setIfEmpty(res.Meta, "intent", "SNMP trap with default community on 162 — trap-receiver recon")
	}

	// A spoofed trap forges events into the monitoring/SIEM pipeline; if a
	// varbind value carries shell metacharacters it targets snmptrapd traphandle
	// command execution, and CRLF/control bytes are a SIEM log-injection attempt.
	for _, v := range in.VarbindStrings {
		if strings.ContainsAny(v, ";|`&$") && strings.ContainsAny(v, "()/ ") {
			flagAnomaly(&res, "snmptrap-traphandle-injection")
			res.Meta["intent"] = "SNMP trap varbind with shell metacharacters — snmptrapd traphandle command injection"
		}
		if strings.ContainsAny(v, "\r\n") || strings.ContainsRune(v, 0x1b) {
			flagAnomaly(&res, "snmptrap-log-injection")
			setIfEmpty(res.Meta, "intent", "SNMP trap varbind with CRLF/control bytes — SIEM log injection")
		}
	}
	if in.IsTrap || in.IsInform {
		flagAnomaly(&res, "snmptrap-injection")
	}

	// Structural anomalies + Cisco IOS / IOS XE SNMP RCE-class attribution.
	applySNMPInspect(&res, in)

	res.BannerSent = "snmptrap " + pdu + " captured"

	// Acknowledge a well-formed inform (a real receiver must, or the sender
	// retransmits): echo the datagram back with the PDU type flipped from
	// InformRequest to GetResponse. The ack is size-neutral (response == request,
	// no amplification), but it is still an unsolicited reply to a spoofable UDP
	// source, so — like the other UDP responders — it is gated by the reply
	// policy (AmplifierReplyAllowed) and a global reflection rate limiter so the
	// sensor can't be turned into a 1:1 reflector.
	if in.IsInform && in.PDUTagOffset >= 0 && len(in.Anomalies) == 0 {
		switch {
		case !AmplifierReplyAllowed("snmptrap", "inform-ack", src):
			res.Meta["amplifier_suppressed"] = true
		case !s.lim.allow():
			res.Meta["rate_limited"] = true
		default:
			ack := make([]byte, len(payload))
			copy(ack, payload)
			ack[in.PDUTagOffset] = pduGetResponse
			if _, err := pc.WriteTo(ack, src); err == nil {
				res.Meta["inform_ack"] = true
			}
		}
	}
	return res, nil
}

func snmpVersionLabel(v int) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	default:
		return "unknown"
	}
}

func pduLabel(tag byte) string {
	switch tag {
	case pduGetRequest:
		return "get-request"
	case pduGetResponse:
		return "get-response"
	case pduSetRequest:
		return "set-request"
	case pduGetBulk:
		return "get-bulk"
	case pduV1Trap:
		return "trap"
	case pduV2Trap:
		return "trap"
	case pduInform:
		return "inform"
	default:
		return "unknown"
	}
}

// v1GenericTrapName maps the SNMPv1 generic-trap number to its name.
func v1GenericTrapName(n int) string {
	switch n {
	case 0:
		return "coldStart"
	case 1:
		return "warmStart"
	case 2:
		return "linkDown"
	case 3:
		return "linkUp"
	case 4:
		return "authenticationFailure"
	case 5:
		return "egpNeighborLoss"
	case 6:
		return "enterpriseSpecific"
	default:
		return ""
	}
}

func trapIntent(in snmpInspection) string {
	switch {
	case len(in.CVEs) > 0:
		return "snmp-rce-attempt"
	case contains(in.Anomalies, "snmp-malformed-asn1"):
		return "malformed-snmp"
	case contains(in.Anomalies, "snmp-nonstandard-version"):
		return "snmp-version-probe"
	case contains(in.Anomalies, "snmp-oversized-packet"), contains(in.Anomalies, "snmp-varbind-flood"):
		return "snmp-fuzzing"
	case in.IsInform:
		return "snmp-inform"
	case in.IsTrap:
		return "snmp-trap"
	default:
		return "snmp-probe"
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
