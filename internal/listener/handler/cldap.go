package handler

import (
	"context"
	"net"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/config"
)

// cldap is LDAP-over-UDP (connectionless LDAP, port 389). AD scanners
// send a CLDAP "Netlogon" / rootDSE ping to enumerate domain
// controllers. The wire format is identical to TCP LDAP — same BER
// LDAPMessage — so we reuse the bind parser to dig out the search
// filter / DN, then reply with a synthesized empty searchResDone.
//
// A CLDAP probe from a wandering scanner is a strong AD-recon signal.
type cldap struct {
	hosts []HoneynetHost
	lim   *udpReflectLimiter
	arch  *archetype.Profile
}

func (c *cldap) Name() string { return "cldap" }

// SetHoneynetView lets the listener install topology data so cldap
// responses can advertise honeynet hosts as fake DCs in their meta.
func (c *cldap) SetHoneynetView(v HoneynetSnapshot) { c.hosts = v.Hosts }

func (c *cldap) Handle(_ context.Context, payload []byte, src net.Addr, pc net.PacketConn, cfg config.Listener) (Result, error) {
	res := Result{Payload: append([]byte(nil), payload...), Meta: map[string]any{}}
	mid, op, opBody, ok := parseLDAPMessage(payload)
	if !ok {
		res.Meta["bad_ldap"] = true
		return res, nil
	}
	res.Meta["message_id"] = mid
	res.Meta["op"] = ldapOpName(op)
	// 0x63 = SearchRequest [APPLICATION 3]
	if op == 0x63 {
		res.Meta["search_request_bytes"] = len(opBody)
		// An anonymous CLDAP SearchRequest (the AD "netlogon" query) is the
		// classic CLDAP reflection/amplification vector (small request → large
		// rootDSE/netlogon reply) and high-signal DC reconnaissance.
		flagAnomaly(&res, "cldap-netlogon-probe")
		flagAnomaly(&res, "amplification-probe")
		// CVE-2026-41089: a crafted CLDAP Netlogon request with an oversized
		// (130+ char) username overflows a 528-byte stack buffer in LSASS
		// (NetpLogonPutUnicodeString byte/WCHAR size confusion) → DC DoS / RCE.
		// The PoC fills the field with a long run of 'A's; flag any abnormally
		// long single-byte run in the datagram (legit CLDAP pings are tiny).
		if run := longestByteRun(payload); run >= 130 {
			flagAnomaly(&res, "cldap-netlogon-overflow")
			res.Meta["cldap_overflow_run"] = run
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2026-41089")
			flagAnomaly(&res, "cve:CVE-2026-41089")
		}
		// CLDAP Netlogon is itself an amplifier, so the reply is gated by the
		// amplifier policy + a global reflection limiter. When allowed, answer
		// like a real DC: a rootDSE SearchResultEntry carrying the AD naming
		// contexts (defaultNamingContext etc.) derived from the deployment
		// domain, followed by the searchResDone — all in one bounded datagram.
		if !AmplifierReplyAllowed("cldap", "netlogon", src) {
			res.Meta["amplifier_suppressed"] = true
		} else if !c.lim.allow() {
			res.Meta["rate_limited"] = true
		} else {
			dom := deploymentDomainOr("example.internal")
			res.Meta["ldap_default_naming_context"] = domainToDN(dom)
			reply := buildLDAPSearchResDone(mid)
			if isRootDSESearch(opBody) {
				reply = append(buildLDAPRootDSE(mid, dom, c.arch.ADFunctionalLevel()), reply...)
			}
			if _, err := pc.WriteTo(reply, src); err != nil {
				res.Meta["write_err"] = err.Error()
			}
			res.BannerSent = "cldap rootDSE + searchResDone"
		}
	} else if op == 0x60 { // BindRequest — rare on CLDAP but log it
		_, bindDN, simplePw, _ := parseBindRequest(opBody)
		res.Meta["bind_dn"] = bindDN
		flagAnomaly(&res, "ldap-bind-attempt")
		if simplePw != "" {
			res.Meta["bind_pw"] = simplePw
		}
		reply := buildLDAPBindResponse(mid, 49)
		_, _ = pc.WriteTo(reply, src)
		res.BannerSent = "cldap BindResponse invalidCredentials"
	}
	if len(c.hosts) > 0 {
		dcs := make([]map[string]string, 0, len(c.hosts))
		for _, h := range c.hosts {
			if h.OS == "windows" {
				dcs = append(dcs, map[string]string{
					"hostname": h.Hostname, "ip": h.IP,
				})
			}
		}
		if len(dcs) > 0 {
			res.Meta["honeynet_domain_controllers"] = dcs
		}
	}
	_ = cfg
	return res, nil
}

// buildLDAPSearchResDone returns a minimal searchResDone PDU
// (resultCode 0 / matchedDN empty / diagnosticMessage empty) wrapped
// in a SEQUENCE with the supplied message_id.
func buildLDAPSearchResDone(messageID int) []byte {
	// resultCode ENUMERATED + matchedDN OCTET STRING + diagnosticMessage OCTET STRING
	inner := []byte{0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	// [APP 5] = 0x65 (searchResDone)
	op := append([]byte{0x65, byte(len(inner))}, inner...)
	mid := encodeBERInt(messageID)
	body := append(mid, op...)
	return append([]byte{0x30, byte(len(body))}, body...)
}
