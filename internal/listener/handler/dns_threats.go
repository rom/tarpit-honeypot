package handler

import (
	"encoding/binary"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/toolfp"
)

// dnsApplyDetections runs the DNS threat-detection heuristics and DNS tool
// fingerprinting over one parsed query (msg is the raw DNS message, q the
// parsed first question) and stamps the result. Shared by the UDP and TCP DNS
// handlers so both transports get identical coverage. Detection only — it
// never changes what the resolver answers (and never makes UDP an amplifier).
func dnsApplyDetections(res *Result, msg []byte, q dnsQuery) {
	for _, a := range dnsThreatMarkers(msg, q) {
		flagAnomaly(res, a)
	}
	// SIG-record query (qtype 24) — the integer-overflow vector behind SIGRed
	// (CVE-2020-1350) in Windows DNS. A SIG lookup is otherwise near-extinct, so
	// it's a high-signal exploit/recon probe.
	if q.qtype == 24 {
		flagAnomaly(res, "dns-sig-query")
		flagAnomaly(res, "cve:CVE-2020-1350")
	}
	// TKEY query (qtype 249) — the ISC BIND assertion-failure DoS vector
	// (CVE-2015-5477); a legitimate client never sends a bare TKEY lookup.
	if q.qtype == 249 {
		flagAnomaly(res, "dns-tkey-query")
		flagAnomaly(res, "cve:CVE-2015-5477")
	}
	// Fingerprint the DNS recon/tunnel/OOB-interaction tool from the QNAME.
	if tools := toolfp.IdentifyDNS(q.name); len(tools) > 0 {
		if _, ok := res.Meta["tools"]; !ok {
			res.Meta["tools"] = tools
			res.Meta["tool_confidence"] = toolfp.ConfMedium
			res.Meta["tool_confidence_label"] = toolfp.ConfidenceLabel(toolfp.ConfMedium)
		}
		for _, t := range tools {
			flagAnomaly(res, "tool:"+t)
		}
	}
	// Summarize what the attacker is actually doing, for the UI intent column.
	if it := dnsIntent(res); it != "" {
		res.Meta["intent"] = it
	}
}

// dnsIntent reduces the flagged anomalies to a single human-readable "what the
// attacker is trying to do" label (most-severe-wins).
func dnsIntent(res *Result) string {
	set := map[string]bool{}
	if list, ok := res.Meta["anomalies"].([]string); ok {
		for _, a := range list {
			set[a] = true
		}
	}
	any := func(ms ...string) bool {
		for _, m := range ms {
			if set[m] {
				return true
			}
		}
		return false
	}
	switch {
	case any("cve:CVE-2020-1350", "dns-sig-query"):
		return "DNS SIG-record query — SIGRed (CVE-2020-1350) RCE/DoS probe"
	case any("cve:CVE-2015-5477", "dns-tkey-query"):
		return "DNS TKEY query — ISC BIND assertion-failure DoS probe (CVE-2015-5477)"
	case any("dns-zone-transfer", "dns-zone-transfer-served"):
		return "DNS zone transfer (AXFR/IXFR) — full-zone reconnaissance"
	case any("dns-dynamic-update"):
		return "DNS dynamic update — unauthorized record injection (RFC 2136)"
	case any("dns-null-record", "dns-cname-tunnel", "dns-long-encoded-label", "dns-many-labels", "dns-repeated-label"):
		return "DNS tunneling / data exfiltration over DNS"
	case any("dns-oob-interaction"):
		return "DNS out-of-band interaction — SSRF/RCE callback / blind-exploit confirmation"
	case any("dns-any-amplification", "dns-dnssec-amplification", "dns-edns-large-udpsize"):
		return "DNS amplification — staging a DRDoS reflector"
	case any("dns-rebind-lookup"):
		return "DNS rebinding lookup — browser SOP bypass setup"
	case any("dns-wpad-probe", "dns-isatap-probe", "dns-response-as-query", "dns-prestuffed-answers", "dns-additional-stuffing"):
		return "DNS spoofing / MITM positioning (WPAD/ISATAP/cache-poison)"
	case any("dns-srv-ad-discovery"):
		return "Active Directory service discovery via DNS SRV"
	case any("dns-ptr-reverse-sweep"):
		return "DNS reverse-PTR sweep — network mapping"
	case any("dns-dnssec-recon", "dns-nsec-walk"):
		return "DNSSEC zone-walk reconnaissance"
	case any("dns-internal-tld-leak", "dns-mail-policy-probe", "dns-chaos-class", "dns-srv-ad-discovery"):
		return "DNS namespace / policy reconnaissance"
	case any("dns-inverse-query", "dns-notify-opcode", "dns-multi-question", "dns-nonstandard-class"):
		return "DNS protocol-anomaly / fuzzing probe"
	}
	return ""
}

// dnsThreatMarkers inspects a parsed DNS query (plus the raw message for header
// flags / section counts / EDNS OPT) and returns anomaly markers for
// DNS-specific vulnerabilities, info leakage, recon, tunneling/exfil, cache
// poisoning and DoS. Computable from a single message, so it works identically
// on the UDP and TCP paths; complements dnsQueryAnomalies (no overlap).
func dnsThreatMarkers(msg []byte, q dnsQuery) []string {
	var out []string
	add := func(m string) { out = append(out, m) }
	name := q.name
	labels := strings.Split(name, ".")

	// --- header: QR bit, opcode, section counts (RFC 1035 §4.1.1) ---
	if len(msg) >= 12 {
		flags1 := msg[2]
		opcode := (flags1 >> 3) & 0x0f
		if flags1&0x80 != 0 { // QR=1 on an *inbound* query
			add("dns-response-as-query") // reflected response / cache-poisoning probe
		}
		switch opcode {
		case 1:
			add("dns-inverse-query") // IQUERY — obsolete (RFC 3425), a scanner tell
		case 4:
			add("dns-notify-opcode") // unsolicited NOTIFY
		case 5:
			add("dns-dynamic-update") // RFC 2136 UPDATE — unauthorized record injection
		}
		qd := binary.BigEndian.Uint16(msg[4:6])
		an := binary.BigEndian.Uint16(msg[6:8])
		ns := binary.BigEndian.Uint16(msg[8:10])
		ar := binary.BigEndian.Uint16(msg[10:12])
		if qd > 1 {
			add("dns-multi-question")
		}
		if an > 0 || ns > 0 { // a *query* carrying answer/authority RRs
			add("dns-prestuffed-answers")
		}
		if ar > 1 { // more than a lone EDNS OPT in the additional section
			add("dns-additional-stuffing")
		}
	}

	// --- query class ---
	switch q.qclass {
	case 1, 3, 254, 255: // IN, CHAOS, NONE, ANY
	default:
		add("dns-nonstandard-class")
	}
	if q.qclass == 3 { // CHAOS — server-identity recon/leak (version.bind family)
		add("dns-chaos-class")
	}

	// --- qtype-driven recon / DNSSEC / service binding / tunnelling ---
	switch q.qtype {
	case 43, 46, 47, 48, 50, 51: // DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM
		add("dns-dnssec-recon")
		if q.qtype == 47 || q.qtype == 50 {
			add("dns-nsec-walk") // NSEC/NSEC3 zone-walking
		}
	case 64, 65: // SVCB, HTTPS
		add("dns-svcb-probe")
	case 257: // CAA
		add("dns-caa-probe")
	case 10: // NULL — the classic high-capacity tunnel record (iodine)
		add("dns-null-record")
	case 5: // CNAME
		if dnsLongOrEncodedLeftLabel(labels) {
			add("dns-cname-tunnel")
		}
	}

	// --- name-driven recon / leakage / MITM bait ---
	if strings.Contains(name, "_dmarc.") || strings.Contains(name, "_domainkey") || strings.HasPrefix(name, "_spf.") {
		add("dns-mail-policy-probe") // SPF/DKIM/DMARC enumeration
	}
	if q.qtype == 33 && (strings.Contains(name, "_ldap._tcp") || strings.Contains(name, "_kerberos.") ||
		strings.Contains(name, "_gc._tcp") || strings.Contains(name, "_kpasswd.") || strings.Contains(name, "_msdcs")) {
		add("dns-srv-ad-discovery") // Active Directory SRV service discovery
	}
	if q.qtype == 12 && (strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")) {
		add("dns-ptr-reverse-sweep")
	}
	if dnsInternalTLD(name) {
		add("dns-internal-tld-leak") // internal namespace leaking to a public resolver
	}
	if strings.HasPrefix(name, "wpad.") {
		add("dns-wpad-probe") // Web Proxy Auto-Discovery MITM
	}
	if strings.HasPrefix(name, "isatap.") {
		add("dns-isatap-probe") // IPv6 transition-tunnel MITM
	}
	if dnsOOBService(name) {
		add("dns-oob-interaction") // SSRF/RCE out-of-band callback (interactsh / Burp / dnslog / …)
	}
	if dnsRebindService(name) {
		add("dns-rebind-lookup") // nip.io / sslip.io / xip.io style DNS rebinding
	}

	// --- tunnelling / exfil structure ---
	if len(labels) > 20 {
		add("dns-many-labels") // chunked exfil over many sub-labels
	}
	for _, l := range labels {
		if len(l) >= 32 && dnsLabelLooksEncoded(l) {
			add("dns-long-encoded-label")
			break
		}
	}
	if dnsHasRepeatedLabel(labels, 8) {
		add("dns-repeated-label") // parser / cache stress
	}
	if (q.qtype == 1 || q.qtype == 28) && len(labels) >= 2 && len(labels) <= 3 && dnsLabelLooksDGA(labels[0]) {
		add("dns-random-subdomain") // pseudo-random-subdomain (water-torture) DoS
	}

	// --- EDNS(0) OPT: amplification setup / fuzzing ---
	if size, doBit, ver, present := dnsEDNS(msg, q.questionEnd); present {
		if size >= 4096 {
			add("dns-edns-large-udpsize") // oversized UDP buffer — reflection/amplification primer
		}
		if ver != 0 {
			add("dns-edns-version-nonzero") // EDNS version != 0 — fuzzing / non-conformant client
		}
		if doBit && (q.qtype == 255 || q.qtype == 48 || q.qtype == 46) {
			add("dns-dnssec-amplification") // DO bit + ANY/DNSKEY/RRSIG — large-response amplification
		}
	}
	return out
}

// dnsLongOrEncodedLeftLabel reports whether the leftmost label looks like a
// tunnel chunk (very long, or moderately long and base32/hex-encoded).
func dnsLongOrEncodedLeftLabel(labels []string) bool {
	if len(labels) == 0 {
		return false
	}
	l := labels[0]
	return len(l) >= 30 || (len(l) >= 20 && dnsLabelLooksEncoded(l))
}

var dnsInternalTLDs = []string{
	".local", ".internal", ".corp", ".lan", ".home", ".intranet",
	".localdomain", ".workgroup", ".home.arpa",
}

func dnsInternalTLD(name string) bool {
	for _, t := range dnsInternalTLDs {
		if strings.HasSuffix(name, t) {
			return true
		}
	}
	return false
}

var dnsOOBServices = []string{
	"burpcollaborator", "oast.fun", "oast.site", "oast.online", "oast.live",
	"oast.pro", "interact.sh", "dnslog.cn", "ceye.io", "canarytokens.com",
	"requestbin", "pipedream.net",
}

func dnsOOBService(name string) bool {
	for _, s := range dnsOOBServices {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

var dnsRebindServices = []string{"nip.io", "sslip.io", "xip.io", "1u.ms", "rbndr.us"}

func dnsRebindService(name string) bool {
	for _, s := range dnsRebindServices {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
}

func dnsHasRepeatedLabel(labels []string, n int) bool {
	counts := map[string]int{}
	for _, l := range labels {
		if l == "" {
			continue
		}
		counts[l]++
		if counts[l] >= n {
			return true
		}
	}
	return false
}

// dnsEDNS does a light scan for the EDNS(0) OPT pseudo-record (RFC 6891): an RR
// with an empty (root) owner name and type 41. Returns the requestor's UDP
// payload size (the OPT CLASS field), the DO ("DNSSEC OK") flag, the EDNS
// version, and whether an OPT was found. Best-effort: a byte-pattern scan past
// the question, which is sufficient for a detection heuristic.
func dnsEDNS(msg []byte, start int) (udpSize uint16, do bool, version uint8, present bool) {
	if start < 12 || start > len(msg) {
		start = 12
	}
	for i := start; i+9 <= len(msg); i++ {
		// root name (0x00) followed by TYPE=41 (0x00 0x29).
		if msg[i] == 0x00 && msg[i+1] == 0x00 && msg[i+2] == 0x29 {
			udpSize = binary.BigEndian.Uint16(msg[i+3 : i+5])
			// TTL field layout: [ext-rcode][version][flags-hi][flags-lo];
			// the DO bit is the top bit of the 16-bit flags.
			version = msg[i+6]
			do = msg[i+7]&0x80 != 0
			return udpSize, do, version, true
		}
	}
	return 0, false, 0, false
}
