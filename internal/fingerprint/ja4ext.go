package fingerprint

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sort"
	"strings"
)

// JA4SSH fingerprints an SSH session from the *sizes* of the first application
// records each side sends after the KEX completes — the FoxIO JA4SSH scheme.
// Unlike HASSH (which hashes the KEXINIT algorithm lists), JA4SSH keys on the
// encrypted-packet length cadence, which survives algorithm negotiation and
// distinguishes client *implementations / automation* even when their KEXINIT
// matches. Format (one mode segment):
//
//	c{clen}s{slen}_{cpkts}_{spkts}_{acks}
//
// where clen/slen are the modal client/server payload lengths, cpkts/spkts the
// packet counts in each direction over the sampled window, and acks the count
// of pure-ACK (zero-payload) records. We compute it from an SSHSample the
// listener fills as it observes the first records; with no samples it returns "".
type SSHSample struct {
	ClientLens []int // payload lengths of client→server app records, in order
	ServerLens []int // payload lengths of server→client app records, in order
	Acks       int   // pure-ACK (empty) records seen
}

// JA4SSH returns the JA4SSH string for one observation window.
func JA4SSH(s SSHSample) string {
	if len(s.ClientLens) == 0 && len(s.ServerLens) == 0 {
		return ""
	}
	return fmt.Sprintf("c%ds%d_%d_%d_%d",
		modeInt(s.ClientLens), modeInt(s.ServerLens),
		len(s.ClientLens), len(s.ServerLens), s.Acks)
}

// modeInt returns the most frequent value in xs (lowest value wins ties), or 0
// for an empty slice — the modal packet length JA4SSH keys on.
func modeInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	counts := map[int]int{}
	for _, x := range xs {
		counts[x]++
	}
	best, bestN := 0, -1
	for v, n := range counts {
		if n > bestN || (n == bestN && v < best) {
			best, bestN = v, n
		}
	}
	return best
}

// JA4L is the JA4 "latency / locality" fingerprint: the observed TTL/hop-limit
// of the peer plus the handshake round-trip time in microseconds. Together they
// approximate the peer's network distance — a strong "this client is not where
// its source IP claims" signal (a proxied/relayed connection shows a TTL or RTT
// inconsistent with the geo of the source IP). Format:
//
//	{rtt_us}_{ttl}
//
// rttMicros is the measured SYN→SYN-ACK→ACK (or handshake) RTT in microseconds;
// ttl is the IP TTL / IPv6 hop-limit seen on the inbound packet. Returns "" when
// neither signal is available.
func JA4L(rttMicros int, ttl uint8) string {
	if rttMicros <= 0 && ttl == 0 {
		return ""
	}
	return fmt.Sprintf("%d_%d", rttMicros, ttl)
}

// JA4X fingerprints an X.509 certificate by the *structure* of its Issuer and
// Subject relative distinguished names plus its extension OIDs, in the FoxIO
// JA4X style:
//
//	{issuer_hash}_{subject_hash}_{ext_hash}
//
// Each segment is the first-12-hex of SHA-256 over the comma-joined RDN
// attribute-type OIDs (issuer, subject) and the sorted extension OIDs. JA4X
// clusters certs minted by the same tooling/CA template even when the values
// differ, which is how malware C2 and scan infrastructure get caught reusing a
// cert-generation library. Returns "" for a nil cert.
func JA4X(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	issuer := rdnOIDs(cert.Issuer.Names)
	subject := rdnOIDs(cert.Subject.Names)
	exts := certExtOIDs(cert)
	return fmt.Sprintf("%s_%s_%s",
		sha256Trunc(strings.Join(issuer, ","), 12),
		sha256Trunc(strings.Join(subject, ","), 12),
		sha256Trunc(strings.Join(exts, ","), 12))
}

// rdnOIDs returns the attribute-type OIDs of a DN in wire order (e.g.
// "2.5.4.3" for CN), which is the structural signal JA4X hashes — the order and
// set of RDN components, not their values.
func rdnOIDs(names []pkix.AttributeTypeAndValue) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n.Type.String())
	}
	return out
}

// certExtOIDs returns the sorted extension OIDs present on the cert.
func certExtOIDs(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.Extensions))
	for _, e := range cert.Extensions {
		out = append(out, e.Id.String())
	}
	sort.Strings(out)
	return out
}
