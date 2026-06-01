package fingerprint

import (
	"fmt"
	"strconv"
	"strings"
)

// JA4S produces the JA4S server-side fingerprint from a raw ServerHello
// handshake message (handshake type 0x02). It is the server analogue of JA4
// and the modern successor to JA3S. Format:
//
//	{proto}{nexts}{alpn}_{cipher}_{ext_hash}
//
// where proto is the two-digit TLS version, nexts is the (bounded) count of
// extensions the server returned, alpn is the first two hex chars of the
// negotiated ALPN (00 if none — the ServerHello rarely echoes ALPN here so we
// emit 00), cipher is the single selected cipher as 4 hex digits, and ext_hash
// is the first 12 hex of SHA-256 over the comma-joined (GREASE-filtered,
// order-preserved) extension list. Unlike JA4 the server extension list is NOT
// sorted — JA4S keeps wire order, since a server's extension ordering is itself
// a stable signal.
//
// Returns "" on parse failure.
func JA4S(handshake []byte) string {
	sh, ok := parseServerHello(handshake)
	if !ok {
		return ""
	}
	exts := filterGREASE(sh.ExtensionTypes)
	ne := boundedCount(len(exts))
	proto := tlsVersionDigits(sh.Version)
	extHash := sha256Trunc(joinUint16Hex4(exts, ","), 12)
	return fmt.Sprintf("%s%s00_%04x_%s", proto, ne, sh.Cipher, extHash)
}

// TCPSyn captures the TCP/IP fields JA4T reads from a client SYN. The
// userspace stack (internal/tcpstack) and any SYN-observing path populate it.
type TCPSyn struct {
	WindowSize  uint16   // advertised receive window
	Options     []TCPOpt // TCP options in wire order
	MSS         uint16   // 0 if no MSS option
	WindowScale uint8    // 0 if no window-scale option
}

// TCPOpt is one TCP option kind as it appeared on the wire (kinds only — JA4T
// fingerprints the option layout, not their values, except MSS/WS/scale).
type TCPOpt struct{ Kind uint8 }

// JA4T produces the JA4T TCP fingerprint from a client SYN's TCP fields.
// Format:
//
//	{window}_{option-kinds}_{mss}_{window-scale}
//
// e.g. "64240_2-4-8-1-3_1460_7". option-kinds is the dash-joined list of TCP
// option kind numbers in wire order; mss and window-scale are the decoded
// values (0 when the option is absent). This is the standard FoxIO JA4T
// layout and lets a SIEM cluster OS/stack families independent of L7.
//
// Returns "" when there are no options to fingerprint.
func JA4T(syn TCPSyn) string {
	if len(syn.Options) == 0 && syn.WindowSize == 0 {
		return ""
	}
	kinds := make([]string, 0, len(syn.Options))
	for _, o := range syn.Options {
		kinds = append(kinds, strconv.Itoa(int(o.Kind)))
	}
	return fmt.Sprintf("%d_%s_%d_%d",
		syn.WindowSize, strings.Join(kinds, "-"), syn.MSS, syn.WindowScale)
}

// JARMProbe is one of the ten ServerHello responses JARM derives its hash
// from: a JARM scan sends ten crafted ClientHellos and records, for each, the
// chosen cipher and the version/extension shape of the ServerHello. Here we
// run as the *server*, so we accumulate our own ServerHello responses (the
// fingerprint a JARM scanner would compute for us) by feeding each observed
// ServerHello in probe order.
type JARMProbe struct {
	Cipher    uint16 // selected cipher (0 = no response / alert)
	Version   uint16 // ServerHello version
	ALPN      string // negotiated ALPN ("" if none)
	Responded bool   // false if the server sent no ServerHello for this probe
}

// JARM computes the 62-character JARM-style fingerprint from up to ten ordered
// ServerHello observations. The canonical JARM is a 30-char cipher/version
// segment plus a 32-char truncated SHA-256 of the extension data; we follow
// that shape: for each probe we emit a 3-char field (cipher index + version
// byte), concatenate the ten, then append the truncated hash of the joined
// per-probe extension detail. A probe with no response contributes "000".
//
// Because a honeypot serves a fixed TLS posture, its JARM is stable per
// archetype — exactly what we want to expose so the operator can confirm the
// sensor's JARM matches the real product it impersonates (or detect drift).
func JARM(probes []JARMProbe) string {
	var cipherseg strings.Builder
	var detail strings.Builder
	for i := 0; i < 10; i++ {
		if i < len(probes) && probes[i].Responded {
			p := probes[i]
			// 3-char per-probe field: 2 hex of the cipher's low byte +
			// 1 hex of the chosen-version nibble. Matches the canonical
			// 30-char cipher/version segment (10 probes x 3 chars).
			cipherseg.WriteString(fmt.Sprintf("%02x%x", p.Cipher&0xff, p.Version&0xf))
			detail.WriteString(fmt.Sprintf("%04x|%s,", p.Version, p.ALPN))
		} else {
			cipherseg.WriteString("000")
			detail.WriteString("0000|,")
		}
	}
	return cipherseg.String() + sha256Trunc(detail.String(), 32)
}
