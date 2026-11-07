package toolfp

import (
	"strconv"
	"strings"
)

// Network-fingerprint → tool attribution, the modern complement to the JA3 and
// SSH-banner maps. The sensor computes JA4 / JA4H (TLS + HTTP) and HASSH (SSH
// crypto) on every handshake; these turn those fingerprints into a tool/stack
// name — and, for JA4, a corpus-free heuristic over the human-readable segment
// that flags non-browser TLS even without an exact signature entry.
//
// Why it matters: a User-Agent is attacker-controlled and trivially spoofed,
// but the TLS/SSH handshake is produced by the client's crypto library and is
// far harder to forge. So a "browser" UA riding a no-ALPN, minimal-cipher TLS
// handshake is a spoofed UA — caught here, UA-independently.

// ja4Signatures maps a full JA4 or JA4H fingerprint to a tool/stack name.
// Illustrative and operator-extensible: JA4 values are environment-stable but
// client/version-specific, so a site populates this from its own corpus (or the
// public JA4 database). Exact attribution is a bonus — JA4Automation already
// flags non-browser TLS with no entry at all.
var ja4Signatures = map[string]string{
	// "t13d1516h2_8daaf6152771_02713d6af862": "chrome", // example shape only
}

// hasshSignatures maps an SSH HASSH (a hash of the client's KEX / cipher / MAC /
// compression algorithm lists) to a tool/stack. HASSH is banner-independent, so
// it catches tooling that spoofs the cleartext "SSH-2.0-OpenSSH_x" banner but
// cannot change its crypto handshake. Operator-extensible, same as above.
var hasshSignatures = map[string]string{}

// IdentifyJA4 maps a JA4 or JA4H fingerprint to a known tool name, or "".
func IdentifyJA4(ja4 string) string { return ja4Signatures[strings.TrimSpace(ja4)] }

// IdentifyHASSH maps an SSH HASSH to a known tool/stack name, or "".
func IdentifyHASSH(hassh string) string { return hasshSignatures[strings.TrimSpace(hassh)] }

// LooksLikeBrowserUA reports whether a User-Agent claims to be a real browser
// (Chrome / Firefox / Safari / Edge …). Exported so the enricher can cross-check
// a browser UA against a non-browser TLS fingerprint (spoofed-UA detection).
func LooksLikeBrowserUA(ua string) bool { return looksLikeBrowserUA(strings.ToLower(ua)) }

// JA4Automation inspects the deterministic, human-readable first segment of a
// JA4 fingerprint and reports when the TLS ClientHello does not look like a
// normal browser — no corpus or signature DB required.
//
// The JA4_a segment is 10 chars: protocol(1, t=TLS/q=QUIC) · version(2) ·
// SNI(1, d=domain / i=IP-no-SNI) · cipher-count(2) · extension-count(2) ·
// first-ALPN(2, e.g. h2 / h1 / 00=none). Real browsers always negotiate ALPN
// (h2,http/1.1) and offer a large cipher/extension set; scanners and scripting
// TLS stacks (nmap, masscan, curl-no-http2, many Go/Python clients) frequently
// omit ALPN and present a minimal suite. The no-ALPN case is the reliable
// discriminator; no-SNI and a tiny cipher list reinforce the reason string.
//
// It returns a short reason and true only when the handshake looks like
// automation; ("", false) for a browser-shaped or unparseable JA4.
func JA4Automation(ja4 string) (reason string, automation bool) {
	a, _, ok := strings.Cut(strings.TrimSpace(ja4), "_")
	if !ok || len(a) < 10 {
		return "", false
	}
	if a[0] != 't' && a[0] != 'q' {
		return "", false
	}
	sni := a[3]
	alpn := a[8:10]
	// No ALPN offered is the strong, low-false-positive non-browser signal.
	if alpn != "00" {
		return "", false
	}
	reasons := []string{"no ALPN"}
	if sni == 'i' {
		reasons = append(reasons, "no SNI")
	}
	if cc, err := strconv.Atoi(a[4:6]); err == nil && cc > 0 && cc <= 5 {
		reasons = append(reasons, "minimal cipher suite")
	}
	return "non-browser TLS (" + strings.Join(reasons, ", ") + ")", true
}
