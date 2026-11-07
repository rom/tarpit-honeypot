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

// ja4Signatures maps a JA4 TLS fingerprint to a tool/stack name. Seeded from the
// public FoxIO JA4 database (ja4plus-mapping.csv, the `ja4` column) with the
// tool / library / malware / C2 entries — the attack-relevant subset; browsers
// and consumer-IoT devices are intentionally omitted so meta.tools stays a
// signal of tooling, not of ordinary clients. Operator-extensible, and the full
// continuously-updated DB (incl. per-version entries) loads at runtime via the
// `fingerprint_db:` loader (scripts/fetch-enrichment.sh pulls it) → ja4_client.
//
// Only TLS JA4 is seeded here: the sensor's JA4H (HTTP) meta is a hash of a
// JA4H string whose layout differs from the FoxIO JA4H column, so those would
// never match and are left to the fingerprint_db path.
var ja4Signatures = map[string]string{
	// Generic HTTP/TLS client libraries (scripted automation, not browsers).
	"t13i181000_85036bcba153_d41ae481755e": "python",
	"t13d181000_85036bcba153_d41ae481755e": "python",
	"t13d4312h1_c7886603b240_b26ce05bbdd6": "python",
	"t13d191000_9dc949149365_e7c285222651": "golang",
	"t13d1412h2_e33ad33b3d25_6b314db333b6": "golang",
	"t12d160700_8cdfa2d4673b_18dd7303c4a5": "golang",
	"t13d141000_cbb2034c60b8_e7c285222651": "golang",
	"t12d190800_d83cc789557e_7af1ed941c26": "wininet", // Windows WinINET (also GoLang in JA4DB)
	// Go's TLS stack — Sliver's default implant rides it, so this JA4 cannot
	// distinguish Sliver from any other Go client on its own (UA / beacon
	// behaviour disambiguates); labelled "golang" to avoid false C2 attribution.
	"t13d190900_9dc949149365_97f8aa674fd9": "golang",
	"t13i190800_9dc949149365_97f8aa674fd9": "golang",
	// Malware / C2 implants with a distinct TLS fingerprint.
	"t13d201100_2b729b4bf6f3_9e7b989ebec8": "icedid",
	"t12i190700_d83cc789557e_16bbda4055b2": "cobaltstrike", // beacon v4.9.1
	"t12i210700_76e208dd3e22_16bbda4055b2": "cobaltstrike",
	"t12d190800_d83cc789557e_16bbda4055b2": "cobaltstrike",
	"t12d210800_76e208dd3e22_16bbda4055b2": "cobaltstrike",
	// Tunnelling / VPN clients abused for egress + pivoting.
	"t13d880900_fcb5b95cb75a_b0d3b4ac2a14": "softether-vpn",
	"t13i880900_fcb5b95cb75a_b0d3b4ac2a14": "softether-vpn",
}

// hasshSignatures maps an SSH HASSH (a hash of the client's KEX / cipher / MAC /
// compression algorithm lists) to a tool/stack. HASSH is banner-independent, so
// it catches tooling that spoofs the cleartext "SSH-2.0-OpenSSH_x" banner but
// cannot change its crypto handshake. The FoxIO JA4 database carries no HASSH
// column, so this built-in map is intentionally empty: a HASSH corpus is loaded
// at runtime via the `fingerprint_db:` loader (→ hassh_client), and the SSH
// banner map (IdentifySSH) already attributes most SSH tooling. Operators extend
// this for banner-independent attribution of specific SSH clients.
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
