package handler

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
)

// Extended SSH key-exchange capture (beyond KEXINIT/HASSH).
//
// HASSH hashes only four client name-lists (kex / enc_c2s / mac_c2s /
// comp_c2s). When interaction.ssh_kex_depth: extended_experimental is set we
// go one step further on the connection we already hold open: we parse the
// *full* client KEXINIT (all ten name-lists + the first_kex_packet_follows
// guess flag), work out the negotiated KEX against what our server advertised,
// and read the client's first key-exchange packet — SSH_MSG_KEXDH_INIT /
// SSH_MSG_KEX_ECDH_INIT (the ephemeral public value e / Q_C) or
// SSH_MSG_KEX_DH_GEX_REQUEST (the requested DH group bounds). We never carry
// the exchange through (no shared secret, no session) — this is capture only,
// so it stays a low-interaction emulator: we record what the client offered
// and dropped, nothing is computed back to it.
//
// SSH message numbers (RFC 4253 §12, RFC 4419 §5).
const (
	sshMsgKexInit      = 20 // 0x14
	sshMsgKexDHInit    = 30 // also SSH_MSG_KEX_ECDH_INIT / GEX_REQUEST_OLD
	sshMsgKexDHGexReq  = 34 // SSH_MSG_KEX_DH_GEX_REQUEST (min/n/max)
	sshMaxKexPktLength = 65535
)

// sshKexInit is the parsed client SSH_MSG_KEXINIT: every name-list plus the
// kex-guess flag. Order per RFC 4253 §7.1.
type sshKexInit struct {
	kex          []string
	hostKeys     []string
	encC2S       []string
	encS2C       []string
	macC2S       []string
	macS2C       []string
	compC2S      []string
	compS2C      []string
	langC2S      []string
	langS2C      []string
	firstFollows bool
}

// parseClientKEXINIT parses a client KEXINIT payload (starting at the 0x14
// type byte, framing already stripped). Returns nil on malformed input.
func parseClientKEXINIT(payload []byte) *sshKexInit {
	if len(payload) < 1+16 || payload[0] != sshMsgKexInit {
		return nil
	}
	p := 1 + 16 // type byte + 16-byte cookie
	lists := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		if p+4 > len(payload) {
			return nil
		}
		l := int(binary.BigEndian.Uint32(payload[p : p+4]))
		p += 4
		if l < 0 || p+l > len(payload) {
			return nil
		}
		lists = append(lists, splitNameList(string(payload[p:p+l])))
		p += l
	}
	ki := &sshKexInit{
		kex: lists[0], hostKeys: lists[1], encC2S: lists[2], encS2C: lists[3],
		macC2S: lists[4], macS2C: lists[5], compC2S: lists[6], compS2C: lists[7],
		langC2S: lists[8], langS2C: lists[9],
	}
	// first_kex_packet_follows is the byte after the ten lists.
	if p < len(payload) {
		ki.firstFollows = payload[p] != 0
	}
	return ki
}

// splitNameList splits an SSH name-list on commas, dropping the empty result
// an empty list yields.
func splitNameList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// negotiatedKex returns the KEX algorithm SSH would settle on: the client's
// most-preferred algorithm that the server also offers (RFC 4253 §7.1 — the
// client's order wins). Empty if there is no overlap.
func negotiatedKex(clientKex, serverKex []string) string {
	srv := make(map[string]struct{}, len(serverKex))
	for _, a := range serverKex {
		srv[a] = struct{}{}
	}
	for _, a := range clientKex {
		if _, ok := srv[a]; ok {
			return a
		}
	}
	return ""
}

// readSSHPacket reads one unencrypted SSH binary packet (RFC 4253 §6) from br
// and returns its payload (type byte first). The "none" cipher is in force
// pre-KEX, so there is no MAC and the wire layout is:
//
//	uint32 packet_length | byte padding_length | payload | random padding
func readSSHPacket(br *bufio.Reader) ([]byte, bool) {
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, false
	}
	pktLen := binary.BigEndian.Uint32(hdr[0:4])
	padLen := int(hdr[4])
	if pktLen < 2 || pktLen > sshMaxKexPktLength {
		return nil, false
	}
	payloadLen := int(pktLen) - padLen - 1
	if payloadLen <= 0 {
		return nil, false
	}
	rest := make([]byte, int(pktLen)-1) // payload + padding (padding_length already read)
	if _, err := io.ReadFull(br, rest); err != nil {
		return nil, false
	}
	if payloadLen > len(rest) {
		return nil, false
	}
	return rest[:payloadLen], true
}

// captureExtendedKex parses the already-read client KEXINIT payload, then
// reads the client's first key-exchange packet, and writes the structured
// findings into res.Meta. serverKex is what our own KEXINIT advertised, used
// to compute the negotiated algorithm. It is best-effort: any short read just
// records less.
func captureExtendedKex(br *bufio.Reader, kexInitPayload []byte, serverKex []string, res *Result) {
	ki := parseClientKEXINIT(kexInitPayload)
	if ki == nil {
		return
	}
	res.Meta["ssh_kex_client"] = ki.kex
	res.Meta["ssh_kex_hostkeys"] = ki.hostKeys
	res.Meta["ssh_kex_ciphers_c2s"] = ki.encC2S
	res.Meta["ssh_kex_ciphers_s2c"] = ki.encS2C
	res.Meta["ssh_kex_macs_c2s"] = ki.macC2S
	res.Meta["ssh_kex_macs_s2c"] = ki.macS2C
	res.Meta["ssh_kex_compression_c2s"] = ki.compC2S
	if len(ki.langC2S) > 0 {
		res.Meta["ssh_kex_languages_c2s"] = ki.langC2S
	}
	res.Meta["ssh_kex_first_follows"] = ki.firstFollows
	if neg := negotiatedKex(ki.kex, serverKex); neg != "" {
		res.Meta["ssh_kex_negotiated"] = neg
	}
	// Flag clients that still offer broken/legacy primitives — an honest
	// signal about the attacker's tooling vintage.
	if hasWeakKexPrimitive(ki) {
		flagAnomaly(res, "ssh-kex-weak-primitive")
	}
	// Terrapin (CVE-2023-48795): a client that does NOT advertise the
	// kex-strict countermeasure while offering chacha20-poly1305 or a CBC-EtM
	// cipher is prefix-truncation-downgrade exploitable.
	if sshTerrapinVulnerable(ki) {
		flagAnomaly(res, "ssh-terrapin-vulnerable")
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2023-48795")
		flagAnomaly(res, "cve:CVE-2023-48795")
		res.Meta["intent"] = "SSH client lacks kex-strict with a Terrapin-affected cipher — prefix-truncation downgrade (CVE-2023-48795)"
	}
	// A client offering the `none` cipher or `none` MAC is requesting an
	// unencrypted/unauthenticated transport — sniff/downgrade posture.
	if sshOffersNone(ki) {
		flagAnomaly(res, "ssh-none-cipher")
		setIfEmpty(res.Meta, "intent", "SSH client offers null cipher/MAC — cleartext/downgrade posture")
	}

	// Read the client's first key-exchange message. With first_kex_packet_
	// follows the client pipelines it right after KEXINIT (an optimistic
	// guess); otherwise it arrives after seeing our KEXINIT.
	pkt, ok := readSSHPacket(br)
	if !ok || len(pkt) < 1 {
		return
	}
	switch pkt[0] {
	case sshMsgKexDHInit: // KEXDH_INIT / KEX_ECDH_INIT: type + string(e | Q_C)
		res.Meta["ssh_kex_msg"] = "ecdh_or_dh_init"
		if pub, ok := sshReadString(pkt[1:]); ok {
			sum := sha256.Sum256(pub)
			res.Meta["ssh_kex_client_pubkey_sha256"] = hex.EncodeToString(sum[:])
			res.Meta["ssh_kex_client_pubkey_bytes"] = len(pub)
		}
	case sshMsgKexDHGexReq: // GEX_REQUEST: type + uint32 min + uint32 n + uint32 max
		res.Meta["ssh_kex_msg"] = "dh_gex_request"
		if len(pkt) >= 1+12 {
			res.Meta["ssh_kex_gex_min"] = binary.BigEndian.Uint32(pkt[1:5])
			res.Meta["ssh_kex_gex_n"] = binary.BigEndian.Uint32(pkt[5:9])
			res.Meta["ssh_kex_gex_max"] = binary.BigEndian.Uint32(pkt[9:13])
		}
	default:
		res.Meta["ssh_kex_msg"] = "unexpected"
		res.Meta["ssh_kex_msg_type"] = int(pkt[0])
	}
}

// sshReadString reads an SSH string / mpint (uint32 length prefix + bytes).
func sshReadString(b []byte) ([]byte, bool) {
	if len(b) < 4 {
		return nil, false
	}
	l := int(binary.BigEndian.Uint32(b[0:4]))
	if l < 0 || 4+l > len(b) {
		return nil, false
	}
	return b[4 : 4+l], true
}

// hasWeakKexPrimitive reports whether the client offers a known-weak KEX, MAC,
// or cipher primitive (SHA-1 / group1 KEX, hmac-md5, CBC/arcfour/DES). These
// flag scanners and outdated client stacks rather than modern clients.
func hasWeakKexPrimitive(ki *sshKexInit) bool {
	for _, a := range ki.kex {
		if strings.Contains(a, "group1-sha1") || strings.HasSuffix(a, "sha1") && strings.Contains(a, "group-exchange") {
			return true
		}
	}
	for _, a := range ki.macC2S {
		if strings.Contains(a, "md5") || a == "hmac-sha1-96" || a == "none" {
			return true
		}
	}
	for _, a := range ki.encC2S {
		if strings.Contains(a, "-cbc") || strings.Contains(a, "arcfour") ||
			strings.Contains(a, "des-") || a == "none" {
			return true
		}
	}
	return false
}

// sshTerrapinVulnerable reports whether a client KEXINIT is exposed to the
// Terrapin prefix-truncation attack (CVE-2023-48795): no kex-strict
// countermeasure advertised, while a ChaCha20-Poly1305 or CBC-EtM cipher is
// offered.
func sshTerrapinVulnerable(ki *sshKexInit) bool {
	for _, k := range ki.kex {
		if k == "kex-strict-c-v00@openssh.com" {
			return false
		}
	}
	affected := func(ciphers, macs []string) bool {
		cbc := false
		for _, c := range ciphers {
			if c == "chacha20-poly1305@openssh.com" {
				return true
			}
			if strings.HasSuffix(c, "-cbc") {
				cbc = true
			}
		}
		if cbc {
			for _, m := range macs {
				if strings.HasSuffix(m, "-etm@openssh.com") {
					return true
				}
			}
		}
		return false
	}
	return affected(ki.encC2S, ki.macC2S) || affected(ki.encS2C, ki.macS2C)
}

// sshOffersNone reports whether the client offers the `none` cipher or MAC.
func sshOffersNone(ki *sshKexInit) bool {
	for _, c := range append(append([]string{}, ki.encC2S...), ki.encS2C...) {
		if c == "none" {
			return true
		}
	}
	for _, m := range append(append([]string{}, ki.macC2S...), ki.macS2C...) {
		if m == "none" {
			return true
		}
	}
	return false
}
